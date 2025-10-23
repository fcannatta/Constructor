#!/usr/bin/env bash
#
# 03-depsolve.sh - Resolve dependências, detecta ciclos e gera ordem topológica
# - Suporta dependências opcionais via flags em config.txt
# - Gera build-order.list, dependency-map.txt e depsolve.dot
# - Inclui função rebuild_all() para update.sh
#
# Uso:
#   ./03-depsolve.sh [--rebuild-all] [--fast]
#

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ----------------------------
# Load config and logger
# ----------------------------
CONFIG_FILE="${ROOT_DIR:-/opt/buildsystem}/config.txt"
LOGGER_FILE="${SCRIPT_DIR}/logger.sh"

if [[ -f "$CONFIG_FILE" ]]; then
  # shellcheck source=/dev/null
  source "$CONFIG_FILE"
else
  echo "ERROR: config.txt not found at $CONFIG_FILE" >&2
  exit 1
fi

if [[ -f "$LOGGER_FILE" ]]; then
  # shellcheck source=/dev/null
  source "$LOGGER_FILE"
else
  echo "ERROR: logger.sh not found at $LOGGER_FILE" >&2
  exit 1
fi

if [[ "${LOGGER_ACTIVE:-0}" -eq 0 ]]; then
  log_init
fi
log_start "depsolve" "init"

# ----------------------------
# Defaults and paths
# ----------------------------
: "${PKG_REPO_LOCAL:=${ROOT_DIR}/package}"
: "${STATUS_DIR:=${LOG_DIR}/status}"
: "${GRAPHS_DIR:=${ROOT_DIR}/graphs}"
: "${DEPSOLVE_LOG_DIR:=${LOG_DIR}/depsolve}"
: "${SILENT_MODE:=no}"
: "${CONTINUE_ON_FAIL:=no}"
: "${REBUILD_SCRIPT:=${SCRIPT_DIR}/04-build.sh}"
: "${TMP_DIR:=/tmp/buildsystem-depsolve}"

mkdir -p "$STATUS_DIR" "$GRAPHS_DIR" "$DEPSOLVE_LOG_DIR" "$TMP_DIR" 2>/dev/null || true

# ----------------------------
# Data structures
# ----------------------------
declare -A PKG_VERSION
declare -A PKG_DEPENDS
declare -A PKG_OPTIONAL
declare -A PKG_CONFLICTS
declare -A PKG_GROUP
declare -A PKG_PRIORITY
declare -A GRAPH_INDEGREE
declare -A GRAPH_ADJ
declare -A NODE_EXISTS
declare -A NORMALIZED_NAME

BUILD_ORDER_FILE="${STATUS_DIR}/build-order.list"
DEPENDENCY_MAP="${STATUS_DIR}/dependency-map.txt"
DOT_FILE="${GRAPHS_DIR}/depsolve.dot"
ERROR_LOG="${DEPSOLVE_LOG_DIR}/errors.log"
SUMMARY_LOG="${DEPSOLVE_LOG_DIR}/summary.log"
MISSING_LOG="${DEPSOLVE_LOG_DIR}/missing.log"

timestamp_now() { date '+%Y-%m-%d_%H-%M-%S'; }
_backup_old() {
  local f="$1"
  [[ -f "$f" ]] && mv "$f" "${f}.$(timestamp_now).bak" 2>/dev/null || true
}
_backup_old "$BUILD_ORDER_FILE"
_backup_old "$DEPENDENCY_MAP"
_backup_old "$DOT_FILE"
_backup_old "$ERROR_LOG"
_backup_old "$SUMMARY_LOG"
_backup_old "$MISSING_LOG"

# ----------------------------
# Helpers
# ----------------------------
_timestamp() { date '+%Y-%m-%d %H:%M:%S'; }

normalize_pkgname() {
  local name="$1"
  name="${name,,}"
  name="${name// /-}"
  name="${name//_/}"
  name="${name//,/}"
  name="$(echo "$name" | sed -E 's/^[^a-z0-9]+//; s/[^a-z0-9]+$//')"
  name="$(echo "$name" | sed -E 's/-[0-9]+(\.[0-9]+)*$//')"
  [[ -z "$name" ]] && name="unknown-$(date +%s%N)"
  printf "%s" "$name"
}

safe_write() {
  local file="$1"; shift
  mkdir -p "$(dirname "$file")" 2>/dev/null || true
  echo "$*" >> "$file" 2>/dev/null || echo "$*" >> "${TMP_DIR}/$(basename "$file")"
}

# ----------------------------
# Parse .desc files
# ----------------------------
parse_all_desc() {
  log_info "Parsing .desc files in $PKG_REPO_LOCAL..."
  if [[ ! -d "$PKG_REPO_LOCAL" ]]; then
    log_error "Package repo not found: $PKG_REPO_LOCAL"
    return 1
  fi

  local desc count=0
  while IFS= read -r -d '' desc; do
    ((count++))
    parse_single_desc "$desc" || log_warn "Invalid .desc ignored: $desc"
  done < <(find "$PKG_REPO_LOCAL" -type f -name "*.desc" -print0 2>/dev/null || true)

  (( count == 0 )) && log_warn "No .desc files found" && return 1
  log_info "Parsed $count .desc files"
}

parse_single_desc() {
  local descfile="$1"
  local name version depends optional conflicts group build_order
  name=""; version=""; depends=""; optional=""; conflicts=""; group=""; build_order="0"

  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line//$'\r'/}"
    line="$(echo "$line" | sed -E 's/#.*$//; s/^[[:space:]]+//; s/[[:space:]]+$//')"
    [[ -z "$line" ]] && continue
    case "$line" in
      NAME*) name="${line#*=}";;
      VERSION*) version="${line#*=}";;
      DEPENDS*) depends="${line#*=}";;
      OPTIONAL*) optional="${line#*=}";;
      CONFLICTS*) conflicts="${line#*=}";;
      GROUP*) group="${line#*=}";;
      BUILD_ORDER*) build_order="${line#*=}";;
    esac
  done < "$descfile"

  [[ -z "$name" ]] && log_warn "Desc missing NAME: $descfile" && return 1

  local n
  n="$(normalize_pkgname "$name")"
  NODE_EXISTS["$n"]=1
  PKG_VERSION["$n"]="$version"
  PKG_GROUP["$n"]="$group"
  PKG_PRIORITY["$n"]="${build_order:-0}"

  depends="$(echo "$depends" | tr ',' ' ' | tr -s ' ')"
  optional="$(echo "$optional" | tr ',' ' ' | tr -s ' ')"
  conflicts="$(echo "$conflicts" | tr ',' ' ' | tr -s ' ')"

  local token out=""
  for token in $depends; do out+="$(normalize_pkgname "$token") "; done
  PKG_DEPENDS["$n"]="${out%% }"

  out=""
  for token in $optional; do out+="$(normalize_pkgname "$token") "; done
  PKG_OPTIONAL["$n"]="${out%% }"

  out=""
  for token in $conflicts; do out+="$(normalize_pkgname "$token") "; done
  PKG_CONFLICTS["$n"]="${out%% }"
}

# ----------------------------
# Apply optional dependencies
# ----------------------------
apply_optionals() {
  log_info "Applying optional dependencies..."
  local pkg dep opt flag ok
  for pkg in "${!NODE_EXISTS[@]}"; do
    opt="${PKG_OPTIONAL[$pkg]:-}"
    [[ -z "$opt" ]] && continue
    local final_add=""
    for dep in $opt; do
      flag="ENABLE_OPTIONAL_$(echo "$dep" | tr '[:lower:]' '[:upper:]' | sed 's/[^A-Z0-9]/_/g')"
      ok="${!flag:-}"
      [[ "$ok" == "yes" ]] && final_add+="$dep "
    done
    if [[ -n "$final_add" ]]; then
      PKG_DEPENDS["$pkg"]="${PKG_DEPENDS[$pkg]} ${final_add}"
      PKG_DEPENDS["$pkg"]="$(echo "${PKG_DEPENDS[$pkg]}" | tr -s ' ' | sed 's/^ //; s/ $//')"
    fi
  done
  log_info "Optional dependencies applied."
}

# ----------------------------
# Build dependency graph
# ----------------------------
build_graph() {
  log_info "Building dependency graph..."
  local pkg dep cleaned
  for pkg in "${!NODE_EXISTS[@]}"; do
    GRAPH_ADJ["$pkg"]=""
    GRAPH_INDEGREE["$pkg"]=0
  done

  for pkg in "${!NODE_EXISTS[@]}"; do
    cleaned="$(echo "${PKG_DEPENDS[$pkg]:-}" | tr -s ' ')"
    [[ -z "$cleaned" ]] && continue
    for dep in $cleaned; do
      [[ "$dep" == "$pkg" ]] && log_warn "Self-dependency removed: $pkg" && continue
      if [[ -z "${NODE_EXISTS[$dep]:-}" ]]; then
        safe_write "$MISSING_LOG" "Missing dependency: $dep required by $pkg"
        NODE_EXISTS["$dep"]=0
      fi
      GRAPH_ADJ["$dep"]="${GRAPH_ADJ[$dep]} $pkg"
      GRAPH_INDEGREE["$pkg"]=$((GRAPH_INDEGREE["$pkg"] + 1))
    done
  done

  for key in "${!GRAPH_ADJ[@]}"; do
    GRAPH_ADJ["$key"]="$(echo "${GRAPH_ADJ[$key]}" | tr ' ' '\n' | sort -u | tr '\n' ' ')"
  done
  log_info "Graph built: ${#NODE_EXISTS[@]} packages"
}

# ----------------------------
# Detect cycles (DFS iterative)
# ----------------------------
detect_cycles() {
  log_info "Detecting cycles..."
  declare -A state  # 0=unvisited, 1=visiting, 2=done
  for node in "${!NODE_EXISTS[@]}"; do state["$node"]=0; done
  local cycle_found=0 cycles_dot="digraph cycles { rankdir=LR; node [shape=box];"

  for node in "${!NODE_EXISTS[@]}"; do
    [[ "${state[$node]}" -ne 0 ]] && continue
    declare -a stack_node=("$node")
    declare -a stack_iter=(0)
    declare path_stack=""

    while ((${#stack_node[@]})); do
      local idx=$((${#stack_node[@]}-1))
      local cur="${stack_node[$idx]}"
      local it="${stack_iter[$idx]}"
      if [[ "${state[$cur]}" -eq 0 ]]; then
        state["$cur"]=1
        path_stack+="$cur "
      fi

      local neighs=()
      read -r -a neighs <<< "${GRAPH_ADJ[$cur]:-}"

      if (( it < ${#neighs[@]} )); then
        local nxt="${neighs[$it]}"
        stack_iter[$idx]=$((it+1))
        if [[ "${state[$nxt]:-0}" -eq 0 ]]; then
          stack_node+=("$nxt")
          stack_iter+=(0)
          continue
        elif [[ "${state[$nxt]:-0}" -eq 1 ]]; then
          cycle_found=1
          local path_arr=($path_stack) cycle_nodes=()
          local found=0
          for p in "${path_arr[@]}"; do
            [[ "$p" == "$nxt" ]] && found=1
            ((found)) && cycle_nodes+=("$p")
          done
          cycle_nodes+=("$nxt")
          log_error "Cycle detected: ${cycle_nodes[*]}"
          for ((i=0;i<${#cycle_nodes[@]}-1;i++)); do
            cycles_dot+="\"${cycle_nodes[i]}\" -> \"${cycle_nodes[i+1]}\"; "
          done
          cycles_dot+="\"${cycle_nodes[-1]}\" -> \"${cycle_nodes[0]}\"; "
        fi
      else
        state["$cur"]=2
        unset 'stack_node[$idx]'
        unset 'stack_iter[$idx]'
        path_stack="$(echo "$path_stack" | sed -E "s/ ?$cur ?//")"
      fi
    done
  done

  if ((cycle_found)); then
    echo "$cycles_dot }" > "${GRAPHS_DIR}/cycles-$(timestamp_now).dot"
    safe_write "$ERROR_LOG" "Cycle(s) detected. See graphs/cycles-*.dot"
    return 1
  fi
  log_info "No cycles found."
}
# ----------------------------
# Topological sort (Kahn algorithm)
# ----------------------------
topological_sort() {
  log_info "Performing topological sort..."
  declare -a queue=()
  declare -a result=()
  declare -A indeg

  for node in "${!GRAPH_INDEGREE[@]}"; do
    indeg["$node"]="${GRAPH_INDEGREE[$node]}"
    (( indeg["$node"] == 0 )) && queue+=("$node")
  done

  while ((${#queue[@]})); do
    # find node with lowest priority
    local best="${queue[0]}"
    local bestp="${PKG_PRIORITY[$best]:-0}"
    for n in "${queue[@]}"; do
      local p="${PKG_PRIORITY[$n]:-0}"
      if (( p < bestp )) || (( p == bestp )) && [[ "$n" < "$best" ]]; then
        best="$n"
        bestp="$p"
      fi
    done
    # remove from queue
    queue=("${queue[@]/$best}")
    result+=("$best")

    local deps=()
    read -r -a deps <<< "${GRAPH_ADJ[$best]:-}"
    for d in "${deps[@]}"; do
      [[ -z "${indeg[$d]:-}" ]] && continue
      indeg["$d"]=$(( indeg["$d"] - 1 ))
      (( indeg["$d"] == 0 )) && queue+=("$d")
    done
  done

  local total=${#NODE_EXISTS[@]}
  local done=${#result[@]}
  if (( done < total )); then
    log_error "Topological sort incomplete ($done of $total)"
    local remaining=()
    for node in "${!NODE_EXISTS[@]}"; do
      local found=0
      for r in "${result[@]}"; do [[ "$r" == "$node" ]] && found=1 && break; done
      (( ! found )) && remaining+=("$node")
    done
    safe_write "$ERROR_LOG" "Unresolved nodes: ${remaining[*]}"
    return 1
  fi

  # Write outputs
  : > "$BUILD_ORDER_FILE" 2>/dev/null || true
  for n in "${result[@]}"; do
    echo "$n" >> "$BUILD_ORDER_FILE"
  done

  : > "$DEPENDENCY_MAP" 2>/dev/null || true
  for n in "${result[@]}"; do
    echo "$n: ${PKG_DEPENDS[$n]:-}" >> "$DEPENDENCY_MAP"
  done

  echo "digraph deps { rankdir=LR; node [shape=box];" > "$DOT_FILE"
  for src in "${!GRAPH_ADJ[@]}"; do
    for dst in ${GRAPH_ADJ[$src]}; do
      echo "\"$src\" -> \"$dst\";" >> "$DOT_FILE"
    done
  done
  echo "}" >> "$DOT_FILE"

  log_info "Build order generated at $BUILD_ORDER_FILE"
}

# ----------------------------
# Generate summary
# ----------------------------
generate_summary() {
  local total=$(echo "${!NODE_EXISTS[@]}" | wc -w)
  local missing=0 cycles=0
  [[ -s "$MISSING_LOG" ]] && missing=$(wc -l < "$MISSING_LOG")
  [[ -s "$ERROR_LOG" ]] && cycles=$(grep -ci "cycle" "$ERROR_LOG" || true)

  local summary="
==============================
DEPENDENCY SOLVE COMPLETE
Date: $(_timestamp)
Packages scanned: $total
Missing deps: $missing
Cycles: $cycles
Build order: $BUILD_ORDER_FILE
Dependency map: $DEPENDENCY_MAP
Graph: $DOT_FILE
==============================
"
  echo "$summary" > "$SUMMARY_LOG"
  log_info "$summary"
}

# ----------------------------
# rebuild_all() - rebuild every package
# ----------------------------
rebuild_all() {
  log_info "Starting full rebuild (rebuild_all)"
  [[ ! -f "$BUILD_ORDER_FILE" ]] && log_error "Missing $BUILD_ORDER_FILE" && return 2

  local fast="${1:-no}" pkg
  while IFS= read -r pkg; do
    [[ -z "$pkg" ]] && continue
    [[ "${NODE_EXISTS[$pkg]:-0}" -eq 0 ]] && log_warn "Skipping missing $pkg" && continue

    log_info "Rebuilding $pkg..."
    if [[ ! -x "$REBUILD_SCRIPT" ]]; then
      log_error "Build script not found: $REBUILD_SCRIPT"
      return 3
    fi

    if [[ "$fast" == "yes" ]]; then
      "$REBUILD_SCRIPT" --fast "$pkg" >> "${DEPSOLVE_LOG_DIR}/rebuild.log" 2>&1 || {
        log_error "$pkg: fast rebuild failed"
        [[ "$CONTINUE_ON_FAIL" == "no" ]] && return 4
      }
    else
      "$REBUILD_SCRIPT" "$pkg" >> "${DEPSOLVE_LOG_DIR}/rebuild.log" 2>&1 || {
        log_error "$pkg: rebuild failed"
        [[ "$CONTINUE_ON_FAIL" == "no" ]] && return 5
      }
    fi
  done < "$BUILD_ORDER_FILE"

  log_info "Full rebuild completed"
  return 0
}

# ----------------------------
# depsolve_main()
# ----------------------------
depsolve_main() {
  log_info "Starting dependency resolution..."
  [[ ! -d "$PKG_REPO_LOCAL" ]] && log_error "Missing repo $PKG_REPO_LOCAL" && return 1

  parse_all_desc || log_warn "No valid .desc files"
  apply_optionals
  build_graph

  if ! detect_cycles; then
    log_error "Cycle detected — aborting"
    generate_summary
    [[ "$CONTINUE_ON_FAIL" == "no" ]] && return 2
  fi

  if ! topological_sort; then
    log_error "Topological sort failed"
    generate_summary
    [[ "$CONTINUE_ON_FAIL" == "no" ]] && return 3
  fi

  generate_summary
  log_success "depsolve" "complete"
}

# ----------------------------
# CLI interface
# ----------------------------
REBUILD_REQ="no"
FAST_REQ="no"
while (( $# )); do
  case "$1" in
    --rebuild-all) REBUILD_REQ="yes"; shift;;
    --fast) FAST_REQ="yes"; shift;;
    --help|-h)
      echo "Usage: $0 [--rebuild-all] [--fast]"
      echo "  --rebuild-all  : Rebuild all packages after depsolve"
      echo "  --fast          : Skip optional deps during rebuild"
      exit 0;;
    *) shift;;
  esac
done

trap 'log_warn "Interrupted by signal"; generate_summary; exit 2' INT TERM

depsolve_main || log_error "Dependency resolution failed"

if [[ "$REBUILD_REQ" == "yes" ]]; then
  rebuild_all "$FAST_REQ" || log_error "Rebuild_all failed"
fi

log_summary
exit 0
