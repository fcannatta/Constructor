#!/usr/bin/env bash
#
# 03-depsolve.sh - Resolve dependências, detecta ciclos, gera ordem topológica
# - Suporta dependências opcionais via flags em config.txt
# - Gera status/build-order.list, status/dependency-map.txt, graphs/depsolve.dot
# - Fornece rebuild_all() para update.sh (chama 04-build.sh por pacote)
#
# Uso:
#   /opt/buildsystem/scripts/03-depsolve.sh [--rebuild-all] [--fast]
#

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# ----------------------------
# Carrega config e logger
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

# inicializa logger se preciso
if [[ "${LOGGER_ACTIVE:-0}" -eq 0 ]]; then
  log_init
fi
log_start "depsolve" "init"

# ----------------------------
# Defaults e paths derivados
# ----------------------------
: "${PKG_REPO_LOCAL:=${ROOT_DIR}/package}"
: "${STATUS_DIR:=${LOG_DIR}/status}"
: "${GRAPHS_DIR:=${ROOT_DIR}/graphs}"
: "${DEPSOLVE_LOG_DIR:=${LOG_DIR}/depsolve}"
: "${SILENT_MODE:=no}"
: "${CONTINUE_ON_FAIL:=no}"
: "${REBUILD_SCRIPT:=${SCRIPT_DIR}/04-build.sh}"
: "${TMP_DIR:=/tmp/buildsystem-depsolve}"
: "${ALLOW_OPTIONAL_DEPS:=yes}"

mkdir -p "$STATUS_DIR" "$GRAPHS_DIR" "$DEPSOLVE_LOG_DIR" "$TMP_DIR" 2>/dev/null || true

# ----------------------------
# Estruturas internas
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

log_and_echo() {
  local level="$1"; shift
  local msg="$*"
  case "$level" in
    INFO) log_info "$msg";;
    WARN) log_warn "$msg";;
    ERROR) log_error "$msg";;
    *) log_info "$msg";;
  esac
}

normalize_pkgname() {
  local name="$1"
  name="${name,,}"                 # lowercase
  name="${name// /-}"              # spaces -> -
  name="${name//\_/}"              # remove underscores (optional)
  name="${name//,/}"               # remove commas
  name="$(echo "$name" | sed -E 's/^[^a-z0-9]+//; s/[^a-z0-9]+$//')"  # trim non alnum edges
  name="$(echo "$name" | sed -E 's/-[0-9]+(\.[0-9]+)*$//')"        # strip trailing version-like suffix
  [[ -z "$name" ]] && name="unknown-$(date +%s%N)"
  printf "%s" "$name"
}

safe_write() {
  local file="$1"; shift
  mkdir -p "$(dirname "$file")" 2>/dev/null || true
  echo "$*" >> "$file" 2>/dev/null || echo "$*" >> "${TMP_DIR}/$(basename "$file")"
}

# ----------------------------
# Parsing dos arquivos .desc
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
    if ! parse_single_desc "$desc"; then
      log_warn "Invalid .desc ignored: $desc"
    fi
  done < <(find "$PKG_REPO_LOCAL" -type f -name "*.desc" -print0 2>/dev/null || true)

  if (( count == 0 )); then
    log_warn "No .desc files found under $PKG_REPO_LOCAL"
    return 1
  fi
  log_info "Parsed $count .desc files"
  return 0
}

parse_single_desc() {
  local descfile="$1"
  local name version depends optional conflicts group build_order
  name=""; version=""; depends=""; optional=""; conflicts=""; group=""; build_order="0"

  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line//$'\r'/}"
    line="$(echo "$line" | sed -E 's/#.*$//; s/^[[:space:]]+//; s/[[:space:]]+$//')"
    [[ -z "$line" ]] && continue
    if [[ "$line" =~ ^NAME[[:space:]]*=[[:space:]]*(.*)$ ]]; then
      name="${BASH_REMATCH[1]//\"/}"
    elif [[ "$line" =~ ^VERSION[[:space:]]*=[[:space:]]*(.*)$ ]]; then
      version="${BASH_REMATCH[1]//\"/}"
    elif [[ "$line" =~ ^DEPENDS[[:space:]]*=[[:space:]]*(.*)$ ]]; then
      depends="${BASH_REMATCH[1]//\"/}"
    elif [[ "$line" =~ ^OPTIONAL[[:space:]]*=[[:space:]]*(.*)$ ]]; then
      optional="${BASH_REMATCH[1]//\"/}"
    elif [[ "$line" =~ ^CONFLICTS[[:space:]]*=[[:space:]]*(.*)$ ]]; then
      conflicts="${BASH_REMATCH[1]//\"/}"
    elif [[ "$line" =~ ^GROUP[[:space:]]*=[[:space:]]*(.*)$ ]]; then
      group="${BASH_REMATCH[1]//\"/}"
    elif [[ "$line" =~ ^BUILD_ORDER[[:space:]]*=[[:space:]]*(.*)$ ]]; then
      build_order="${BASH_REMATCH[1]//\"/}"
    fi
  done < "$descfile"

  if [[ -z "$name" ]]; then
    log_warn "Desc missing NAME: $descfile"
    return 1
  fi

  local n
  n="$(normalize_pkgname "$name")"
  NORMALIZED_NAME["$name"]="$n"
  NODE_EXISTS["$n"]=1
  PKG_VERSION["$n"]="$version"
  PKG_GROUP["$n"]="$group"
  PKG_PRIORITY["$n"]="${build_order:-0}"

  # normalize lists: comma or space separated -> space separated normalized tokens
  local token out=""
  depends="$(echo "$depends" | tr ',' ' ' | tr -s ' ' | sed 's/^ *//; s/ *$//')"
  for token in $depends; do
    token="$(normalize_pkgname "$token")"
    out+="$token "
  done
  PKG_DEPENDS["$n"]="${out%% }"

  out=""
  optional="$(echo "$optional" | tr ',' ' ' | tr -s ' ' | sed 's/^ *//; s/ *$//')"
  for token in $optional; do
    token="$(normalize_pkgname "$token")"
    out+="$token "
  done
  PKG_OPTIONAL["$n"]="${out%% }"

  out=""
  conflicts="$(echo "$conflicts" | tr ',' ' ' | tr -s ' ' | sed 's/^ *//; s/ *$//')"
  for token in $conflicts; do
    token="$(normalize_pkgname "$token")"
    out+="$token "
  done
  PKG_CONFLICTS["$n"]="${out%% }"

  return 0
}

# ----------------------------
# Apply optional dependencies (flags in config.txt)
# ----------------------------
apply_optionals() {
  log_info "Applying optional dependencies according to config..."
  local pkg dep opt flag ok
  for pkg in "${!NODE_EXISTS[@]}"; do
    opt="${PKG_OPTIONAL[$pkg]:-}"
    [[ -z "$opt" ]] && continue
    local final_add=""
    for dep in $opt; do
      # flag lookups: ENABLE_OPTIONAL_<DEP> or ENABLE_OPTIONAL_<GROUP>
      flag="ENABLE_OPTIONAL_$(echo "$dep" | tr '[:lower:]' '[:upper:]' | sed 's/[^A-Z0-9]/_/g')"
      ok="${!flag:-}"
      if [[ -z "$ok" ]] && [[ -n "${PKG_GROUP[$pkg]:-}" ]]; then
        local gflag="ENABLE_OPTIONAL_$(echo "${PKG_GROUP[$pkg]}" | tr '[:lower:]' '[:upper:]' | sed 's/[^A-Z0-9]/_/g')"
        ok="${!gflag:-}"
      fi
      if [[ -z "$ok" ]]; then
        [[ "${ALLOW_OPTIONAL_DEPS:-yes}" == "yes" ]] && ok="yes" || ok="no"
      fi
      if [[ "$ok" == "yes" ]]; then
        final_add+="$dep "
      fi
    done
    if [[ -n "$final_add" ]]; then
      PKG_DEPENDS["$pkg"]="${PKG_DEPENDS[$pkg]:-} ${final_add}"
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
      if [[ "$dep" == "$pkg" ]]; then
        log_warn "Self-dependency removed: $pkg"
        continue
      fi
      if [[ -z "${NODE_EXISTS[$dep]:-}" ]]; then
        safe_write "$MISSING_LOG" "Missing dependency: $dep required by $pkg"
        log_warn "Missing dependency: $dep required by $pkg"
        NODE_EXISTS["$dep"]=0
        GRAPH_ADJ["$dep"]="${GRAPH_ADJ[$dep]:-}"
        GRAPH_INDEGREE["$dep"]="${GRAPH_INDEGREE[$dep]:-0}"
      fi
      GRAPH_ADJ["$dep"]="${GRAPH_ADJ[$dep]} $pkg"
      GRAPH_INDEGREE["$pkg"]=$((GRAPH_INDEGREE["$pkg"] + 1))
    done
  done

  # dedupe adjacency
  for key in "${!GRAPH_ADJ[@]}"; do
    GRAPH_ADJ["$key"]="$(echo "${GRAPH_ADJ[$key]}" | tr ' ' '\n' | awk 'NF' | sort -u | tr '\n' ' ' | sed 's/ $//')"
  done

  log_info "Graph built: nodes=$(echo "${!NODE_EXISTS[@]}" | wc -w | awk '{print $1}')"
}

# ----------------------------
# Detect cycles (DFS iterative)
# ----------------------------
detect_cycles() {
  log_info "Detecting cycles..."
  declare -A state
  for node in "${!NODE_EXISTS[@]}"; do state["$node"]=0; done

  local cycle_found=0
  local cycles_dot="digraph cycles { rankdir=LR; node [shape=box];"

  for node in "${!NODE_EXISTS[@]}"; do
    [[ "${state[$node]}" -ne 0 ]] && continue
    declare -a stack_node=("$node")
    declare -a stack_iter=(0)
    local path_stack=""
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
          local path_arr=($path_stack)
          local cycle_nodes=()
          local found=0
          for p in "${path_arr[@]}"; do
            [[ "$p" == "$nxt" ]] && found=1
            ((found)) && cycle_nodes+=("$p")
          done
          cycle_nodes+=("$nxt")
          log_error "Dependency cycle detected: ${cycle_nodes[*]}"
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

  if (( cycle_found )); then
    echo "$cycles_dot }" > "${GRAPHS_DIR}/cycles-$(timestamp_now).dot" 2>/dev/null || true
    safe_write "$ERROR_LOG" "Dependency cycles detected at $(_timestamp). See graphs/cycles-*.dot"
    return 1
  fi
  log_info "No dependency cycles detected."
  return 0
}
# ----------------------------
# Topological sort (Kahn algorithm)
# ----------------------------
topological_sort() {
  log_info "Performing topological sort..."
  declare -a queue=()
  declare -a result=()
  declare -A indeg

  # initialize indegrees
  for node in "${!GRAPH_INDEGREE[@]}"; do
    indeg["$node"]="${GRAPH_INDEGREE[$node]}"
    if (( indeg["$node"] == 0 )); then
      queue+=("$node")
    fi
  done

  # process queue
  while ((${#queue[@]})); do
    # choose node with lowest PKG_PRIORITY and stable ordering
    local best_idx=0
    local best="${queue[0]}"
    local bestp="${PKG_PRIORITY[$best]:-0}"
    for ((i=1;i<${#queue[@]};i++)); do
      local cand="${queue[i]}"
      local cp="${PKG_PRIORITY[$cand]:-0}"
      if (( cp < bestp )) || { (( cp == bestp )) && [[ "$cand" < "$best" ]]; }; then
        best="$cand"
        bestp="$cp"
        best_idx=$i
      fi
    done
    # pop best_idx
    result+=("$best")
    queue=("${queue[@]:0:$best_idx}" "${queue[@]:$((best_idx+1))}")

    # decrement neighbors
    local neighs=()
    read -r -a neighs <<< "${GRAPH_ADJ[$best]:-}"
    for neigh in "${neighs[@]}"; do
      [[ -z "${indeg[$neigh]:-}" ]] && continue
      indeg["$neigh"]=$((indeg["$neigh"] - 1))
      if (( indeg["$neigh"] == 0 )); then
        queue+=("$neigh")
      fi
    done
  done

  # validate
  local total_nodes=0
  for n in "${!NODE_EXISTS[@]}"; do ((total_nodes++)); done
  if (( ${#result[@]} < total_nodes )); then
    log_error "Topological sort incomplete: processed=${#result[@]} total=${total_nodes}"
    # list remaining
    local remaining=()
    for n in "${!NODE_EXISTS[@]}"; do
      local found=0
      for r in "${result[@]}"; do [[ "$r" == "$n" ]] && found=1 && break; done
      (( found == 0 )) && remaining+=("$n")
    done
    safe_write "$ERROR_LOG" "Unresolved nodes after topological sort: ${remaining[*]}"
    return 1
  fi

  # write outputs
  : > "$BUILD_ORDER_FILE" 2>/dev/null || true
  for n in "${result[@]}"; do echo "$n" >> "$BUILD_ORDER_FILE"; done

  : > "$DEPENDENCY_MAP" 2>/dev/null || true
  for n in "${result[@]}"; do echo "$n: ${PKG_DEPENDS[$n]:-}" >> "$DEPENDENCY_MAP"; done

  # DOT graph
  echo "digraph deps { rankdir=LR; node [shape=box];" > "$DOT_FILE"
  for src in "${!GRAPH_ADJ[@]}"; do
    for dst in ${GRAPH_ADJ[$src]}; do
      echo "\"$src\" -> \"$dst\";" >> "$DOT_FILE"
    done
  done
  echo "}" >> "$DOT_FILE"

  log_info "Build order generated at $BUILD_ORDER_FILE"
  return 0
}

# ----------------------------
# Generate summary
# ----------------------------
generate_summary() {
  local total=0 missing=0 cycles=0
  for k in "${!NODE_EXISTS[@]}"; do ((total++)); done
  [[ -s "$MISSING_LOG" ]] && missing=$(wc -l < "$MISSING_LOG" 2>/dev/null || echo 0)
  [[ -s "$ERROR_LOG" ]] && cycles=$(grep -ci "cycle" "$ERROR_LOG" 2>/dev/null || echo 0)

  local summary
  summary="DEPENDENCY SOLVE SUMMARY:
Date: $(_timestamp)
Packages scanned: ${total}
Missing deps lines: ${missing}
Cycle errors logged: ${cycles}
Build order: ${BUILD_ORDER_FILE}
Dependency map: ${DEPENDENCY_MAP}
DOT graph: ${DOT_FILE}
"
  echo "$summary" > "$SUMMARY_LOG" 2>/dev/null || true
  log_info "$summary"
}

# ----------------------------
# rebuild_all() - usado por update.sh
# ----------------------------
rebuild_all() {
  log_info "Starting full rebuild (rebuild_all)"
  if [[ ! -f "$BUILD_ORDER_FILE" ]]; then
    log_error "Build order file not found: $BUILD_ORDER_FILE"
    return 2
  fi

  local fast_mode="${1:-no}"
  local pkg
  while IFS= read -r pkg; do
    [[ -z "$pkg" ]] && continue
    # skip placeholders/missing nodes
    if [[ "${NODE_EXISTS[$pkg]:-0}" -eq 0 ]]; then
      log_warn "Skipping rebuild of missing placeholder: $pkg"
      continue
    fi
    log_info "Rebuilding package: $pkg"
    if [[ ! -x "$REBUILD_SCRIPT" ]]; then
      log_error "Rebuild script not executable: $REBUILD_SCRIPT"
      return 3
    fi
    if [[ "$fast_mode" == "yes" ]]; then
      "$REBUILD_SCRIPT" --fast "$pkg" >> "${DEPSOLVE_LOG_DIR}/rebuild.log" 2>&1 || {
        log_error "$pkg: fast rebuild failed"
        [[ "${CONTINUE_ON_FAIL}" == "no" ]] && return 4
      }
    else
      "$REBUILD_SCRIPT" "$pkg" >> "${DEPSOLVE_LOG_DIR}/rebuild.log" 2>&1 || {
        log_error "$pkg: rebuild failed"
        [[ "${CONTINUE_ON_FAIL}" == "no" ]] && return 5
      }
    fi
  done < "$BUILD_ORDER_FILE"

  log_info "Full rebuild completed"
  return 0
}

# ----------------------------
# Main controller
# ----------------------------
depsolve_main() {
  log_info "Starting dependency resolution..."
  if [[ ! -d "$PKG_REPO_LOCAL" ]]; then
    log_error "Package repository missing: $PKG_REPO_LOCAL"
    return 1
  fi

  parse_all_desc || log_warn "parse_all_desc returned non-zero (maybe no .desc files)"
  apply_optionals
  build_graph

  if ! detect_cycles; then
    log_error "Dependency cycles detected"
    generate_summary
    [[ "${CONTINUE_ON_FAIL}" == "no" ]] && return 2
  fi

  if ! topological_sort; then
    log_error "Topological sort failed"
    generate_summary
    [[ "${CONTINUE_ON_FAIL}" == "no" ]] && return 3
  fi

  generate_summary
  log_success "depsolve" "complete"
  return 0
}

# ----------------------------
# CLI handling
# ----------------------------
REBUILD_REQ="no"
FAST_REQ="no"
while (( $# )); do
  case "$1" in
    --rebuild-all) REBUILD_REQ="yes"; shift;;
    --fast) FAST_REQ="yes"; shift;;
    --help|-h)
      cat <<EOF
Usage: $(basename "$0") [--rebuild-all] [--fast]
  --rebuild-all : after depsolve, call rebuild_all() to rebuild all packages
  --fast        : used with --rebuild-all to pass --fast to rebuild script
EOF
      exit 0
      ;;
    *) shift;;
  esac
done

trap 'log_warn "Depsolve interrupted by signal"; generate_summary; exit 2' INT TERM

# Execute
if ! depsolve_main; then
  log_error "Depsolve main failed"
fi

if [[ "$REBUILD_REQ" == "yes" ]]; then
  if ! rebuild_all "${FAST_REQ}"; then
    log_error "rebuild_all failed"
    [[ "${CONTINUE_ON_FAIL}" == "no" ]] && exit 5
  fi
fi

log_summary
exit 0
