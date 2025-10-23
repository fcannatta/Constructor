#!/usr/bin/env bash
#
# 03-depsolve.sh - Resolve dependências, detecta ciclos, gera ordem topológica
# - Suporta dependências opcionais controladas por flags em config.txt
# - Detecta e reporta loops
# - Gera: status/build-order.list, status/dependency-map.txt, graphs/depsolve.dot
# - Fornece rebuild_all() para update.sh (usa 04-build.sh)
#
# Usage:
#   source /opt/buildsystem/config.txt
#   source /opt/buildsystem/scripts/logger.sh
#   /opt/buildsystem/scripts/03-depsolve.sh [--rebuild-all] [--fast]
#
set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# ----------------------------
# Load config and logger (best-effort)
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

# Ensure logger active
if [[ "${LOGGER_ACTIVE:-0}" -eq 0 ]]; then
  log_init
fi

log_start "depsolve" "init"

# ----------------------------
# Defaults and derived paths
# ----------------------------
: "${PKG_REPO_LOCAL:=${ROOT_DIR}/package}"
: "${STATUS_DIR:=${LOG_DIR}/status}"
: "${GRAPHS_DIR:=${ROOT_DIR}/graphs}"
: "${DEPSOLVE_LOG_DIR:=${LOG_DIR}/depsolve}"
: "${SILENT_MODE:=no}"
: "${CONTINUE_ON_FAIL:=no}"    # fallback to continue on non-critical errors
: "${REBUILD_SCRIPT:=${SCRIPT_DIR}/04-build.sh}"  # script to call in rebuild_all
: "${TMP_DIR:=/tmp/buildsystem-depsolve}"

mkdir -p "$STATUS_DIR" "$GRAPHS_DIR" "$DEPSOLVE_LOG_DIR" "$TMP_DIR" 2>/dev/null || true

# ----------------------------
# Internal data structures
# ----------------------------
declare -A PKG_VERSION        # PKG_VERSION[name]=version
declare -A PKG_DEPENDS       # PKG_DEPENDS[name]="dep1 dep2"
declare -A PKG_OPTIONAL      # PKG_OPTIONAL[name]="opt1 opt2"
declare -A PKG_CONFLICTS     # PKG_CONFLICTS[name]="bad1 bad2"
declare -A PKG_GROUP         # PKG_GROUP[name]=group
declare -A PKG_PRIORITY      # PKG_PRIORITY[name]=numeric (BUILD_ORDER)
declare -A GRAPH_INDEGREE    # indegree for Kahn
declare -A GRAPH_ADJ         # adjacency: GRAPH_ADJ[node]="n1 n2"
declare -A NODE_EXISTS       # NODE_EXISTS[name]=1 if present
declare -A NORMALIZED_NAME   # optional mapping original -> normalized

BUILD_ORDER_FILE="${STATUS_DIR}/build-order.list"
DEPENDENCY_MAP="${STATUS_DIR}/dependency-map.txt"
DOT_FILE="${GRAPHS_DIR}/depsolve.dot"
ERROR_LOG="${DEPSOLVE_LOG_DIR}/errors.log"
SUMMARY_LOG="${DEPSOLVE_LOG_DIR}/summary.log"
MISSING_LOG="${DEPSOLVE_LOG_DIR}/missing.log"

# Clean previous outputs (but keep backups)
timestamp_now() { date '+%Y-%m-%d_%H-%M-%S'; }
_backup_old() {
  local f="$1"
  if [[ -f "$f" ]]; then
    mv "$f" "${f}.$(timestamp_now).bak" 2>/dev/null || true
  fi
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

# Normalize package name: lowercase, trim, replace spaces with -, strip extension/version heuristics
normalize_pkgname() {
  local name="$1"
  name="${name,,}"                 # lowercase
  name="${name// /-}"              # spaces -> -
  name="${name//_/}"               # remove underscores (optional)
  name="${name//,}"                # remove commas
  name="${name//\(/}"              # remove parens
  name="${name//\)/}"
  # trim leading/trailing non alnum
  name="$(echo "$name" | sed -E 's/^[^a-z0-9]+//; s/[^a-z0-9]+$//')"
  # remove version-like suffixes e.g. "-1.2.3"
  name="$(echo "$name" | sed -E 's/-[0-9]+(\.[0-9]+)*$//')"
  # fallback: if empty, set unknown-N
  if [[ -z "$name" ]]; then
    name="unknown-$(date +%s%N)"
  fi
  printf "%s" "$name"
}

# safe file writer
safe_write() {
  local file="$1"; shift
  local content="$*"
  mkdir -p "$(dirname "$file")" 2>/dev/null || true
  echo "$content" >> "$file" 2>/dev/null || {
    # fallback to tmp
    echo "$content" >> "${TMP_DIR}/$(basename "$file")" 2>/dev/null || true
  }
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

  local desc
  local count=0
  while IFS= read -r -d '' desc; do
    ((count++))
    parse_single_desc "$desc" || {
      log_warn "Skipping invalid .desc: $desc"
      continue
    }
  done < <(find "$PKG_REPO_LOCAL" -type f -name "*.desc" -print0 2>/dev/null || true)

  if (( count == 0 )); then
    log_warn "No .desc files found under $PKG_REPO_LOCAL"
    return 1
  fi
  log_info "Parsed $count .desc files"
  return 0
}

# parse_single_desc <path>
# fills PKG_* associative arrays
parse_single_desc() {
  local descfile="$1"
  local name version depends optional conflicts group build_order
  name=""; version=""; depends=""; optional=""; conflicts=""; group=""; build_order="0"

  while IFS= read -r line || [[ -n "$line" ]]; do
    # remove windows CR
    line="${line//$'\r'/}"
    # strip comments and whitespace
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
  # normalize lists: split by comma/space and rejoin single-space
  depends="$(echo "$depends" | tr ',' ' ' | tr -s ' ' | sed 's/^ *//; s/ *$//')"
  optional="$(echo "$optional" | tr ',' ' ' | tr -s ' ' | sed 's/^ *//; s/ *$//')"
  conflicts="$(echo "$conflicts" | tr ',' ' ' | tr -s ' ' | sed 's/^ *//; s/ *$//')"
  # convert each token to normalized name if possible
  local token out=""
  for token in $depends; do
    token="$(normalize_pkgname "$token")"
    out+="$token "
  done
  PKG_DEPENDS["$n"]="${out%% }"
  out=""
  for token in $optional; do
    token="$(normalize_pkgname "$token")"
    out+="$token "
  done
  PKG_OPTIONAL["$n"]="${out%% }"
  out=""
  for token in $conflicts; do
    token="$(normalize_pkgname "$token")"
    out+="$token "
  done
  PKG_CONFLICTS["$n"]="${out%% }"
  PKG_PRIORITY["$n"]="${build_order:-0}"

  return 0
}

# ----------------------------
# Apply optional dependencies based on config flags
# Flags naming convention: ENABLE_OPTIONAL_<NAME>=yes|no
# We will check both group-level and dependency-level flags.
# ----------------------------
apply_optionals() {
  log_info "Applying optional dependencies according to config flags..."
  local pkg dep opt flag ok
  for pkg in "${!NODE_EXISTS[@]}"; do
    opt="${PKG_OPTIONAL[$pkg]:-}"
    [[ -z "$opt" ]] && continue
    local final_add=""
    for dep in $opt; do
      # check flags:
      # 1) package-specific: ENABLE_OPTIONAL_${pkg}_${dep}
      flag="ENABLE_OPTIONAL_$(echo "${pkg}_${dep}" | tr '[:lower:]' '[:upper:]' | sed 's/[^A-Z0-9]/_/g')"
      ok=""
      if [[ -n "${!flag:-}" ]]; then
        [[ "${!flag}" == "yes" ]] && ok="yes" || ok="no"
      fi
      # 2) dep-level: ENABLE_OPTIONAL_${dep}
      if [[ -z "$ok" ]] && [[ -n "${!("ENABLE_OPTIONAL_$(echo "$dep" | tr '[:lower:]' '[:upper:]' | sed 's/[^A-Z0-9]/_/g')"):-}" ]]; then
        local flag2="ENABLE_OPTIONAL_$(echo "$dep" | tr '[:lower:]' '[:upper:]' | sed 's/[^A-Z0-9]/_/g')"
        [[ "${!flag2}" == "yes" ]] && ok="yes" || ok="no"
      fi
      # 3) group level: ENABLE_OPTIONAL_<GROUP>
      if [[ -z "$ok" ]] && [[ -n "${PKG_GROUP[$pkg]:-}" ]]; then
        local grp="${PKG_GROUP[$pkg]}"
        local gflag="ENABLE_OPTIONAL_$(echo "$grp" | tr '[:lower:]' '[:upper:]' | sed 's/[^A-Z0-9]/_/g')"
        if [[ -n "${!gflag:-}" ]]; then
          [[ "${!gflag}" == "yes" ]] && ok="yes" || ok="no"
        fi
      fi
      # default behavior: include optional dependencies unless explicitly disabled globally
      if [[ -z "$ok" ]]; then
        if [[ "${ALLOW_OPTIONAL_DEPS:-yes}" == "yes" ]]; then
          ok="yes"
        else
          ok="no"
        fi
      fi

      if [[ "$ok" == "yes" ]]; then
        final_add+="$dep "
      fi
    done
    # merge final_add into PKG_DEPENDS
    if [[ -n "$final_add" ]]; then
      PKG_DEPENDS["$pkg"]="${PKG_DEPENDS[$pkg]} ${final_add}"
      # normalize spacing
      PKG_DEPENDS["$pkg"]="$(echo "${PKG_DEPENDS[$pkg]}" | tr -s ' ' | sed 's/^ //; s/ $//')"
    fi
  done
  log_info "Optional dependencies applied."
}

# ----------------------------
# Build adjacency and indegree for Kahn
# ----------------------------
build_graph() {
  log_info "Building dependency graph..."
  local pkg dep cleaned_deps
  # initialize
  for pkg in "${!NODE_EXISTS[@]}"; do
    GRAPH_ADJ["$pkg"]=""    # will store space-separated list of neighbors (dependents)
    GRAPH_INDEGREE["$pkg"]=0
  done

  # iterate packages, add edges dep -> pkg
  for pkg in "${!NODE_EXISTS[@]}"; do
    cleaned_deps="$(echo "${PKG_DEPENDS[$pkg]:-}" | tr -s ' ' | sed 's/^ //; s/ $//')"
    if [[ -z "$cleaned_deps" ]]; then
      PKG_DEPENDS["$pkg"]=""
      continue
    fi
    for dep in $cleaned_deps; do
      # skip self-dependency
      if [[ "$dep" == "$pkg" ]]; then
        log_warn "Self-dependency detected and removed: $pkg -> $dep"
        continue
      fi
      # if dependency does not exist, record missing
      if [[ -z "${NODE_EXISTS[$dep]:-}" ]]; then
        safe_write "$MISSING_LOG" "Missing dependency: $dep required by $pkg"
        log_warn "Missing dependency: $dep required by $pkg"
        # still add node placeholder so graph algorithms can note it
        NODE_EXISTS["$dep"]=0
        GRAPH_ADJ["$dep"]="${GRAPH_ADJ[$dep]:-}"
        GRAPH_INDEGREE["$dep"]="${GRAPH_INDEGREE[$dep]:-0}"
      fi
      # append pkg as dependent of dep
      GRAPH_ADJ["$dep"]="${GRAPH_ADJ[$dep]} $pkg"
      # increment indegree of pkg
      GRAPH_INDEGREE["$pkg"]=$((GRAPH_INDEGREE["$pkg"] + 1))
    done
  done

  # dedupe adjacency lists
  local key val uniq
  for key in "${!GRAPH_ADJ[@]}"; do
    val="${GRAPH_ADJ[$key]}"
    uniq="$(echo "$val" | tr ' ' '\n' | awk 'NF' | sort -u | tr '\n' ' ' | sed 's/ $//')"
    GRAPH_ADJ["$key"]="$uniq"
  done

  log_info "Graph built: nodes=$(echo "${!NODE_EXISTS[@]}" | wc -w | awk '{print $1}')"
}

# ----------------------------
# Detect cycles using DFS (recursive)
# returns 0 if no cycles, 1 if cycle found (also writes cycles.dot & errors.log)
# ----------------------------
detect_cycles() {
  log_info "Detecting cycles in dependency graph..."
  declare -A state  # 0=unvisited, 1=visiting, 2=visited
  local node
  for node in "${!NODE_EXISTS[@]}"; do state["$node"]=0; done

  local path_stack
  local cycle_found=0
  cycles_dot_header="digraph cycles { rankdir=LR; node [shape=box];"
  local cycles_dot_body=""

  # recursive DFS function using subshell to preserve associative array? we will implement iterative stack to avoid recursion depth issues
  for node in "${!NODE_EXISTS[@]}"; do
    if [[ "${state[$node]}" -ne 0 ]]; then continue; fi
    # iterative stack: entries "node|iterator"
    declare -a stack_node=()
    declare -a stack_iter=()
    stack_node+=("$node")
    stack_iter+=("0")
    while ((${#stack_node[@]})); do
      local top_index=$((${#stack_node[@]}-1))
      local cur="${stack_node[$top_index]}"
      local iter="${stack_iter[$top_index]}"
      if [[ "${state[$cur]}" -eq 0 ]]; then
        state["$cur"]=1  # visiting
        path_stack+="$cur "
      fi

      # get adjacency list and split into array
      local neighs=()
      if [[ -n "${GRAPH_ADJ[$cur]:-}" ]]; then
        read -r -a neighs <<< "${GRAPH_ADJ[$cur]}"
      fi

      if (( iter < ${#neighs[@]} )); then
        local nxt="${neighs[$iter]}"
        # increment iterator
        stack_iter[$top_index]=$((iter+1))
        # check state of nxt
        if [[ "${state[$nxt]:-0}" -eq 0 ]]; then
          stack_node+=("$nxt")
          stack_iter+=("0")
          continue
        elif [[ "${state[$nxt]:-0}" -eq 1 ]]; then
          # cycle detected: reconstruct cycle path
          cycle_found=1
          # attempt to get cycle nodes from path_stack
          local path_arr=($path_stack)
          local cycle_nodes=()
          local found=0
          for p in "${path_arr[@]}"; do
            if [[ "$p" == "$nxt" ]]; then found=1; fi
            if (( found )); then cycle_nodes+=("$p"); fi
          done
          cycle_nodes+=("$nxt")
          log_error "Dependency cycle detected: ${cycle_nodes[*]}"
          # append to cycles dot
          local i
          for ((i=0;i<${#cycle_nodes[@]}-1;i++)); do
            cycles_dot_body+="${cycle_nodes[i]} -> ${cycle_nodes[i+1]}; "
          done
          cycles_dot_body+="${cycle_nodes[-1]} -> ${cycle_nodes[0]}; "
          # break out: we'll keep scanning to log all cycles but we can decide to stop later
        fi
        # continue loop
      else
        # finished adjacency
        state["$cur"]=2
        # pop stack
        unset 'stack_node[top_index]'
        unset 'stack_iter[top_index]'
        # remove last occurrence of cur from path_stack
        path_stack="$(echo "$path_stack" | sed -E "s/ ?$cur ?//")"
      fi
    done
  done

  if (( cycle_found )); then
    # write dot
    echo "${cycles_dot_header} ${cycles_dot_body} }" > "${GRAPHS_DIR}/cycles-$(timestamp_now).dot" 2>/dev/null || true
    safe_write "$ERROR_LOG" "Dependency cycles detected at $(_timestamp). See graphs/cycles-*.dot"
    return 1
  fi
  log_info "No dependency cycles detected."
  return 0
}

# ----------------------------
# Topological sort (Kahn). Produces ORDERED_LIST (global)
# ----------------------------
topological_sort() {
  log_info "Performing topological sort (Kahn algorithm)..."
  declare -a queue=()
  declare -a result=()
  local node indeg

  # copy indegrees into a local associative array (to mutate)
  declare -A indeg
  for node in "${!GRAPH_INDEGREE[@]}"; do
    indeg["$node"]="${GRAPH_INDEGREE[$node]}"
  done

  # enqueue nodes with indeg 0
  for node in "${!indeg[@]}"; do
    if (( indeg[$node] == 0 )); then
      queue+=("$node")
    fi
  done

  # optionally sort queue by priority (lower BUILD_ORDER first) - keep stable
  # We'll implement by always selecting the node with lowest PKG_PRIORITY
  while ((${#queue[@]})); do
    # pick index of node with smallest priority (and then lexicographic)
    local best_idx=0
    local best_node="${queue[0]}"
    local i
    for ((i=1;i<${#queue[@]};i++)); do
      local cand="${queue[i]}"
      local bp="${PKG_PRIORITY[$best_node]:-0}"
      local cp="${PKG_PRIORITY[$cand]:-0}"
      if (( cp < bp )); then
        best_idx=$i
        best_node="$cand"
      elif (( cp == bp )) && [[ "$cand" < "$best_node" ]]; then
        best_idx=$i
        best_node="$cand"
      fi
    done
    # pop best_idx
    local node="${queue[$best_idx]}"
    queue=("${queue[@]:0:$best_idx}" "${queue[@]:$((best_idx+1))}")
    result+=("$node")
    # for each neighbor (dependent), decrement indegree
    local neighs=()
    read -r -a neighs <<< "${GRAPH_ADJ[$node]:-}"
    for neigh in "${neighs[@]}"; do
      if [[ -z "${indeg[$neigh]:-}" ]]; then continue; fi
      indeg["$neigh"]=$((indeg["$neigh"] - 1))
      if (( indeg["$neigh"] == 0 )); then
        queue+=("$neigh")
      fi
    done
  done

  # check if all nodes processed (only count nodes that actually exist as packages)
  local total_nodes=0 processed=0
  for node in "${!NODE_EXISTS[@]}"; do
    # consider as relevant nodes those that were defined (NODE_EXISTS==1) or placeholders (0) - treat both but report missing later
    ((total_nodes++))
  done
  processed=${#result[@]}

  if (( processed < total_nodes )); then
    log_error "Topological sort incomplete: processed=$processed total=$total_nodes - possible cycles or missing dependencies"
    # find remaining nodes
    local remaining=()
    for node in "${!NODE_EXISTS[@]}"; do
      local found=0
      for r in "${result[@]}"; do [[ "$r" == "$node" ]] && found=1 && break; done
      if (( found == 0 )); then remaining+=("$node"); fi
    done
    safe_write "$ERROR_LOG" "Unresolved nodes after topological sort: ${remaining[*]}"
    return 1
  fi

  # output ordered list to file
  : > "$BUILD_ORDER_FILE" 2>/dev/null || true
  for n in "${result[@]}"; do
    echo "$n" >> "$BUILD_ORDER_FILE"
  done

  # write dependency map
  : > "$DEPENDENCY_MAP" 2>/dev/null || true
  for n in "${result[@]}"; do
    echo "$n: ${PKG_DEPENDS[$n]:-}" >> "$DEPENDENCY_MAP"
  done

  # generate DOT file for graph
  echo "digraph deps { rankdir=LR; node [shape=box];" > "$DOT_FILE" 2>/dev/null || true
  for n in "${!GRAPH_ADJ[@]}"; do
    for dep in ${GRAPH_ADJ[$n]}; do
      # only write edges where both nodes are non-empty
      echo "\"${n}\" -> \"${dep}\";" >> "$DOT_FILE" 2>/dev/null || true
    done
  done
  echo "}" >> "$DOT_FILE" 2>/dev/null || true

  log_info "Topological sort complete. Build order saved to $BUILD_ORDER_FILE"
  return 0
}

# ----------------------------
# Generate summary
# ----------------------------
generate_summary() {
  local total=0 missing=0 cycles=0
  total=$(echo "${!NODE_EXISTS[@]}" | wc -w | awk '{print $1}')
  if [[ -s "$MISSING_LOG" ]]; then
    missing=$(wc -l < "$MISSING_LOG" 2>/dev/null || echo 0)
  fi
  if [[ -s "$ERROR_LOG" ]]; then
    cycles=$(grep -c "cycle\|Cycle\|CYCLE" "$ERROR_LOG" 2>/dev/null || echo 0)
  fi

  local summary
  summary="DEPENDENCY SOLVE SUMMARY:
Date: $(_timestamp)
Total nodes scanned: ${total}
Missing dependencies logged: ${missing}
Cycle errors logged: ${cycles}
Build order: ${BUILD_ORDER_FILE}
Dependency map: ${DEPENDENCY_MAP}
Graph DOT: ${DOT_FILE}
"

  echo "$summary" > "$SUMMARY_LOG" 2>/dev/null || true
  log_info "$summary"
}

# ----------------------------
# rebuild_all - used by update.sh to rebuild everything in correct order
# returns: 0 on success, non-zero on first critical failure (unless CONTINUE_ON_FAIL=yes)
# ----------------------------
rebuild_all() {
  log_info "rebuild_all(): starting full rebuild according to $BUILD_ORDER_FILE"
  if [[ ! -f "$BUILD_ORDER_FILE" ]]; then
    log_error "Build order file not found: $BUILD_ORDER_FILE"
    return 2
  fi
  local fast_mode="${1:-no}"
  local pkg
  while IFS= read -r pkg; do
    [[ -z "$pkg" ]] && continue
    # skip placeholders (NODE_EXISTS 0) - these are missing deps
    if [[ "${NODE_EXISTS[$pkg]:-0}" -eq 0 ]]; then
      log_warn "Skipping rebuild of placeholder/missing package: $pkg"
      continue
    fi
    log_info "Rebuilding package: $pkg"
    if [[ -x "$REBUILD_SCRIPT" ]]; then
      if [[ "$fast_mode" == "yes" ]]; then
        "$REBUILD_SCRIPT" --fast "$pkg" >> "${DEPSOLVE_LOG_DIR}/rebuild.log" 2>&1 || {
          log_error "$pkg: rebuild failed (fast). See ${DEPSOLVE_LOG_DIR}/rebuild.log"
          if [[ "${CONTINUE_ON_FAIL}" == "no" ]]; then
            return 3
          fi
        }
      else
        "$REBUILD_SCRIPT" "$pkg" >> "${DEPSOLVE_LOG_DIR}/rebuild.log" 2>&1 || {
          log_error "$pkg: rebuild failed. See ${DEPSOLVE_LOG_DIR}/rebuild.log"
          if [[ "${CONTINUE_ON_FAIL}" == "no" ]]; then
            return 4
          fi
        }
      fi
    else
      log_error "Rebuild script not executable: $REBUILD_SCRIPT"
      return 5
    fi
  done < "$BUILD_ORDER_FILE"

  log_info "rebuild_all(): completed"
  return 0
}

# ----------------------------
# Main routine
# ----------------------------
depsolve_main() {
  log_info "Starting depsolve_main..."
  # sanity checks
  if [[ ! -d "$PKG_REPO_LOCAL" ]]; then
    log_error "Package repository missing: $PKG_REPO_LOCAL"
    return 1
  fi

  parse_all_desc || log_warn "parse_all_desc returned non-zero (may be no desc files)"

  # apply optional dependencies according to config
  apply_optionals

  # build graph
  build_graph

  # detect cycles
  if ! detect_cycles; then
    log_error "Dependency cycles detected - aborting depsolve"
    generate_summary
    if [[ "${CONTINUE_ON_FAIL}" == "no" ]]; then
      return 2
    fi
  fi

  # topological sort
  if ! topological_sort; then
    log_error "Topological sort failed"
    generate_summary
    if [[ "${CONTINUE_ON_FAIL}" == "no" ]]; then
      return 3
    fi
  fi

  generate_summary
  log_success "depsolve" "complete"
  return 0
}

# ----------------------------
# CLI handling: support --rebuild-all and --fast
# ----------------------------
REBUILD_REQ="no"
FAST_REQ="no"
while (( $# )); do
  case "$1" in
    --rebuild-all) REBUILD_REQ="yes"; shift;;
    --fast) FAST_REQ="yes"; shift;;
    --help|-h) echo "Usage: $0 [--rebuild-all] [--fast]"; exit 0;;
    *) shift;;
  esac
done

# trap signals gracefully
trap 'log_warn "Depsolve interrupted (signal)."; generate_summary; exit 2' INT TERM

# run main
if ! depsolve_main; then
  log_error "Depsolve main failed"
fi

# optional rebuild
if [[ "$REBUILD_REQ" == "yes" ]]; then
  if ! rebuild_all "${FAST_REQ}"; then
    log_error "rebuild_all failed"
    if [[ "${CONTINUE_ON_FAIL}" == "no" ]]; then
      exit 5
    fi
  fi
fi

# finish
log_summary
exit 0
