#!/usr/bin/env bash
#
# 01-fetch.sh - Robust fetcher for sources, git repos and binaries
# Supports: multiple formats, mirrors, git, gpg verify, parallel downloads,
# retries, silent mode, fallbacks, detailed logging.
#
# Usage (example):
#   source /opt/buildsystem/config.txt
#   source /opt/buildsystem/scripts/logger.sh
#   fetch_main [optional: list-of-packages]
#
set -euo pipefail
# -------------------------
# Defaults (if not in config.txt)
# -------------------------
: "${ROOT_DIR:=/opt/buildsystem}"
: "${SRC_DIR:=${ROOT_DIR}/sources}"
: "${PKG_REPO_LOCAL:=${ROOT_DIR}/package}"
: "${BIN_REPO_LOCAL:=${ROOT_DIR}/binaries}"
: "${MIRRORS:=()}"
: "${RETRY_COUNT:=3}"
: "${AUTO_SYNC_PKG_REPO:=yes}"
: "${AUTO_SYNC_BIN_REPO:=no}"
: "${SILENT_MODE:=no}"
: "${LOG_DIR:=${ROOT_DIR}/logs}"
: "${JOBS:=4}"
: "${MAX_FETCH_JOBS:=${JOBS}}"
: "${VERIFY_SIGNATURES:=yes}"
: "${MIN_FREE_KB:=5120}"       # 5MB minimum (fetch checks larger)
: "${FETCH_TIMEOUT:=300}"      # curl timeout default (seconds)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# -------- load config + logger (fail early if missing) ----------
CONFIG_FILE="${ROOT_DIR}/config.txt"
LOGGER_FILE="${SCRIPT_DIR}/logger.sh"

if [[ -f "$CONFIG_FILE" ]]; then
  # shellcheck source=/dev/null
  source "$CONFIG_FILE"
fi

if [[ -f "$LOGGER_FILE" ]]; then
  # shellcheck source=/dev/null
  source "$LOGGER_FILE"
else
  echo "ERROR: logger.sh not found at $LOGGER_FILE" >&2
  exit 1
fi

# Initialize logger if not already
if [[ "${LOGGER_ACTIVE:-0}" -eq 0 ]]; then
  log_init
fi
log_start "fetch" "init"
log_info "Fetch script started"

# -------------------------
# Paths inside sources
# -------------------------
SRC_CACHE_DIR="${SRC_DIR}/cache"
SRC_VERIFIED_DIR="${SRC_DIR}/verified"
SRC_TMP_DIR="${SRC_DIR}/tmp"
SRC_FAILED_DIR="${SRC_DIR}/failed"

mkdir -p "$SRC_CACHE_DIR" "$SRC_VERIFIED_DIR" "$SRC_TMP_DIR" "$SRC_FAILED_DIR" 2>/dev/null || true

# -------------------------
# Helpers
# -------------------------
_timestamp() { date '+%Y-%m-%d %H:%M:%S'; }

# safe echo according to silent mode
sane_echo() {
  if [[ "${SILENT_MODE}" != "yes" ]]; then
    echo "$@"
  fi
}

# check free space on mount containing ROOT_DIR
_check_free_space_or_die() {
  local avail_kb
  avail_kb=$(df -k --output=avail "$ROOT_DIR" 2>/dev/null | tail -n1 || echo 0)
  if [[ -z "$avail_kb" ]]; then avail_kb=0; fi
  if (( avail_kb < MIN_FREE_KB )); then
    log_error "Espaço insuficiente em ${ROOT_DIR} (${avail_kb} KB). Abortando fetch."
    exit 1
  fi
}

# pick a working mirror for a given path suffix (quick HEAD)
# args: <path_suffix> (e.g. "/pub/firefox/releases/.../file.tar.xz")
choose_mirror_for() {
  local suffix="$1"
  local m url rc
  for m in "${MIRRORS[@]}"; do
    url="${m%/}${suffix}"
    # quick HEAD check
    if curl -s --head --fail --max-time 10 "$url" >/dev/null 2>&1; then
      printf "%s" "$m"
      return 0
    fi
  done
  return 1
}

# compute sha256
calc_sha256() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" 2>/dev/null | awk '{print $1}'
  else
    openssl dgst -sha256 "$file" 2>/dev/null | awk '{print $NF}'
  fi
}

# download with curl + retries, writing to target
# args: <url> <target>
download_with_curl() {
  local url="$1"
  local target="$2"
  local attempt=1
  local rc=0
  while (( attempt <= RETRY_COUNT )); do
    log_info "Attempt $attempt downloading $url -> $target"
    # --fail => exit nonzero on HTTP errors, -L follow redirects
    if curl -L --connect-timeout 15 --max-time "$FETCH_TIMEOUT" --retry 2 --retry-delay 3 --fail -o "$target" "$url" 2>>"${LOG_DIR}/fetch/curl.err.log"; then
      rc=0
      break
    else
      rc=$?
      log_warn "Download failed (attempt $attempt) for $url (rc=$rc)"
      ((attempt++))
      sleep $(( attempt ))  # backoff
    fi
  done
  return $rc
}

# gpg verify if asc present and enabled
gpg_verify_if_present() {
  local target="$1"
  local asc="${target}.asc"
  if [[ "${VERIFY_SIGNATURES}" == "yes" ]] && [[ -f "$asc" ]]; then
    if command -v gpg >/dev/null 2>&1; then
      if gpg --no-default-keyring --keyring "${GPG_KEYRING:-/dev/null}" --verify "$asc" "$target" >/dev/null 2>&1; then
        log_info "GPG signature OK for $(basename "$target")"
        return 0
      else
        log_warn "GPG verification failed for $(basename "$target")"
        return 2
      fi
    else
      log_warn "gpg not installed; cannot verify signature for $(basename "$target")"
      return 2
    fi
  fi
  return 0
}

# safe move to verified dir
move_to_verified() {
  local file="$1"
  mkdir -p "$SRC_VERIFIED_DIR" 2>/dev/null || true
  mv -f "$file" "$SRC_VERIFIED_DIR/" 2>/dev/null || mv -f "$file" "$SRC_TMP_DIR/" 2>/dev/null || true
}

# -------------------------
# Parse .desc file (simple parser)
# returns variables: DESC_NAME, DESC_VERSION, DESC_URL, DESC_SHA256, DESC_TYPE
parse_desc() {
  local descfile="$1"
  DESC_NAME=""
  DESC_VERSION=""
  DESC_URL=""
  DESC_SHA256=""
  DESC_TYPE="source"
  if [[ ! -f "$descfile" ]]; then
    return 1
  fi
  # read simple key = value lines
  while IFS= read -r line; do
    # remove spaces around =
    if [[ "$line" =~ ^[[:space:]]*NAME[[:space:]]*=[[:space:]]*(.*)$ ]]; then
      DESC_NAME="${BASH_REMATCH[1]//\"/}"
      DESC_NAME="${DESC_NAME## }"
      DESC_NAME="${DESC_NAME%% }"
    elif [[ "$line" =~ ^[[:space:]]*VERSION[[:space:]]*=[[:space:]]*(.*)$ ]]; then
      DESC_VERSION="${BASH_REMATCH[1]//\"/}"
    elif [[ "$line" =~ ^[[:space:]]*URL[[:space:]]*=[[:space:]]*(.*)$ ]]; then
      DESC_URL="${BASH_REMATCH[1]//\"/}"
    elif [[ "$line" =~ ^[[:space:]]*SHA256[[:space:]]*=[[:space:]]*(.*)$ ]]; then
      DESC_SHA256="${BASH_REMATCH[1]//\"/}"
    elif [[ "$line" =~ ^[[:space:]]*TYPE[[:space:]]*=[[:space:]]*(.*)$ ]]; then
      DESC_TYPE="${BASH_REMATCH[1]//\"/}"
    fi
  done < "$descfile"

  # minimal validation
  if [[ -z "$DESC_NAME" ]] || [[ -z "$DESC_VERSION" ]] || [[ -z "$DESC_URL" ]]; then
    return 2
  fi
  return 0
}

# determine filename from URL
filename_from_url() {
  local url="$1"
  echo "${url##*/}"
}

# extension detection
get_ext() {
  local fname="$1"
  # lower-case
  local l="${fname,,}"
  case "$l" in
    *.tar.gz|*.tgz) printf "tar.gz";;
    *.tar.xz|*.txz) printf "tar.xz";;
    *.tar.bz2|*.tbz2) printf "tar.bz2";;
    *.tar.lz|*.tlz) printf "tar.lz";;
    *.tar.zst|*.tzst) printf "tar.zst";;
    *.zip) printf "zip";;
    *.7z) printf "7z";;
    *.gz) printf "gz";;
    *.xz) printf "xz";;
    *.bz2) printf "bz2";;
    *.zst) printf "zst";;
    *.deb) printf "deb";;
    *.rpm) printf "rpm";;
    *) printf "bin";;
  esac
}

# fetch single package (main worker)
# args: <descfile>
fetch_package() {
  local descfile="$1"
  parse_desc "$descfile" || { log_error "Invalid .desc: $descfile"; return 1; }
  local pkg="${DESC_NAME}"
  local version="${DESC_VERSION}"
  local url="${DESC_URL}"
  local sha256="${DESC_SHA256:-}"
  local type="${DESC_TYPE:-source}"
  local name_file
  name_file=$(filename_from_url "$url")
  local target="${SRC_CACHE_DIR}/${name_file}"

  log_start "$pkg" "fetch"
  log_info "Fetching $pkg ($version) type=$type url=$url"

  # decide if package already exists and valid
  if [[ -f "${SRC_VERIFIED_DIR}/${name_file}" ]]; then
    if [[ -n "$sha256" ]]; then
      local got
      got=$(calc_sha256 "${SRC_VERIFIED_DIR}/${name_file}" || true)
      if [[ "$got" == "$sha256" ]]; then
        log_info "$pkg: already present and verified in ${SRC_VERIFIED_DIR}"
        log_success "$pkg" "fetch"
        return 0
      else
        log_warn "$pkg: present in verified but checksum differs; will re-download"
      fi
    else
      log_info "$pkg: already present in verified and no sha256 to check"
      log_success "$pkg" "fetch"
      return 0
    fi
  fi

  # special handling: git repo
  if [[ "$type" == "git" ]] || [[ "$url" =~ \.git$ ]]; then
    # clone or pull into SRC_CACHE_DIR/git/$pkg
    local gitdir="${SRC_CACHE_DIR}/git/${pkg}"
    mkdir -p "$(dirname "$gitdir")" 2>/dev/null || true
    if [[ ! -d "$gitdir/.git" ]]; then
      log_info "$pkg: cloning git repo $url -> $gitdir"
      if git clone --depth 1 "$url" "$gitdir" >> "${LOG_DIR}/fetch/${pkg}.log" 2>&1; then
        log_success "$pkg" "fetch"
        return 0
      else
        log_error "$pkg: git clone failed"
        return 2
      fi
    else
      log_info "$pkg: updating git repo $gitdir"
      if git -C "$gitdir" pull --ff-only >> "${LOG_DIR}/fetch/${pkg}.log" 2>&1; then
        log_success "$pkg" "fetch"
        return 0
      else
        log_warn "$pkg: git pull failed; attempting clone fresh"
        rm -rf "$gitdir"
        if git clone --depth 1 "$url" "$gitdir" >> "${LOG_DIR}/fetch/${pkg}.log" 2>&1; then
          log_success "$pkg" "fetch"
          return 0
        else
          log_error "$pkg: git clone retry failed"
          return 2
        fi
      fi
    fi
  fi

  # for source/binary types: try mirrors then original URL
  local used_url=""
  local mirror_base
  local suffix
  # if URL is absolute (has host path), compute suffix from origin host path
  # We'll try: original URL first, then try mirrors + suffix
  suffix="${url#*//*/}"   # crude: strip protocol and first host
  if [[ "$suffix" == "$url" ]]; then
    # fallback: use path from url removing scheme+host
    suffix="/${url#*://*/}"
  else
    suffix="/${suffix}"
  fi

  # Try original URL first
  if download_with_curl "$url" "$target"; then
    used_url="$url"
  else
    # try mirrors
    for m in "${MIRRORS[@]}"; do
      # construct mirror url
      local trial="${m%/}/${suffix#/}"
      log_info "$pkg: trying mirror $trial"
      if download_with_curl "$trial" "$target"; then
        used_url="$trial"
        break
      fi
    done
  fi

  if [[ -z "$used_url" ]]; then
    log_error "$pkg: all downloads failed for $url"
    # move any partial file to failed
    [[ -f "$target" ]] && mv -f "$target" "${SRC_FAILED_DIR}/${name_file}.partial" 2>/dev/null || true
    return 3
  fi

  # downloaded - verify size & hash
  if [[ -n "$sha256" ]]; then
    local got
    got=$(calc_sha256 "$target" || echo "")
    if [[ "$got" != "$sha256" ]]; then
      log_error "$pkg: checksum mismatch (expected $sha256 got $got). moving to failed."
      mv -f "$target" "${SRC_FAILED_DIR}/${name_file}.bad" 2>/dev/null || true
      return 4
    fi
  else
    log_warn "$pkg: no sha256 provided, skipping checksum"
  fi

  # optional gpg verify: attempt to download .asc and verify
  if [[ "${VERIFY_SIGNATURES}" == "yes" ]]; then
    local asc_url="${used_url}.asc"
    local asc_target="${target}.asc"
    if download_with_curl "$asc_url" "$asc_target"; then
      if ! gpg_verify_if_present "$target"; then
        log_warn "$pkg: GPG verification failed (but continuing if allowed)"
      fi
    else
      log_info "$pkg: no .asc found at $asc_url (ok)"
      [[ -f "$asc_target" ]] && rm -f "$asc_target" 2>/dev/null || true
    fi
  fi

  # move to verified
  move_to_verified "$target"
  log_success "$pkg" "fetch"
  return 0
}

# -------------------------
# Load .desc files to process
# Accepts optional arguments: list of package names or path to desc files
# If none provided, loads all .desc under PKG_REPO_LOCAL
# -------------------------
load_desc_list() {
  local input=("$@")
  local descs=()
  if (( ${#input[@]} == 0 )); then
    # find .desc files
    if [[ -d "$PKG_REPO_LOCAL" ]]; then
      while IFS= read -r f; do descs+=("$f"); done < <(find "$PKG_REPO_LOCAL" -type f -name "*.desc" -print)
    else
      log_error "PKG_REPO_LOCAL not present: $PKG_REPO_LOCAL"
      return 1
    fi
  else
    # each arg can be package name or path
    for itm in "${input[@]}"; do
      if [[ -f "$itm" ]]; then
        descs+=("$itm")
      else
        # try find by name under PKG_REPO_LOCAL
        local found
        found=$(find "$PKG_REPO_LOCAL" -type f -name "${itm}.desc" -print -quit || true)
        if [[ -n "$found" ]]; then
          descs+=("$found")
        else
          log_warn "No .desc found for input: $itm"
        fi
      fi
    done
  fi

  # dedupe
  DESC_LIST=()
  local d
  for d in "${descs[@]}"; do
    if [[ -f "$d" ]]; then DESC_LIST+=("$d"); fi
  done

  if (( ${#DESC_LIST[@]} == 0 )); then
    log_warn "Nenhum .desc encontrado para fetch"
    return 1
  fi
  return 0
}

# -------------------------
# Parallel dispatcher
# -------------------------
parallel_fetch() {
  local -n list_ref=$1
  local total=${#list_ref[@]}
  log_info "Starting parallel fetch of $total packages (max jobs=${MAX_FETCH_JOBS})"
  mkdir -p "${LOG_DIR}/fetch" 2>/dev/null || true

  # Use a simple job control with background processes and a FIFO queue
  local i=0
  local pids=()
  for desc in "${list_ref[@]}"; do
    ((i++))
    (
      # each worker must source logger to have functions (but we already sourced globally)
      fetch_package "$desc"
    ) &
    pids+=($!)
    # limit
    while (( ${#pids[@]} >= MAX_FETCH_JOBS )); do
      # wait for first to finish
      wait "${pids[0]}" || true
      # remove first pid
      pids=("${pids[@]:1}")
      sleep 0.2
    done
  done

  # wait remaining
  for p in "${pids[@]}"; do
    wait "$p" || true
  done

  log_info "Parallel fetch tasks completed"
}

# -------------------------
# Consolidate results and summary
# -------------------------
generate_summary() {
  mkdir -p "${LOG_DIR}/fetch" 2>/dev/null || true
  local total=0 success=0 failed=0
  local pkg statusfile pkgname
  # check status by looking at logs/ status files created by logger (status dir)
  local status_dir="${LOG_DIR}/status"
  if [[ -d "$status_dir" ]]; then
    for f in "$status_dir"/*.status; do
      [[ -e "$f" ]] || continue
      ((total++))
      if grep -q "^SUCCESS" "$f" 2>/dev/null; then
        ((success++))
      else
        ((failed++))
      fi
    done
  fi

  # if no status files, estimate from verified/failed dirs
  if (( total == 0 )); then
    total=$(ls -1 "${SRC_VERIFIED_DIR}" 2>/dev/null | wc -l || echo 0)
    failed=$(ls -1 "${SRC_FAILED_DIR}" 2>/dev/null | wc -l || echo 0)
    success=$(( total - failed ))
  fi

  local summary_text
  summary_text="FETCH SUMMARY:
Date: $(_timestamp)
Total processed (approx): ${total}
Success (approx): ${success}
Failed (approx): ${failed}
Verified dir: ${SRC_VERIFIED_DIR}
Failed dir: ${SRC_FAILED_DIR}"

  log_info "$summary_text"
  echo "$summary_text" > "${LOG_DIR}/fetch/fetch-summary.txt" 2>/dev/null || true

  # optional JSON
  if [[ "${LOG_FORMAT:-text}" == "json" ]]; then
    local json
    json="{\"date\":\"$(_timestamp)\",\"total\":${total},\"success\":${success},\"failed\":${failed}}"
    echo "$json" > "${LOG_DIR}/fetch/fetch-summary.json" 2>/dev/null || true
  fi
}

# -------------------------
# Main
# -------------------------
fetch_main() {
  # checks
  log_info "Preparing fetch environment"
  _check_free_space_or_die

  # ensure fetch log dir
  mkdir -p "${LOG_DIR}/fetch" 2>/dev/null || true

  # optional: sync pkg repo if configured (bootstrap usually did this)
  if [[ "${AUTO_SYNC_PKG_REPO:-yes}" == "yes" ]] && [[ -d "${PKG_REPO_LOCAL}" ]]; then
    log_info "Auto-sync PKG repo: ${PKG_REPO_LOCAL}"
    if git -C "$PKG_REPO_LOCAL" pull --rebase >> "${LOG_DIR}/fetch/git.log" 2>&1; then
      log_info "PKG repo updated"
    else
      log_warn "PKG repo pull had issues; proceeding with existing files"
    fi
  fi

  # load desc list from arguments (if any)
  load_desc_list "$@" || true

  # run parallel fetch
  parallel_fetch DESC_LIST

  # generate summary
  generate_summary

  log_summary
  log_info "Fetch finished"
}

# Trap signals to gracefully finalize
trap 'log_warn "Fetch interrupted by signal"; generate_summary; log_summary; exit 2' INT TERM

# If script is sourced and called via fetch_main with arguments: allow that.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  # invoked directly; accept optional arguments as package names
  fetch_main "$@"
else
  # sourced: provide function but not run
  :
fi
