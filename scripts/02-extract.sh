#!/usr/bin/env bash
#
# 02-extract.sh - Extrai pacotes, aplica patches e prepara ambiente de build
# Suporta: .tar.gz .tar.xz .tar.bz2 .tar.lz .tar.zst .zip .7z .deb .rpm .git clones
#            com tratamento robusto de erros, modo silencioso e logs integrados.
#
# Uso:
#   source /opt/buildsystem/config.txt
#   source /opt/buildsystem/scripts/logger.sh
#   /opt/buildsystem/scripts/02-extract.sh [optional: list-of-packages-or-desc-files]
#
set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# -----------------------
# Load config and logger
# -----------------------
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

log_start "extract" "init"

# -----------------------
# Defaults (if not set in config)
# -----------------------
: "${ROOT_DIR:=/opt/buildsystem}"
: "${SRC_VERIFIED_DIR:=${ROOT_DIR}/sources/verified}"
: "${BUILD_DIR:=${ROOT_DIR}/build}"
: "${BUILD_TMP_DIR:=${BUILD_DIR}/tmp}"
: "${LOG_DIR:=${ROOT_DIR}/logs}"
: "${PATCHES_DIR:=${ROOT_DIR}/package}"   # expects package/<pkg>/patches/
: "${SILENT_MODE:=no}"
: "${MIN_FREE_KB:=5242880}"   # 5GB as safety for extraction (config can override)
: "${CONTINUE_ON_FAIL:=no}"

# Derived
EXTRACT_LOG_DIR="${LOG_DIR}/extract"
STATUS_DIR="${LOG_DIR}/status"
EXTRACTED_LIST="${STATUS_DIR}/extracted.list"
CURRENT_ENV="${STATUS_DIR}/current-build.env"

mkdir -p "$EXTRACT_LOG_DIR" "$STATUS_DIR" "$BUILD_TMP_DIR" 2>/dev/null || true

# -----------------------
# Helpers
# -----------------------
_timestamp() { date '+%Y-%m-%d %H:%M:%S'; }

# safe echo depending on silent mode
sane_echo() {
  if [[ "${SILENT_MODE}" != "yes" ]]; then
    echo "$@"
  fi
}

# check free space for ROOT_DIR
_check_free_space_or_abort() {
  local avail_kb
  avail_kb=$(df -k --output=avail "$ROOT_DIR" 2>/dev/null | tail -n1 || echo 0)
  if [[ -z "$avail_kb" ]]; then avail_kb=0; fi
  if (( avail_kb < MIN_FREE_KB )); then
    log_error "Espaço insuficiente em $ROOT_DIR (${avail_kb} KB). Abortando extração."
    exit 1
  fi
}

# normalize package name from filename or desc (remove version extension)
pkgname_from_filename() {
  local fname="$1"
  # try to strip common suffixes: -1.2.3.tar.xz or _1.2.3.tar.gz
  local base
  base="$(basename "$fname")"
  # remove extensions
  base="${base%.tar.xz}"
  base="${base%.tar.gz}"
  base="${base%.tgz}"
  base="${base%.tar.bz2}"
  base="${base%.tbz2}"
  base="${base%.tar.lz}"
  base="${base%.tar.zst}"
  base="${base%.zip}"
  base="${base%.7z}"
  base="${base%.gz}"
  base="${base%.xz}"
  base="${base%.bz2}"
  base="${base%.zst}"
  base="${base%.deb}"
  base="${base%.rpm}"
  # strip version suffix if present (heuristic)
  base="${base%%-[0-9]*}"
  echo "$base"
}

# safe remove directory with retries
safe_rmdir() {
  local dir="$1"
  if [[ -d "$dir" ]]; then
    if rm -rf "$dir" 2>/dev/null; then
      return 0
    fi
    chmod -R u+w "$dir" 2>/dev/null || true
    rm -rf "$dir" 2>/dev/null || true
  fi
  return 0
}

# extraction helpers
_extract_tar() {
  local src="$1"; local dest="$2"
  if command -v tar >/dev/null 2>&1; then
    # use tar autodetect
    tar -xf "$src" -C "$dest" 2>>"${EXTRACT_LOG_DIR}/tar.err.log"
    return $?
  fi
  return 1
}

_extract_zip() {
  local src="$1"; local dest="$2"
  if command -v unzip >/dev/null 2>&1; then
    unzip -q "$src" -d "$dest" 2>>"${EXTRACT_LOG_DIR}/unzip.err.log"
    return $?
  fi
  return 1
}

_extract_7z() {
  local src="$1"; local dest="$2"
  if command -v 7z >/dev/null 2>&1; then
    7z x "$src" -o"$dest" -y >>"${EXTRACT_LOG_DIR}/7z.log" 2>&1
    return $?
  fi
  return 1
}

_extract_deb() {
  local src="$1"; local dest="$2"
  if command -v ar >/dev/null 2>&1 && command -v tar >/dev/null 2>&1; then
    local tmpd
    tmpd="$(mktemp -d "${BUILD_TMP_DIR}/deb-XXXX")"
    (cd "$tmpd" && ar x "$src" >>"${EXTRACT_LOG_DIR}/deb.log" 2>&1)
    # extract data.tar.* if present
    shopt -s nullglob
    for f in "$tmpd"/data.tar.*; do
      tar -xf "$f" -C "$dest" >>"${EXTRACT_LOG_DIR}/deb.log" 2>&1 || true
    done
    rm -rf "$tmpd" 2>/dev/null || true
    return 0
  fi
  return 1
}

_extract_rpm() {
  local src="$1"; local dest="$2"
  if command -v rpm2cpio >/dev/null 2>&1 && command -v cpio >/dev/null 2>&1; then
    rpm2cpio "$src" | (cd "$dest" && cpio -idmv) >>"${EXTRACT_LOG_DIR}/rpm.log" 2>&1
    return $?
  fi
  return 1
}

# apply patches: expects patches directory e.g. package/<pkg>/patches/
apply_patches_for_pkg() {
  local pkg="$1"
  local workdir="$2"
  local patches_dir="${PATCHES_DIR}/${pkg}/patches"
  if [[ ! -d "$patches_dir" ]]; then
    log_info "$pkg: nenhum patch encontrado em $patches_dir"
    return 0
  fi

  # apply patches in sorted order
  local p
  for p in "$(ls "$patches_dir" 2>/dev/null | sort -V)"; do
    local patchfile="${patches_dir}/${p}"
    [[ -f "$patchfile" ]] || continue
    log_info "$pkg: aplicando patch $p"
    # try patch -p1 first then -p0
    if (cd "$workdir" && patch -p1 --forward < "$patchfile" >>"${EXTRACT_LOG_DIR}/${pkg}.patch.log" 2>&1); then
      log_info "$pkg: patch $p aplicado (-p1)"
    elif (cd "$workdir" && patch -p0 --forward < "$patchfile" >>"${EXTRACT_LOG_DIR}/${pkg}.patch.log" 2>&1); then
      log_info "$pkg: patch $p aplicado (-p0)"
    else
      log_warn "$pkg: falha ao aplicar patch $p (veja ${EXTRACT_LOG_DIR}/${pkg}.patch.log)"
      if [[ "${CONTINUE_ON_FAIL}" == "no" ]]; then
        log_error "$pkg: abortando extração por falha no patch $p"
        return 2
      fi
    fi
  done

  return 0
}

# prepare environment for build: create env file consumed by build script
prepare_env_for_pkg() {
  local pkg="$1"
  local version="$2"
  local srcdir="$3"
  local dest_env="${CURRENT_ENV}"
  mkdir -p "$(dirname "$dest_env")" 2>/dev/null || true
  {
    echo "BUILD_PKG_NAME=\"$pkg\""
    echo "BUILD_PKG_VERSION=\"$version\""
    echo "BUILD_SRC_DIR=\"$srcdir\""
    echo "BUILD_TMP_DIR=\"$BUILD_TMP_DIR\""
    echo "CFLAGS=\"${CFLAGS:-}\""
    echo "CXXFLAGS=\"${CXXFLAGS:-}\""
    echo "LDFLAGS=\"${LDFLAGS:-}\""
    echo "MAKEFLAGS=\"${MAKEFLAGS:-}\""
  } > "$dest_env" 2>/dev/null || true
  # mark package-specific env too
  echo "$pkg:$srcdir" >> "${STATUS_DIR}/extracted.map" 2>/dev/null || true
  return 0
}

# log and mark failure for the package
mark_pkg_failed() {
  local pkg="$1"
  log_error "$pkg: extração falhou"
  # append to extracted list as failed marker
  echo "FAILED:$pkg" >> "$EXTRACT_LOG_DIR/extract-failures.txt" 2>/dev/null || true
}

# mark success
mark_pkg_success() {
  local pkg="$1"
  echo "$pkg" >> "$EXTRACTED_LIST" 2>/dev/null || true
  log_success "$pkg" "extract"
}

# -----------------------
# parse optional arguments (list of package names or desc files)
# -----------------------
REQUESTED_DESC=()
if (( $# > 0 )); then
  for a in "$@"; do
    REQUESTED_DESC+=("$a")
  done
fi

# gather candidate archives from SRC_VERIFIED_DIR
gather_candidates() {
  local list=()
  if (( ${#REQUESTED_DESC[@]} > 0 )); then
    # if argument is file (desc or file) then use directly, else try to find matching file by name
    for r in "${REQUESTED_DESC[@]}"; do
      if [[ -f "$r" ]]; then
        list+=("$r")
      else
        # try find by pattern in verified dir
        local found
        found="$(find "$SRC_VERIFIED_DIR" -type f -iname "*${r}*" -print -quit 2>/dev/null || true)"
        if [[ -n "$found" ]]; then
          list+=("$found")
        else
          log_warn "Nenhum artefato encontrado para pedido: $r"
        fi
      fi
    done
  else
    while IFS= read -r -d '' f; do
      list+=("$f")
    done < <(find "$SRC_VERIFIED_DIR" -maxdepth 1 -type f -print0 2>/dev/null || true)
  fi

  CANDIDATES=("${list[@]}")
  return 0
}

# extract a single candidate file
extract_candidate() {
  local srcfile="$1"
  local fname
  fname="$(basename "$srcfile")"
  local pkg
  pkg="$(pkgname_from_filename "$fname")"
  local workdir="${BUILD_TMP_DIR}/${pkg}"
  local logpkg="${EXTRACT_LOG_DIR}/${pkg}.log"

  log_start "$pkg" "extract"
  log_info "$pkg: iniciando extração do arquivo $fname"

  # cleanup previous
  safe_rmdir "$workdir"
  mkdir -p "$workdir" 2>/dev/null || true

  # try to detect type
  local ext
  ext="$(echo "$fname" | tr '[:upper:]' '[:lower:]')"

  local rc=0

  if [[ "$ext" =~ \.tar\.gz$ ]] || [[ "$ext" =~ \.tgz$ ]] || [[ "$ext" =~ \.tar\.xz$ ]] || [[ "$ext" =~ \.txz$ ]] || [[ "$ext" =~ \.tar\.bz2$ ]] || [[ "$ext" =~ \.tbz2$ ]] || [[ "$ext" =~ \.tar\.lz$ ]] || [[ "$ext" =~ \.tar\.zst$ ]] || [[ "$ext" =~ \.tar$ ]] ; then
    if _extract_tar "$srcfile" "$workdir"; then
      log_info "$pkg: tar extraído com sucesso em $workdir"
    else
      log_warn "$pkg: tar extraction error, tentando bsdtar (se disponível)"
      if command -v bsdtar >/dev/null 2>&1 && bsdtar -xf "$srcfile" -C "$workdir" >>"$logpkg" 2>&1; then
        log_info "$pkg: extração com bsdtar bem sucedida"
      else
        log_error "$pkg: falha ao extrair tarball"
        rc=1
      fi
    fi

  elif [[ "$ext" =~ \.zip$ ]]; then
    if _extract_zip "$srcfile" "$workdir"; then
      log_info "$pkg: zip extraído"
    else
      log_error "$pkg: falha ao extrair zip"
      rc=1
    fi

  elif [[ "$ext" =~ \.7z$ ]]; then
    if _extract_7z "$srcfile" "$workdir"; then
      log_info "$pkg: 7z extraído"
    else
      log_error "$pkg: falha ao extrair 7z"
      rc=1
    fi

  elif [[ "$ext" =~ \.deb$ ]]; then
    if _extract_deb "$srcfile" "$workdir"; then
      log_info "$pkg: deb extraído"
    else
      log_warn "$pkg: falha ao extrair deb usando ar/tar"
      rc=1
    fi

  elif [[ "$ext" =~ \.rpm$ ]]; then
    if _extract_rpm "$srcfile" "$workdir"; then
      log_info "$pkg: rpm extraído"
    else
      log_warn "$pkg: falha ao extrair rpm"
      rc=1
    fi

  else
    # fallback: try tar autodetect then 7z then unzip
    if _extract_tar "$srcfile" "$workdir"; then
      log_info "$pkg: extraído como tar (fallback)"
    elif _extract_7z "$srcfile" "$workdir"; then
      log_info "$pkg: extraído como 7z (fallback)"
    elif _extract_zip "$srcfile" "$workdir"; then
      log_info "$pkg: extraído como zip (fallback)"
    else
      log_error "$pkg: formato não suportado ou extração falhou"
      rc=1
    fi
  fi

  # if extraction succeeded, usually extraction creates a subdir (source root) - detect it
  if [[ $rc -eq 0 ]]; then
    # if workdir contains a single directory, set srctree to that; else use workdir
    local srctree
    shopt -s nullglob
    local entries=( "$workdir"/* )
    if (( ${#entries[@]} == 1 )) && [[ -d "${entries[0]}" ]]; then
      srctree="${entries[0]}"
    else
      srctree="$workdir"
    fi
    shopt -u nullglob

    # apply patches if exist
    if ! apply_patches_for_pkg "$pkg" "$srctree"; then
      mark_pkg_failed "$pkg"
      # cleanup partial if CONTINUE_ON_FAIL=no (we already logged inside apply_patches)
      if [[ "${CONTINUE_ON_FAIL}" == "no" ]]; then
        safe_rmdir "$workdir"
        return 1
      fi
    fi

    # standardize permissions (user writable)
    chmod -R u+rwX "$srctree" 2>/dev/null || true

    # prepare env for build
    prepare_env_for_pkg "$pkg" "unknown" "$srctree"

    # mark success
    mark_pkg_success "$pkg"
    log_info "$pkg: extração concluída; fonte em $srctree"
    return 0
  else
    # move file to failed dir for inspection
    mkdir -p "$SRC_VERIFIED_DIR/../failed" 2>/dev/null || true
    mv -f "$srcfile" "$SRC_VERIFIED_DIR/../failed/" 2>/dev/null || true
    mark_pkg_failed "$pkg"
    return 2
  fi
}

# -----------------------
# Main flow
# -----------------------
extract_main() {
  log_info "Iniciando fase de extração"
  _check_free_space_or_abort

  gather_candidates

  if (( ${#CANDIDATES[@]} == 0 )); then
    log_warn "Nenhum arquivo para extrair em $SRC_VERIFIED_DIR"
    log_summary
    return 0
  fi

  # ensure per-package logs dir exists
  mkdir -p "$EXTRACT_LOG_DIR" 2>/dev/null || true

  # iterate candidates sequentially (could be parallelized if needed)
  local failed_count=0
  for c in "${CANDIDATES[@]}"; do
    if ! extract_candidate "$c"; then
      ((failed_count++))
      # continue with others (we don't abort entire run unless critical)
    fi
  done

  # summary
  local total=${#CANDIDATES[@]}
  local success_count=0
  if [[ -f "$EXTRACTED_LIST" ]]; then
    success_count=$(wc -l < "$EXTRACTED_LIST" 2>/dev/null || echo 0)
  fi
  local failed_est=$(( total - success_count ))

  log_info "Extração finalizada: total=${total} success=${success_count} failed=${failed_est}"
  log_summary
}

# Trap
trap 'log_error "Extração interrompida (linha $LINENO)"; log_summary; exit 2' INT TERM ERR

# If script invoked directly, run extract_main with args
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  extract_main "$@"
else
  # when sourced, expose functions
  :
fi
