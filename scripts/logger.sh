#!/usr/bin/env bash
#
# logger.sh - Sistema de registro central do buildsystem
# Compatível com todos os módulos (00-bootstrap, 01-fetch, 02-extract, 03-depsolve, 04-build)
#

set -o errexit
set -o nounset
set -o pipefail

# ============================================
# CONFIGURAÇÃO BÁSICA
# ============================================

: "${ROOT_DIR:=/opt/buildsystem}"
: "${LOG_DIR:=$ROOT_DIR/logs}"
: "${MASTER_LOG:=$LOG_DIR/build-master.log}"
: "${SILENT_MODE:=no}"
: "${LOG_FORMAT:=text}"
: "${SAVE_LOGS:=yes}"
: "${DATE_FMT:='%Y-%m-%d %H:%M:%S'}"

export LOGGER_ACTIVE=1

mkdir -p "$LOG_DIR" 2>/dev/null || true

# ============================================
# CORES E FORMATAÇÃO (modo texto)
# ============================================
if [[ -t 1 && "$SILENT_MODE" == "no" ]]; then
  COLOR_RESET="\033[0m"
  COLOR_INFO="\033[1;34m"
  COLOR_WARN="\033[1;33m"
  COLOR_ERROR="\033[1;31m"
  COLOR_SUCCESS="\033[1;32m"
  COLOR_HEAD="\033[1;36m"
else
  COLOR_RESET=""
  COLOR_INFO=""
  COLOR_WARN=""
  COLOR_ERROR=""
  COLOR_SUCCESS=""
  COLOR_HEAD=""
fi

# ============================================
# FUNÇÕES INTERNAS
# ============================================

timestamp() { date +"$DATE_FMT"; }

_safe_append() {
  local file="$1"; shift
  mkdir -p "$(dirname "$file")" 2>/dev/null || true
  echo "$*" >> "$file" 2>/dev/null || echo "$*" >> "/tmp/logger-fallback.log"
}

_log_console() {
  local color="$1"; shift
  local label="$1"; shift
  local msg="$*"
  if [[ "$SILENT_MODE" != "yes" ]]; then
    echo -e "${color}[${label}]${COLOR_RESET} $msg"
  fi
}

_log_file() {
  local level="$1"; shift
  local msg="$*"
  [[ "$SAVE_LOGS" == "yes" ]] || return 0
  _safe_append "$MASTER_LOG" "[$(timestamp)] [$level] $msg"
}

# ============================================
# FUNÇÕES PÚBLICAS DE LOG
# ============================================

log_init() {
  mkdir -p "$LOG_DIR" || true
  : > "$MASTER_LOG"
  _log_file "SYSTEM" "==============================="
  _log_file "SYSTEM" "BuildSystem iniciado em $(timestamp)"
  _log_file "SYSTEM" "Host: $(hostname)"
  _log_file "SYSTEM" "==============================="
}

log_start() {
  local module="$1"
  local phase="${2:-start}"
  _log_console "$COLOR_HEAD" "START" "[$module] Iniciando fase: $phase"
  _log_file "START" "[$module] Iniciando fase: $phase"
}

log_info() {
  local msg="$*"
  _log_console "$COLOR_INFO" "INFO" "$msg"
  _log_file "INFO" "$msg"
}

log_warn() {
  local msg="$*"
  _log_console "$COLOR_WARN" "WARN" "$msg"
  _log_file "WARN" "$msg"
}

log_error() {
  local msg="$*"
  _log_console "$COLOR_ERROR" "ERROR" "$msg"
  _log_file "ERROR" "$msg"
}

log_success() {
  local module="${1:-general}"
  local phase="${2:-ok}"
  local msg="${3:-Concluído com sucesso}"
  _log_console "$COLOR_SUCCESS" "OK" "[$module] $phase - $msg"
  _log_file "SUCCESS" "[$module] $phase - $msg"
}

log_summary() {
  _log_console "$COLOR_HEAD" "SUMMARY" "Gerando resumo final de build..."
  _safe_append "$MASTER_LOG" "==============================="
  _safe_append "$MASTER_LOG" "RESUMO FINAL — $(timestamp)"
  _safe_append "$MASTER_LOG" "==============================="
  if [[ -f "$LOG_DIR/depsolve/summary.log" ]]; then
    cat "$LOG_DIR/depsolve/summary.log" >> "$MASTER_LOG"
  fi
  if [[ -f "$LOG_DIR/fetch/summary.log" ]]; then
    cat "$LOG_DIR/fetch/summary.log" >> "$MASTER_LOG"
  fi
  if [[ -f "$LOG_DIR/extract/summary.log" ]]; then
    cat "$LOG_DIR/extract/summary.log" >> "$MASTER_LOG"
  fi
  _log_console "$COLOR_SUCCESS" "DONE" "Resumo consolidado em $MASTER_LOG"
}

log_fatal() {
  local msg="$*"
  _log_console "$COLOR_ERROR" "FATAL" "$msg"
  _log_file "FATAL" "$msg"
  exit 1
}

# ============================================
# TRATAMENTO DE SINAIS E LIMPEZA
# ============================================
trap 'log_warn "Interrompido pelo usuário (SIGINT)"; exit 130' INT
trap 'log_warn "Encerrando (SIGTERM)"; exit 143' TERM

# ============================================
# EXEMPLO DE USO (para debug manual)
# ============================================
if [[ "${1:-}" == "--test" ]]; then
  log_init
  log_start "logger" "test"
  log_info "Mensagem informativa"
  log_warn "Aviso"
  log_error "Erro de exemplo"
  log_success "logger" "test" "Tudo OK"
  log_summary
fi
