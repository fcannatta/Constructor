#!/usr/bin/env bash
#
# logger.sh - Módulo de logging robusto para o sistema de build
# Implementa: log_init, log_start, log_info, log_warn, log_error, log_success,
#             log_summary, log_recover, e utilitários internos.
#
# Uso: source /opt/buildsystem/config.txt
#      source /opt/buildsystem/scripts/logger.sh
#
# O script tenta ser tolerante a erros: nunca deve encerrar o processo chamador.
#

# ---------- Configurações padrão (usadas se não carregadas do config.txt) ----------
: "${ROOT_DIR:=/opt/buildsystem}"
: "${LOG_DIR:=${ROOT_DIR}/logs}"
: "${MASTER_LOG:=${LOG_DIR}/build-master.log}"
: "${SUMMARY_JSON:=${LOG_DIR}/build-summary.json}"
: "${LOG_FORMAT:=text}"     # text | json
: "${SILENT_MODE:=no}"      # yes | no
: "${SAVE_LOGS:=yes}"       # yes | no

# Local de fallback (quando LOG_DIR não for gravável)
FALLBACK_DIR="/tmp/buildsystem-logs"
BUFFER_FILE="${FALLBACK_DIR}/logger-buffer.log"
RECOVERY_QUEUE="${FALLBACK_DIR}/recovery-queue.txt"

# Retentativas e limites
SAFE_WRITE_RETRIES=3
SAFE_WRITE_SLEEP=1         # segundos entre retries
MIN_FREE_KB=5120           # 5 MB mínimo livre antes de considerar "disco cheio"

# Timestamp helper
_timestamp() { date '+%Y-%m-%d %H:%M:%S'; }

# ---------- Estado interno ----------
LOGGER_ACTIVE=0
CURRENT_LOG_FILE=""       # arquivo atual do pacote/fase
CURRENT_PKG=""            # pacote atual
CURRENT_PHASE=""          # fase atual
LOG_DIR_EFFECTIVE="$LOG_DIR"
MASTER_LOG_EFFECTIVE="$MASTER_LOG"
FAILED_LIST="${LOG_DIR_EFFECTIVE}/failed.list"
STATUS_DIR="${LOG_DIR_EFFECTIVE}/status"

# ---------- Funções internas ----------

# log_safe_write <file> <message>
# Escreve de forma atômica e com retries. Em caso de falha, escreve no buffer temporário.
log_safe_write() {
  local file="$1"
  local msg="$2"
  local tmp tmpdir i rc

  # cria diretório do arquivo se necessário
  tmpdir="$(dirname "$file")"
  if ! mkdir -p "$tmpdir" 2>/dev/null; then
    # não consegue criar diretório, usa fallback
    mkdir -p "$FALLBACK_DIR" 2>/dev/null || true
    echo "[$(_timestamp)] WARN: falha ao criar diretório $tmpdir. Usando fallback" >> "$BUFFER_FILE" 2>/dev/null || true
    echo "$msg" >> "$BUFFER_FILE" 2>/dev/null || true
    return 1
  fi

  # escrita atômica via arquivo temporário e mv
  for ((i=1; i<=SAFE_WRITE_RETRIES; i++)); do
    tmp="${file}.$$.$i.tmp"
    printf "%s\n" "$msg" > "$tmp" 2>/dev/null
    rc=$?
    if [[ $rc -eq 0 ]]; then
      # append preserving atomicity: cat tmp >> file && rm tmp
      cat "$tmp" >> "$file" 2>/dev/null && rm -f "$tmp" 2>/dev/null || rc=2
    fi

    if [[ $rc -eq 0 ]]; then
      return 0
    fi

    sleep "$SAFE_WRITE_SLEEP"
  done

  # todas as tentativas falharam -> fallback buffer
  mkdir -p "$FALLBACK_DIR" 2>/dev/null || true
  printf "%s\n" "$msg" >> "$BUFFER_FILE" 2>/dev/null || true
  return 2
}

# checa ambiente de logs: existência, permissão e espaço
log_check_env() {
  # verifica existência do LOG_DIR, tenta criar
  if ! mkdir -p "$LOG_DIR" 2>/dev/null; then
    # fallback
    mkdir -p "$FALLBACK_DIR" 2>/dev/null || true
    LOG_DIR_EFFECTIVE="$FALLBACK_DIR"
    MASTER_LOG_EFFECTIVE="${LOG_DIR_EFFECTIVE}/build-master.log"
    FAILED_LIST="${LOG_DIR_EFFECTIVE}/failed.list"
    STATUS_DIR="${LOG_DIR_EFFECTIVE}/status"
    log_safe_write "$BUFFER_FILE" "[$(_timestamp)] WARN: não foi possível criar ${LOG_DIR}. Usando fallback ${FALLBACK_DIR}"
    return 1
  fi

  # checa permissão de escrita
  if ! touch "${LOG_DIR}/.logger_test" 2>/dev/null; then
    mkdir -p "$FALLBACK_DIR" 2>/dev/null || true
    LOG_DIR_EFFECTIVE="$FALLBACK_DIR"
    MASTER_LOG_EFFECTIVE="${LOG_DIR_EFFECTIVE}/build-master.log"
    FAILED_LIST="${LOG_DIR_EFFECTIVE}/failed.list"
    STATUS_DIR="${LOG_DIR_EFFECTIVE}/status"
    log_safe_write "$BUFFER_FILE" "[$(_timestamp)] WARN: sem permissão para escrever em ${LOG_DIR}. Usando fallback ${FALLBACK_DIR}"
    return 2
  else
    rm -f "${LOG_DIR}/.logger_test" 2>/dev/null || true
  fi

  # checa espaço disponível
  local avail_kb
  avail_kb=$(df -k --output=avail "$LOG_DIR" 2>/dev/null | tail -n1 || echo 0)
  if [[ -z "$avail_kb" ]]; then avail_kb=0; fi
  if (( avail_kb < MIN_FREE_KB )); then
    mkdir -p "$FALLBACK_DIR" 2>/dev/null || true
    LOG_DIR_EFFECTIVE="$FALLBACK_DIR"
    MASTER_LOG_EFFECTIVE="${LOG_DIR_EFFECTIVE}/build-master.log"
    FAILED_LIST="${LOG_DIR_EFFECTIVE}/failed.list"
    STATUS_DIR="${LOG_DIR_EFFECTIVE}/status"
    log_safe_write "$BUFFER_FILE" "[$(_timestamp)] WARN: pouco espaço em $(realpath "$LOG_DIR") (${avail_kb} KB). Usando fallback ${FALLBACK_DIR}"
    return 3
  fi

  # tudo ok
  LOG_DIR_EFFECTIVE="$LOG_DIR"
  MASTER_LOG_EFFECTIVE="$MASTER_LOG"
  FAILED_LIST="${LOG_DIR_EFFECTIVE}/failed.list"
  STATUS_DIR="${LOG_DIR_EFFECTIVE}/status"
  return 0
}

# tenta recuperar buffer temporário para logs oficiais (quando possível)
log_recover() {
  # mover buffer para MASTER_LOG_EFFECTIVE se possível
  if [[ -f "$BUFFER_FILE" ]] && [[ -s "$BUFFER_FILE" ]]; then
    mkdir -p "$LOG_DIR" 2>/dev/null || true
    if touch "$MASTER_LOG_EFFECTIVE" 2>/dev/null; then
      cat "$BUFFER_FILE" >> "$MASTER_LOG_EFFECTIVE" 2>/dev/null || true
      rm -f "$BUFFER_FILE" 2>/dev/null || true
    fi
  fi
}

# internal: escreve linha em master log (e opcionalmente echo)
_master_log() {
  local line="$1"
  log_safe_write "$MASTER_LOG_EFFECTIVE" "$line" >/dev/null 2>&1 || true
  if [[ "$SILENT_MODE" != "yes" ]]; then
    printf "%s\n" "$line"
  fi
}

# ---------- API pública do logger ----------

# log_init
# Inicializa ambiente de logs e escreve cabeçalho
log_init() {
  # tenta checar ambiente
  log_check_env || true

  mkdir -p "$LOG_DIR_EFFECTIVE" 2>/dev/null || true
  mkdir -p "$STATUS_DIR" 2>/dev/null || true

  local header
  header="[$(_timestamp)] === INÍCIO DO BUILD ===
Host: $(hostname)
Root: ${ROOT_DIR}
Log dir efetivo: ${LOG_DIR_EFFECTIVE}
---------------------------------------------"

  _master_log "$header"
  LOGGER_ACTIVE=1

  # tenta recuperar buffers antigos
  log_recover

  return 0
}

# log_start <pkg> <fase>
# Inicia log para pacote/fase e define CURRENT_LOG_FILE
log_start() {
  local pkg="$1"
  local phase="$2"
  CURRENT_PKG="$pkg"
  CURRENT_PHASE="$phase"

  # garante ambiente
  log_check_env || true
  mkdir -p "${LOG_DIR_EFFECTIVE}/${pkg}" 2>/dev/null || true

  CURRENT_LOG_FILE="${LOG_DIR_EFFECTIVE}/${pkg}/${phase}.log"
  # cabeçalho
  local head="[$(_timestamp)] === ${phase^^} ${pkg} ==="
  log_safe_write "$CURRENT_LOG_FILE" "$head" >/dev/null 2>&1 || true

  # também escreve no master
  _master_log "[$(_timestamp)] START: ${pkg} - ${phase}"
  return 0
}

# log_info <mensagem>
log_info() {
  local msg="$*"
  local line="[$(_timestamp)] INFO: ${msg}"
  if [[ -n "$CURRENT_LOG_FILE" ]]; then
    log_safe_write "$CURRENT_LOG_FILE" "$line" >/dev/null 2>&1 || true
  else
    log_safe_write "$MASTER_LOG_EFFECTIVE" "$line" >/dev/null 2>&1 || true
  fi

  if [[ "$SILENT_MODE" != "yes" ]]; then
    echo "$line"
  fi
}

# log_warn <mensagem>
log_warn() {
  local msg="$*"
  local line="[$(_timestamp)] WARN: ${msg}"
  if [[ -n "$CURRENT_LOG_FILE" ]]; then
    log_safe_write "$CURRENT_LOG_FILE" "$line" >/dev/null 2>&1 || true
  else
    log_safe_write "$MASTER_LOG_EFFECTIVE" "$line" >/dev/null 2>&1 || true
  fi

  # registra no master também
  _master_log "$line"
  if [[ "$SILENT_MODE" != "yes" ]]; then
    echo "$line" >&2
  fi
}

# log_error <mensagem>
# Marca pacote como failed (arquivo status) e registra em failed.list
log_error() {
  local msg="$*"
  local line="[$(_timestamp)] ERROR: ${msg}"

  # escreve no log atual (ou master)
  if [[ -n "$CURRENT_LOG_FILE" ]]; then
    log_safe_write "$CURRENT_LOG_FILE" "$line" >/dev/null 2>&1 || true
  else
    log_safe_write "$MASTER_LOG_EFFECTIVE" "$line" >/dev/null 2>&1 || true
  fi

  # atualiza master
  _master_log "$line"

  # registra falha global e status do pacote
  if [[ -n "$CURRENT_PKG" ]]; then
    mkdir -p "$STATUS_DIR" 2>/dev/null || true
    printf "FAIL\n%s\n" "ts: $(_timestamp)" > "${STATUS_DIR}/${CURRENT_PKG}.status" 2>/dev/null || true
    # adiciona em failed.list se não estiver lá
    touch "$FAILED_LIST" 2>/dev/null || true
    if ! grep -Fxq "$CURRENT_PKG" "$FAILED_LIST" 2>/dev/null; then
      log_safe_write "$FAILED_LIST" "$CURRENT_PKG" >/dev/null 2>&1 || true
    fi
  fi

  if [[ "$SILENT_MODE" != "yes" ]]; then
    echo "$line" >&2
  fi
}

# log_success <pkg> <fase> [duracao]
log_success() {
  local pkg="${1:-$CURRENT_PKG}"
  local phase="${2:-$CURRENT_PHASE}"
  local duration="${3:-}"
  local dur_msg=""
  if [[ -n "$duration" ]]; then dur_msg=" (duração: $duration)"; fi

  local line="[$(_timestamp)] SUCCESS: ${pkg} - ${phase}${dur_msg}"

  # escreve no log do pacote/fase
  local file="${LOG_DIR_EFFECTIVE}/${pkg}/${phase}.log"
  log_safe_write "$file" "$line" >/dev/null 2>&1 || true

  # status do pacote: se não existir erro marcado, marcar success
  mkdir -p "$STATUS_DIR" 2>/dev/null || true
  if [[ -f "${STATUS_DIR}/${pkg}.status" ]]; then
    # se já marcado FAIL, mantem FAIL; caso contrário sobrescreve SUCCESS
    if grep -q "^FAIL" "${STATUS_DIR}/${pkg}.status" 2>/dev/null; then
      # mantém FAIL, mas adiciona nota de tentativa
      log_safe_write "${STATUS_DIR}/${pkg}.status" "last-success-at: $(_timestamp)" >/dev/null 2>&1 || true
    else
      printf "SUCCESS\n%s\n" "ts: $(_timestamp)" > "${STATUS_DIR}/${pkg}.status" 2>/dev/null || true
    fi
  else
    printf "SUCCESS\n%s\n" "ts: $(_timestamp)" > "${STATUS_DIR}/${pkg}.status" 2>/dev/null || true
  fi

  _master_log "$line"
  if [[ "$SILENT_MODE" != "yes" ]]; then
    echo "$line"
  fi
}

# log_summary
# Gera resumo final (texto e opcional JSON)
log_summary() {
  log_check_env || true

  local total=0 success=0 failed=0 pkg
  local failed_pkgs=()
  mkdir -p "$STATUS_DIR" 2>/dev/null || true

  for statusfile in "$STATUS_DIR"/*.status; do
    [[ -e "$statusfile" ]] || continue
    ((total++))
    pkg="$(basename "$statusfile" .status)"
    if grep -q "^SUCCESS" "$statusfile" 2>/dev/null; then
      ((success++))
    else
      ((failed++))
      failed_pkgs+=("$pkg")
    fi
  done

  # fallback: se não houver statusfiles, tenta descobrir por diretórios de logs
  if [[ $total -eq 0 ]]; then
    for dir in "$LOG_DIR_EFFECTIVE"/*/; do
      [[ -d "$dir" ]] || continue
      ((total++))
    done
  fi

  local time_total="unknown"
  local date_now="$(_timestamp)"

  # monta mensagem texto
  local summary_text
  summary_text="============================
BUILD FINALIZADO
DATA: ${date_now}
Pacotes verificados: ${total}
Sucesso: ${success}
Falhas: ${failed}
Falhas em: ${failed_pkgs[*]:-none}
Logs em: ${LOG_DIR_EFFECTIVE}
============================"

  # escreve em master log
  _master_log "$summary_text"

  # grava JSON se requisitado
  if [[ "$LOG_FORMAT" == "json" ]] || [[ "$SUMMARY_JSON" != "" ]]; then
    # constrói JSON simples
    local json
    json="{\"date\":\"${date_now}\",\"total\":${total},\"success\":${success},\"failed\":${failed},\"failed_pkgs\":["
    local first=1
    for p in "${failed_pkgs[@]}"; do
      if [[ $first -eq 1 ]]; then
        json+="\"${p}\""
        first=0
      else
        json+=",\"${p}\""
      fi
    done
    json+="],\"log_dir\":\"${LOG_DIR_EFFECTIVE}\"}"
    # tenta gravar
    log_safe_write "$SUMMARY_JSON" "$json" >/dev/null 2>&1 || log_safe_write "$MASTER_LOG_EFFECTIVE" "$json" >/dev/null 2>&1 || true
  fi

  # tenta recuperar buffers pendentes
  log_recover

  return 0
}

# ---------- Inicialização automática se chamado diretamente ----------
# Se o arquivo for executado (não apenas source), inicializa e mostra ajuda mínima.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  echo "logger.sh: este arquivo foi projetado para ser 'sourced' por outros scripts."
  echo "Exemplo:"
  echo "  source /opt/buildsystem/config.txt"
  echo "  source /opt/buildsystem/scripts/logger.sh"
  echo "  log_init"
  echo
  # auto init para conveniência
  log_init
  exit 0
fi

# fim do script
