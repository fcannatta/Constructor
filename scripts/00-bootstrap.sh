#!/usr/bin/env bash
#
# 00-bootstrap.sh — Inicialização do sistema de build
# Versão: 1.0
# Função: preparar ambiente, validar dependências, sincronizar repositórios e iniciar logs.
#

set -euo pipefail

# -----------------------------
# 1️⃣ Carrega configurações globais
# -----------------------------
CONFIG_FILE="/opt/buildsystem/config.txt"
LOGGER_FILE="/opt/buildsystem/scripts/logger.sh"

if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "ERRO: Arquivo de configuração não encontrado: $CONFIG_FILE" >&2
  exit 1
fi

source "$CONFIG_FILE"

if [[ ! -f "$LOGGER_FILE" ]]; then
  echo "ERRO: logger.sh não encontrado em $LOGGER_FILE" >&2
  exit 1
fi

source "$LOGGER_FILE"
log_init
log_start "bootstrap" "init"
log_info "Bootstrap iniciado..."

# -----------------------------
# 2️⃣ Função: verificar dependências obrigatórias
# -----------------------------
check_tools() {
  local missing=()
  log_info "Verificando ferramentas obrigatórias..."
  for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      missing+=("$tool")
      log_error "Dependência ausente: $tool"
    else
      log_info "✓ $tool encontrado"
    fi
  done

  if (( ${#missing[@]} > 0 )); then
    echo "${missing[@]}" > "$LOG_DIR/missing-tools.log" 2>/dev/null || true
    if [[ "${CONTINUE_ON_FAIL:-no}" == "no" ]]; then
      log_error "Dependências críticas ausentes. Abortando bootstrap."
      log_summary
      exit 1
    fi
  fi
}

# -----------------------------
# 3️⃣ Função: criar estrutura de diretórios
# -----------------------------
create_structure() {
  local dirs=("$SRC_DIR" "$BUILD_DIR" "$LOG_DIR" "$OUTPUT_DIR" "$TOOLCHAIN_DIR" "$DB_DIR" "$HOOKS_DIR")
  log_info "Criando estrutura de diretórios..."
  for d in "${dirs[@]}"; do
    if mkdir -p "$d" 2>/dev/null; then
      log_info "Diretório OK: $d"
    else
      log_warn "Falha ao criar diretório: $d — tentando fallback /tmp"
      mkdir -p "/tmp$(basename "$d")" 2>/dev/null || true
    fi
  done
}

# -----------------------------
# 4️⃣ Função: verificar espaço em disco e permissões
# -----------------------------
check_space() {
  local avail_kb
  avail_kb=$(df -k --output=avail "$ROOT_DIR" 2>/dev/null | tail -n1 || echo 0)
  if [[ -z "$avail_kb" ]]; then avail_kb=0; fi
  local avail_gb=$((avail_kb / 1024 / 1024))

  if (( avail_kb < 5242880 )); then  # <5GB
    log_error "Espaço insuficiente em disco (${avail_gb}GB livres). É necessário ao menos 5GB."
    exit 1
  fi

  if ! touch "$ROOT_DIR/.perm_test" 2>/dev/null; then
    log_error "Sem permissão de escrita em $ROOT_DIR"
    exit 1
  fi
  rm -f "$ROOT_DIR/.perm_test" 2>/dev/null || true
  log_info "Espaço disponível: ${avail_gb}GB — OK"
}

# -----------------------------
# 5️⃣ Função: sincronizar repositórios Git
# -----------------------------
sync_repo() {
  log_info "Sincronizando repositórios de pacotes..."

  # Pacotes .desc
  if [[ "${AUTO_SYNC_PKG_REPO}" == "yes" ]]; then
    if [[ ! -d "$PKG_REPO_LOCAL/.git" ]]; then
      log_info "Clonando repositório de pacotes: $PKG_REPO_GIT"
      if git clone -b "$PKG_REPO_BRANCH" "$PKG_REPO_GIT" "$PKG_REPO_LOCAL" >>"$LOG_DIR/bootstrap/git.log" 2>&1; then
        log_success "bootstrap" "pkg_repo_clone"
      else
        log_warn "Falha ao clonar repositório de pacotes."
      fi
    else
      log_info "Atualizando repositório de pacotes..."
      if git -C "$PKG_REPO_LOCAL" pull --rebase >>"$LOG_DIR/bootstrap/git.log" 2>&1; then
        log_success "bootstrap" "pkg_repo_update"
      else
        log_warn "Falha ao atualizar repositório de pacotes."
      fi
    fi
  fi

  # Binários (opcional)
  if [[ "${AUTO_SYNC_BIN_REPO}" == "yes" ]]; then
    if [[ ! -d "$BIN_REPO_LOCAL/.git" ]]; then
      log_info "Clonando repositório de binários: $BIN_REPO_GIT"
      if git clone -b "$BIN_REPO_BRANCH" "$BIN_REPO_GIT" "$BIN_REPO_LOCAL" >>"$LOG_DIR/bootstrap/git.log" 2>&1; then
        log_success "bootstrap" "bin_repo_clone"
      else
        log_warn "Falha ao clonar repositório de binários."
      fi
    else
      log_info "Atualizando repositório de binários..."
      if git -C "$BIN_REPO_LOCAL" pull --rebase >>"$LOG_DIR/bootstrap/git.log" 2>&1; then
        log_success "bootstrap" "bin_repo_update"
      else
        log_warn "Falha ao atualizar repositório de binários."
      fi
    fi
  fi
}

# -----------------------------
# 6️⃣ Função: verificar toolchain mínima
# -----------------------------
check_toolchain() {
  log_info "Verificando toolchain mínima..."
  local tools=(gcc make bash tar)
  for t in "${tools[@]}"; do
    if ! command -v "$t" >/dev/null 2>&1; then
      log_error "Ferramenta básica ausente: $t"
      exit 1
    else
      log_info "✓ $t funcional"
    fi
  done
}

# -----------------------------
# 7️⃣ Função: snapshot do ambiente
# -----------------------------
snapshot_env() {
  mkdir -p "$LOG_DIR/bootstrap" 2>/dev/null || true
  local file="$LOG_DIR/bootstrap/env.txt"
  {
    echo "=== SNAPSHOT DO AMBIENTE ==="
    echo "Data: $(date)"
    echo "Usuário: $(whoami)"
    echo "Host: $(hostname)"
    echo "Arquitetura: $(uname -m)"
    echo "CPU Cores: $(nproc)"
    echo "Sistema: $(uname -srv)"
    echo "Espaço livre: $(df -h "$ROOT_DIR" | tail -1)"
    echo "ROOT_DIR: $ROOT_DIR"
    echo "PKG_REPO_LOCAL: $PKG_REPO_LOCAL"
    echo "BIN_REPO_LOCAL: $BIN_REPO_LOCAL"
    echo "---------------------------------------------"
  } >"$file" 2>/dev/null || true
  log_info "Snapshot do ambiente salvo em $file"
}

# -----------------------------
# 8️⃣ Função principal
# -----------------------------
bootstrap_main() {
  log_info "Iniciando sequência de bootstrap..."
  check_tools
  create_structure
  check_space
  sync_repo
  check_toolchain
  snapshot_env
  log_success "bootstrap" "init"
  log_summary
  log_info "Bootstrap concluído com sucesso!"
}

# -----------------------------
# 9️⃣ Execução principal
# -----------------------------
trap 'log_error "Erro inesperado no bootstrap (linha $LINENO)."; log_summary; exit 1' ERR
bootstrap_main
exit 0
