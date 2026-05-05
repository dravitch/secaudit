#!/usr/bin/env bash
# secaudit-setup.sh
# SecAudit / Mini-Mythos - Script d'installation et de lancement Ubuntu/Debian
#
# Usage :
#   ./secaudit-setup.sh                          # Installation + run complet
#   ./secaudit-setup.sh --skip-install           # Repo deja installe, relancer seulement
#   ./secaudit-setup.sh --no-ai                  # Pipeline sans agents IA (S1+S2+S3)
#   ./secaudit-setup.sh --skip-scan              # Ouvrir le dashboard directement
#   ./secaudit-setup.sh --target monsite.com     # Cible differente de telemo.gov.gn
#   ./secaudit-setup.sh --sprints 1,2,3          # Sprints specifiques
#   ./secaudit-setup.sh --install-dir ~/projets/secaudit  # Dossier personnalise
#
# Prerequis installes automatiquement si absents :
#   git, python3.11+, python3-venv, curl, uv, openai (pip)
#
# Le depot GitHub est public - aucun compte GitHub requis pour cloner.
#
# Rendu executable : chmod +x secaudit-setup.sh

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Valeurs par defaut des parametres
# ─────────────────────────────────────────────────────────────────────────────
SKIP_INSTALL=false
NO_AI=false
SKIP_SCAN=false
TARGET="telemo.gov.gn"
SPRINTS="1,2,3,4,5"
REPO_URL="https://github.com/dravitch/secaudit.git"
INSTALL_DIR="$HOME/SecAudit/secaudit"

# Flags d'etat globaux
ANTHROPIC_OK=false
HF_OK=false
FORCE_NO_AI=false
REPORT_PATH=""
SERVER_PID=""
PYTHON_CMD="python3"
USE_UV=false
VENV_PYTHON=""
SCRIPT_ERRORS=0
START_TIME=$(date +%s)

# ─────────────────────────────────────────────────────────────────────────────
# Parsing des arguments
# ─────────────────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-install)   SKIP_INSTALL=true ;;
        --no-ai)          NO_AI=true ;;
        --skip-scan)      SKIP_SCAN=true ;;
        --target)         TARGET="$2"; shift ;;
        --sprints)        SPRINTS="$2"; shift ;;
        --repo-url)       REPO_URL="$2"; shift ;;
        --install-dir)    INSTALL_DIR="$2"; shift ;;
        -h|--help)
            sed -n '2,14p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *)
            echo "Option inconnue : $1  (utilisez --help)" >&2
            exit 1
            ;;
    esac
    shift
done

# ─────────────────────────────────────────────────────────────────────────────
# Couleurs ANSI
# ─────────────────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    C_CYAN="\033[1;36m"
    C_GREEN="\033[1;32m"
    C_YELLOW="\033[1;33m"
    C_RED="\033[1;31m"
    C_WHITE="\033[0;37m"
    C_RESET="\033[0m"
else
    C_CYAN="" C_GREEN="" C_YELLOW="" C_RED="" C_WHITE="" C_RESET=""
fi

# ─────────────────────────────────────────────────────────────────────────────
# Fonctions d'affichage
# ─────────────────────────────────────────────────────────────────────────────
write_banner() {
    echo ""
    echo -e "${C_CYAN}  ╔══════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_CYAN}  ║        SecAudit / Mini-Mythos  v0.1.0           ║${C_RESET}"
    echo -e "${C_CYAN}  ║   Outil d'audit de securite web automatise       ║${C_RESET}"
    echo -e "${C_CYAN}  ╚══════════════════════════════════════════════════╝${C_RESET}"
    echo -e "${C_WHITE}  Cible    : $TARGET${C_RESET}"
    echo -e "${C_WHITE}  Sprints  : $SPRINTS${C_RESET}"
    echo -e "${C_WHITE}  Dossier  : $INSTALL_DIR${C_RESET}"
    echo ""
}

write_phase() { echo -e "\n${C_CYAN}  ┌─ Phase $1 - $2${C_RESET}"; }
write_step()  { echo -e "${C_WHITE}  │  >> $1${C_RESET}"; }
write_ok()    { echo -e "${C_GREEN}  │  [OK] $1${C_RESET}"; }
write_warn()  { echo -e "${C_YELLOW}  │  [!!] $1${C_RESET}"; }
write_fail()  { echo -e "${C_RED}  │  [FAIL] $1${C_RESET}"; (( SCRIPT_ERRORS++ )) || true; }
write_done()  { echo -e "${C_CYAN}  └─ $1${C_RESET}"; }
write_gap()   { echo -e "  │"; }

# Arret fatal avec message
die() { write_fail "$1"; echo ""; echo -e "${C_RED}  Arret du script. Corriger l'erreur ci-dessus et relancer.${C_RESET}"; exit 1; }

# ─────────────────────────────────────────────────────────────────────────────
# Phase 0 - Prerequis systeme
# ─────────────────────────────────────────────────────────────────────────────
check_prerequisites() {
    write_phase 0 "Verification des prerequis systeme"

    # Systeme d'exploitation
    write_step "Systeme d'exploitation..."
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        write_ok "${PRETTY_NAME:-Linux}"
        # Avertissement si ce n'est pas une distribution Debian/Ubuntu
        if [[ "${ID_LIKE:-$ID}" != *"debian"* && "${ID:-}" != "ubuntu" && "${ID:-}" != "debian" ]]; then
            write_warn "Distribution non-Debian detectee. Le script est optimise pour Ubuntu/Debian."
            write_warn "Les commandes apt peuvent ne pas fonctionner - installation manuelle possible."
        fi
    else
        write_warn "Impossible de determiner la distribution Linux"
    fi

    # Bash version (4+ requis pour associative arrays, etc.)
    write_step "Version Bash..."
    if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
        die "Bash ${BASH_VERSION} detecte. Version 4.0+ requise."
    fi
    write_ok "Bash ${BASH_VERSION}"

    # Espace disque (minimum 1 Go sur la partition d'installation)
    write_step "Espace disque disponible..."
    local mount_point
    mount_point=$(df -P "$HOME" 2>/dev/null | awk 'NR==2{print $6}')
    local free_kb
    free_kb=$(df -P "$HOME" 2>/dev/null | awk 'NR==2{print $4}')
    local free_gb
    free_gb=$(awk "BEGIN{printf \"%.1f\", $free_kb/1048576}")
    if awk "BEGIN{exit ($free_kb < 1048576)}"; then
        die "Espace insuffisant sur $mount_point : ${free_gb} Go disponibles (minimum 1 Go requis)"
    fi
    write_ok "Espace disque : ${free_gb} Go disponibles sur ${mount_point}"

    # Acces Internet - tentative sur trois endpoints
    write_step "Acces Internet..."
    local internet=false
    for check_host in github.com pypi.org router.huggingface.co; do
        if timeout 5 bash -c "echo >/dev/tcp/${check_host}/443" 2>/dev/null; then
            internet=true
            break
        fi
    done
    if [[ "$internet" == false ]]; then
        # Fallback curl si /dev/tcp indisponible
        if curl -s --max-time 5 -o /dev/null https://github.com 2>/dev/null; then
            internet=true
        fi
    fi
    if [[ "$internet" == false ]]; then
        die "Pas d'acces Internet detecte. Verifier la connexion reseau."
    fi
    write_ok "Acces Internet confirme"

    # Acces a la cible
    write_step "Acces a la cible ($TARGET)..."
    local target_host="${TARGET#http://}"
    target_host="${target_host#https://}"
    target_host="${target_host%%/*}"
    if timeout 5 bash -c "echo >/dev/tcp/${target_host}/443" 2>/dev/null; then
        write_ok "Cible $TARGET accessible (port 443)"
    else
        write_warn "Cible $TARGET inaccessible sur port 443 - le scan continuera en mode degrade"
    fi

    write_done "Prerequis systeme OK"
}

# ─────────────────────────────────────────────────────────────────────────────
# Phase 1 - Installation des outils systeme
# ─────────────────────────────────────────────────────────────────────────────
install_system_tools() {
    write_phase 1 "Installation des outils systeme"

    # ── sudo disponible ? ────────────────────────────────────────────────────
    local SUDO=""
    if [[ $EUID -ne 0 ]]; then
        if command -v sudo &>/dev/null; then
            SUDO="sudo"
            write_ok "sudo disponible"
        else
            write_warn "sudo absent et script non lance en root - les installations systeme peuvent echouer"
        fi
    fi

    # ── Git ──────────────────────────────────────────────────────────────────
    write_step "Git..."
    if command -v git &>/dev/null; then
        write_ok "Git deja installe : $(git --version)"
    else
        write_step "Git absent - installation via apt..."
        if $SUDO apt-get update -qq 2>&1 | tail -1 && $SUDO apt-get install -y -qq git 2>&1 | tail -1; then
            write_ok "Git installe : $(git --version)"
        else
            die "Impossible d'installer Git. Lancer : sudo apt-get install git"
        fi
    fi

    # ── curl (requis pour uv) ────────────────────────────────────────────────
    write_step "curl..."
    if command -v curl &>/dev/null; then
        write_ok "curl present"
    else
        write_step "curl absent - installation via apt..."
        $SUDO apt-get install -y -qq curl 2>&1 | tail -1 || write_warn "Installation curl echouee - uv indisponible"
    fi

    # ── Python 3.11+ ─────────────────────────────────────────────────────────
    write_step "Python 3.11+..."
    PYTHON_CMD=""
    for cmd in python3.13 python3.12 python3.11 python3 python; do
        if command -v "$cmd" &>/dev/null; then
            local ver
            ver=$("$cmd" --version 2>&1)
            if [[ "$ver" =~ 3\.([0-9]+) ]] && [[ "${BASH_REMATCH[1]}" -ge 11 ]]; then
                PYTHON_CMD="$cmd"
                write_ok "Python : $ver  ($cmd)"
                break
            fi
        fi
    done

    if [[ -z "$PYTHON_CMD" ]]; then
        write_step "Python 3.11+ absent - installation via apt..."
        # Tenter d'abord deadsnakes PPA pour les versions recentes
        if $SUDO apt-get install -y -qq python3.12 python3.12-venv 2>/dev/null; then
            PYTHON_CMD="python3.12"
            write_ok "Python installe : $(python3.12 --version)"
        elif $SUDO apt-get install -y -qq python3.11 python3.11-venv 2>/dev/null; then
            PYTHON_CMD="python3.11"
            write_ok "Python installe : $(python3.11 --version)"
        else
            write_warn "Tentative via deadsnakes PPA..."
            $SUDO apt-get install -y -qq software-properties-common 2>/dev/null || true
            $SUDO add-apt-repository -y ppa:deadsnakes/ppa 2>/dev/null || true
            $SUDO apt-get update -qq 2>/dev/null || true
            if $SUDO apt-get install -y -qq python3.11 python3.11-venv 2>/dev/null; then
                PYTHON_CMD="python3.11"
                write_ok "Python installe via deadsnakes : $(python3.11 --version)"
            else
                die "Impossible d'installer Python 3.11+. Voir : https://www.python.org/downloads/"
            fi
        fi
    fi

    # S'assurer que python3-venv est present (Ubuntu le separe parfois)
    write_step "Module venv Python..."
    if ! "$PYTHON_CMD" -m venv --help &>/dev/null; then
        local pkg="${PYTHON_CMD}-venv"
        write_step "venv absent - installation de $pkg..."
        $SUDO apt-get install -y -qq "$pkg" 2>/dev/null || \
            $SUDO apt-get install -y -qq python3-venv 2>/dev/null || \
            write_warn "venv non installe - la creation du virtualenv peut echouer"
    else
        write_ok "Module venv disponible"
    fi

    # ── uv ───────────────────────────────────────────────────────────────────
    write_step "uv (gestionnaire de packages Python)..."
    if command -v uv &>/dev/null; then
        write_ok "uv deja installe : $(uv --version)"
        USE_UV=true
    else
        write_step "Installation de uv (methode officielle)..."
        if command -v curl &>/dev/null; then
            if curl -LsSf https://astral.sh/uv/install.sh | sh 2>/dev/null; then
                # Recharger le PATH (uv s'installe dans ~/.cargo/bin ou ~/.local/bin)
                export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
                if command -v uv &>/dev/null; then
                    write_ok "uv installe : $(uv --version)"
                    USE_UV=true
                else
                    write_warn "uv installe mais non trouve dans PATH - ajout de ~/.local/bin et ~/.cargo/bin"
                    write_warn "Relancer le terminal ou executer : source ~/.bashrc"
                    write_warn "Fallback sur pip pour cette session"
                    USE_UV=false
                fi
            else
                write_warn "Installation uv echouee - fallback sur pip"
                USE_UV=false
            fi
        else
            write_warn "curl absent - impossible d'installer uv - fallback sur pip"
            USE_UV=false
        fi
    fi

    write_done "Outils systeme OK"
}

# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 - Depot GitHub (clone ou synchronisation)
# ─────────────────────────────────────────────────────────────────────────────
sync_repository() {
    write_phase 2 "Depot GitHub"

    if [[ -d "$INSTALL_DIR/.git" ]]; then
        # Depot existant - synchroniser
        write_step "Depot existant detecte dans $INSTALL_DIR - synchronisation..."
        pushd "$INSTALL_DIR" > /dev/null
        if git fetch origin 2>/dev/null && git pull origin main 2>/dev/null; then
            local last_commit
            last_commit=$(git log -1 --pretty=format:"%h %s (%cr)" 2>/dev/null || echo "inconnu")
            write_ok "Synchronise - dernier commit : $last_commit"
        else
            write_warn "Synchronisation git echouee (mode hors ligne ?) - continuation avec version locale"
        fi
        popd > /dev/null
    else
        # Premier clone
        write_step "Clonage depuis $REPO_URL..."
        write_step "(depot public - aucun compte GitHub requis)"
        local parent_dir
        parent_dir=$(dirname "$INSTALL_DIR")
        mkdir -p "$parent_dir"
        if git clone --quiet "$REPO_URL" "$INSTALL_DIR" 2>/dev/null; then
            pushd "$INSTALL_DIR" > /dev/null
            local last_commit
            last_commit=$(git log -1 --pretty=format:"%h %s" 2>/dev/null || echo "inconnu")
            write_ok "Clone reussi : $last_commit"
            popd > /dev/null
        else
            die "Clone echoue. Verifier que le depot $REPO_URL est public et accessible."
        fi
    fi

    pushd "$INSTALL_DIR" > /dev/null

    # Gerer le fichier .env
    # Cas special: .env present dans le dossier parent (migration depuis ancienne structure)
    local parent_env
    parent_env="$(dirname "$INSTALL_DIR")/.env"
    if [[ -f "$parent_env" && ! -f ".env" ]]; then
        cp "$parent_env" ".env"
        write_ok ".env copie depuis le dossier parent"
    fi

    if [[ ! -f ".env" ]]; then
        if [[ -f ".env.example" ]]; then
            write_step "Creation de .env depuis .env.example..."
            cp ".env.example" ".env"
            write_warn ".env cree - EDITER le fichier pour ajouter les cles API :"
            write_warn "  ANTHROPIC_API_KEY=sk-ant-..."
            write_warn "  HF_TOKEN=hf_..."
            echo ""
            echo -e "${C_YELLOW}  Ouvrir .env dans un editeur ? [O/n] ${C_RESET}\c"
            read -r resp
            if [[ "$resp" != "n" && "$resp" != "N" ]]; then
                # Choisir un editeur disponible
                local editor=""
                for ed in "$EDITOR" nano vim vi; do
                    if [[ -n "$ed" ]] && command -v "$ed" &>/dev/null; then
                        editor="$ed"
                        break
                    fi
                done
                if [[ -n "$editor" ]]; then
                    "$editor" "$INSTALL_DIR/.env"
                else
                    write_warn "Aucun editeur trouve. Editer manuellement : $INSTALL_DIR/.env"
                fi
            fi
        else
            write_warn ".env absent et pas de .env.example - le pipeline IA ne pourra pas demarrer"
            write_warn "Creer $INSTALL_DIR/.env avec ANTHROPIC_API_KEY et HF_TOKEN"
        fi
    else
        write_ok ".env present"
    fi

    popd > /dev/null
    write_done "Depot pret dans $INSTALL_DIR"
}

# ─────────────────────────────────────────────────────────────────────────────
# Phase 3 - Environnement Python (venv + dependances)
# ─────────────────────────────────────────────────────────────────────────────
install_python_env() {
    write_phase 3 "Environnement Python"
    pushd "$INSTALL_DIR" > /dev/null

    local venv_path=".venv"
    VENV_PYTHON="$INSTALL_DIR/$venv_path/bin/python"
    local venv_pip="$INSTALL_DIR/$venv_path/bin/pip"

    # Creer le venv
    if [[ ! -f "$VENV_PYTHON" ]]; then
        write_step "Creation du venv Python..."
        if [[ "$USE_UV" == true ]]; then
            uv venv "$venv_path" 2>/dev/null || "$PYTHON_CMD" -m venv "$venv_path"
        else
            "$PYTHON_CMD" -m venv "$venv_path"
        fi
        write_ok "Venv cree dans $venv_path"
    else
        write_ok "Venv existant reutilise"
    fi

    # Installer les dependances
    if [[ -f "requirements.txt" ]]; then
        write_step "Installation des dependances (requirements.txt)..."
        local install_ok=true
        if [[ "$USE_UV" == true ]]; then
            if ! uv pip install -r requirements.txt --python "$VENV_PYTHON" 2>&1 | tail -3; then
                install_ok=false
            fi
        else
            if ! "$venv_pip" install -r requirements.txt --quiet 2>&1 | tail -3; then
                install_ok=false
            fi
        fi
        if [[ "$install_ok" == true ]]; then
            write_ok "Dependances installees"
        else
            write_fail "Installation dependances echouee - verifier requirements.txt"
        fi
    else
        write_warn "requirements.txt absent dans $INSTALL_DIR"
        write_warn "Le depot semble incomplet. Tentative de re-clone..."
        # Supprimer et re-cloner
        rm -rf "$INSTALL_DIR/.git"
        if git clone --quiet "$REPO_URL" "$INSTALL_DIR" 2>/dev/null; then
            if [[ -f "requirements.txt" ]]; then
                write_ok "Re-clone reussi - requirements.txt retrouve"
                if [[ "$USE_UV" == true ]]; then
                    uv pip install -r requirements.txt --python "$VENV_PYTHON" --quiet 2>/dev/null || true
                else
                    "$venv_pip" install -r requirements.txt --quiet 2>/dev/null || true
                fi
                write_ok "Dependances installees"
            else
                write_fail "requirements.txt toujours absent apres re-clone"
            fi
        else
            write_fail "Re-clone echoue"
        fi
    fi

    # Verifier openai
    write_step "Verification paquet openai..."
    if ! "$VENV_PYTHON" -c "import openai" 2>/dev/null; then
        write_step "Installation de openai..."
        if [[ "$USE_UV" == true ]]; then
            uv pip install openai --python "$VENV_PYTHON" --quiet 2>/dev/null || true
        else
            "$venv_pip" install openai --quiet 2>/dev/null || true
        fi
        if "$VENV_PYTHON" -c "import openai" 2>/dev/null; then
            write_ok "openai installe"
        else
            write_warn "openai non installe - le CriticAgent HuggingFace sera inoperant"
        fi
    else
        write_ok "openai present dans le venv"
    fi

    # Verifier anthropic
    write_step "Verification paquet anthropic..."
    if "$VENV_PYTHON" -c "import anthropic" 2>/dev/null; then
        write_ok "anthropic present dans le venv"
    else
        write_warn "anthropic non installe - verifier requirements.txt"
    fi

    popd > /dev/null
    write_done "Environnement Python pret"
}

# ─────────────────────────────────────────────────────────────────────────────
# Phase 4 - Test des cles API
# ─────────────────────────────────────────────────────────────────────────────
test_api_keys() {
    write_phase 4 "Test des cles API"
    pushd "$INSTALL_DIR" > /dev/null

    if [[ ! -f "test_api_keys.py" ]]; then
        write_warn "test_api_keys.py absent - test des cles ignore"
        popd > /dev/null
        return
    fi

    # Charger les variables du .env dans le shell courant
    if [[ -f ".env" ]]; then
        # Lecture prudente : ignorer les lignes commentees et vides
        while IFS='=' read -r key value; do
            [[ "$key" =~ ^[[:space:]]*# ]] && continue
            [[ -z "$key" ]] && continue
            key="${key// /}"
            value="${value%\"}"
            value="${value#\"}"
            value="${value%\'}"
            value="${value#\'}"
            export "$key=$value"
        done < <(grep -E '^[^#][A-Za-z_][A-Za-z0-9_]*=' .env 2>/dev/null || true)
        write_ok ".env charge dans le processus"
    fi

    # Test Anthropic
    write_step "Test Anthropic API (AnalystAgent)..."
    if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
        write_warn "ANTHROPIC_API_KEY absent du .env - test Anthropic ignore"
        ANTHROPIC_OK=false
    else
        local result
        if result=$("$VENV_PYTHON" test_api_keys.py --anthropic-only 2>&1); then
            write_ok "Anthropic API : cle valide"
            ANTHROPIC_OK=true
        else
            local reset_line
            reset_line=$(echo "$result" | grep -iE "reset|budget|epuise|credit" | head -1 || true)
            if [[ -n "$reset_line" ]]; then
                write_warn "Anthropic : $reset_line"
            else
                write_warn "Anthropic API : cle invalide ou solde insuffisant"
                echo "$result" | tail -3 | while read -r line; do
                    write_warn "    $line"
                done
            fi
            ANTHROPIC_OK=false
        fi
    fi

    # Test HuggingFace
    write_step "Test HuggingFace Router (CriticAgent DeepSeek)..."
    if [[ -z "${HF_TOKEN:-}" ]]; then
        write_warn "HF_TOKEN absent du .env - test HuggingFace ignore"
        HF_OK=false
    else
        local result
        if result=$("$VENV_PYTHON" test_api_keys.py --hf-only 2>&1); then
            write_ok "HuggingFace Router : token valide, DeepSeek V4 Pro accessible"
            HF_OK=true
        else
            local reset_line
            reset_line=$(echo "$result" | grep -iE "reset|budget|quota|epuise" | head -1 || true)
            if [[ -n "$reset_line" ]]; then
                write_warn "HuggingFace : $reset_line"
            else
                write_warn "HuggingFace : token invalide ou quota depasse"
                echo "$result" | tail -3 | while read -r line; do
                    write_warn "    $line"
                done
            fi
            HF_OK=false
        fi
    fi

    # Ajuster le mode si IA indisponible
    if [[ "$ANTHROPIC_OK" == false || "$HF_OK" == false ]]; then
        write_warn "Une ou les deux cles IA sont invalides - le pipeline sera lance en mode --no-ai"
        FORCE_NO_AI=true
    else
        FORCE_NO_AI=false
    fi

    popd > /dev/null
    write_done "Test cles API termine"
}

# ─────────────────────────────────────────────────────────────────────────────
# Phase 5 - Tests unitaires pytest
# ─────────────────────────────────────────────────────────────────────────────
run_tests() {
    write_phase 5 "Tests unitaires (pytest)"
    pushd "$INSTALL_DIR" > /dev/null

    local pytest_bin="$INSTALL_DIR/.venv/bin/pytest"
    if [[ ! -f "$pytest_bin" ]]; then
        write_warn "pytest absent dans le venv - tests ignores"
        popd > /dev/null
        return
    fi

    write_step "Lancement de pytest..."
    local output
    output=$("$pytest_bin" tests/ -v --tb=short 2>&1 || true)
    local summary_line
    summary_line=$(echo "$output" | grep -E "passed|failed|error" | tail -1 || true)

    if [[ -n "$summary_line" ]]; then
        local passed failed errors skipped total_fail
        passed=$(echo "$summary_line"  | grep -oP '\d+(?= passed)'  || echo "0")
        failed=$(echo "$summary_line"  | grep -oP '\d+(?= failed)'  || echo "0")
        errors=$(echo "$summary_line"  | grep -oP '\d+(?= error)'   || echo "0")
        skipped=$(echo "$summary_line" | grep -oP '\d+(?= skipped)' || echo "0")
        total_fail=$(( failed + errors ))

        if [[ "$total_fail" -eq 0 ]]; then
            local skip_msg=""
            [[ "$skipped" -gt 0 ]] && skip_msg=", $skipped skip"
            write_ok "pytest : $passed PASS${skip_msg}"
        else
            write_warn "pytest : $total_fail FAIL / $passed PASS"
            echo "$output" | grep -E "FAILED|ERROR" | while read -r line; do
                write_warn "    $line"
            done
            write_warn "Des tests echouent mais le pipeline peut quand meme tourner"
        fi
    else
        write_warn "Aucun test collecte - verifier le dossier tests/"
    fi

    popd > /dev/null
    write_done "Tests unitaires termines"
}

# ─────────────────────────────────────────────────────────────────────────────
# Phase 6 - Pipeline de scan
# ─────────────────────────────────────────────────────────────────────────────
run_pipeline() {
    write_phase 6 "Pipeline de scan"
    pushd "$INSTALL_DIR" > /dev/null

    if [[ ! -f "main.py" ]]; then
        write_warn "main.py absent - pipeline ignore"
        popd > /dev/null
        return
    fi

    # Construire les arguments
    local args=("main.py" "--target" "$TARGET" "--sprints" "$SPRINTS")

    if [[ "$NO_AI" == true || "$FORCE_NO_AI" == true ]]; then
        args+=("--no-ai")
        write_step "Mode --no-ai active (sprints S1+S2+S3 uniquement)"
    else
        write_step "Mode complet (sprints $SPRINTS avec agents IA)"
    fi

    write_step "Commande : $VENV_PYTHON ${args[*]}"
    write_gap

    # Charger les variables du .env dans l'environnement du sous-processus
    local env_exports=()
    if [[ -f ".env" ]]; then
        while IFS='=' read -r key value; do
            [[ "$key" =~ ^[[:space:]]*# ]] && continue
            [[ -z "$key" ]] && continue
            key="${key// /}"
            value="${value%\"}"
            value="${value#\"}"
            value="${value%\'}"
            value="${value#\'}"
            env_exports+=("$key=$value")
        done < <(grep -E '^[^#][A-Za-z_][A-Za-z0-9_]*=' .env 2>/dev/null || true)
    fi

    # Lancer le pipeline en streaming (affichage temps reel)
    local exit_code=0
    env "${env_exports[@]}" "$VENV_PYTHON" "${args[@]}" 2>&1 | while IFS= read -r line; do
        if echo "$line" | grep -qiE "FAIL|ERROR|Traceback"; then
            echo -e "${C_RED}  │  $line${C_RESET}"
        elif echo "$line" | grep -qiE "CONFIRMED|CONFIRMED="; then
            echo -e "${C_GREEN}  │  $line${C_RESET}"
        elif echo "$line" | grep -qiE "NUANCED|WARNING|warn"; then
            echo -e "${C_YELLOW}  │  $line${C_RESET}"
        else
            echo -e "${C_WHITE}  │  $line${C_RESET}"
        fi
    done || exit_code=$?

    if [[ "$exit_code" -ne 0 ]]; then
        write_fail "Pipeline termine avec exit code $exit_code"
    else
        write_ok "Pipeline termine avec succes"
    fi

    # Lister les fichiers de resultat produits
    write_gap
    write_step "Fichiers de resultats produits :"
    local results_dir="$INSTALL_DIR/results"
    if [[ -d "$results_dir" ]]; then
        local found=false
        while IFS= read -r f; do
            if [[ -n "$f" ]]; then
                local size_kb
                size_kb=$(du -k "$f" | cut -f1)
                write_ok "$(basename "$f")  (${size_kb} Ko)"
                found=true
            fi
        done < <(find "$results_dir" -name "*.json" -newer "$0" -type f 2>/dev/null | sort)
        [[ "$found" == false ]] && write_warn "Aucun fichier JSON produit dans results/"
    else
        write_warn "Dossier results/ absent"
    fi

    # Chercher le rapport MD
    local report
    report=$(find "${results_dir:-$INSTALL_DIR/results}" -name "*.md" -newer "$0" -type f 2>/dev/null | sort -t_ -k1 | tail -1 || true)
    if [[ -n "$report" ]]; then
        write_ok "Rapport genere : $report"
        REPORT_PATH="$report"
    fi

    popd > /dev/null
    write_done "Pipeline termine"
}

# ─────────────────────────────────────────────────────────────────────────────
# Phase 7 - Ouverture du dashboard
# ─────────────────────────────────────────────────────────────────────────────
open_dashboard() {
    write_phase 7 "Dashboard SecAudit"
    pushd "$INSTALL_DIR" > /dev/null

    local dash_path="$INSTALL_DIR/ui/dashboard.html"
    if [[ ! -f "$dash_path" ]]; then
        write_warn "Dashboard absent : $dash_path"
        popd > /dev/null
        return
    fi

    # Choisir le port (8080 par defaut, fallback 8081)
    local port=8080
    if ss -tlnp 2>/dev/null | grep -q ":${port} " || \
       netstat -tlnp 2>/dev/null | grep -q ":${port} "; then
        port=8081
        write_warn "Port 8080 occupe - utilisation du port $port"
    fi

    local dash_url="http://localhost:${port}/dashboard.html"
    write_step "Demarrage du serveur local sur le port $port..."

    # Lancer le serveur Python en arriere-plan
    "$VENV_PYTHON" -m http.server "$port" \
        --directory "$INSTALL_DIR/ui" \
        --bind 127.0.0.1 \
        > /tmp/secaudit-server.log 2>&1 &
    SERVER_PID=$!
    sleep 2

    # Verifier que le serveur repond
    if curl -s --max-time 5 -o /dev/null "http://localhost:${port}" 2>/dev/null; then
        write_ok "Serveur local demarre : $dash_url"
    else
        write_warn "Serveur peut-etre pas encore pret - ouverture quand meme"
    fi

    # Ouvrir le navigateur par defaut (selon l'environnement)
    write_step "Ouverture du navigateur..."
    local browser_opened=false
    for opener in xdg-open gnome-open sensible-browser; do
        if command -v "$opener" &>/dev/null; then
            "$opener" "$dash_url" &>/dev/null &
            write_ok "Dashboard ouvert : $dash_url  (via $opener)"
            browser_opened=true
            break
        fi
    done
    if [[ "$browser_opened" == false ]]; then
        write_warn "Impossible d'ouvrir le navigateur automatiquement."
        write_warn "Ouvrir manuellement : $dash_url"
    fi

    # Indiquer le dernier fichier JSON disponible
    local latest_json
    latest_json=$(find "$INSTALL_DIR/results" -name "s5_critic*.json" -type f 2>/dev/null | sort | tail -1 || true)
    if [[ -n "$latest_json" ]]; then
        write_gap
        write_step "Pour charger les resultats dans le dashboard :"
        write_step "  1. Cliquer sur le bouton 'Charger JSON'"
        write_step "  2. Selectionner : $latest_json"
    fi

    if [[ -n "$REPORT_PATH" ]]; then
        write_gap
        write_step "Rapport Markdown disponible :"
        write_step "  $REPORT_PATH"
        echo ""
        echo -e "${C_YELLOW}  Ouvrir le rapport dans un editeur ? [O/n] ${C_RESET}\c"
        read -r resp
        if [[ "$resp" != "n" && "$resp" != "N" ]]; then
            local editor=""
            for ed in "${EDITOR:-}" xdg-open nano vim vi; do
                if [[ -n "$ed" ]] && command -v "$ed" &>/dev/null; then
                    editor="$ed"
                    break
                fi
            done
            if [[ -n "$editor" ]]; then
                "$editor" "$REPORT_PATH" &>/dev/null &
            else
                write_warn "Aucun editeur trouve. Ouvrir manuellement : $REPORT_PATH"
            fi
        fi
    fi

    popd > /dev/null
    write_done "Dashboard lance"
}

# ─────────────────────────────────────────────────────────────────────────────
# Resume final
# ─────────────────────────────────────────────────────────────────────────────
write_final_summary() {
    local end_time
    end_time=$(date +%s)
    local elapsed=$(( end_time - START_TIME ))
    local duration_str
    duration_str=$(printf "%dm%02ds" $(( elapsed / 60 )) $(( elapsed % 60 )))

    echo ""
    echo -e "${C_CYAN}  ╔══════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_CYAN}  ║              Resume d'execution                  ║${C_RESET}"
    echo -e "${C_CYAN}  ╠══════════════════════════════════════════════════╣${C_RESET}"
    printf "${C_WHITE}  ║  Duree totale  : %-30s  ║${C_RESET}\n"  "$duration_str"
    printf "${C_WHITE}  ║  Cible         : %-30s  ║${C_RESET}\n"  "$TARGET"

    if [[ "$ANTHROPIC_OK" == true ]]; then
        printf "${C_GREEN}  ║  Anthropic API : %-30s  ║${C_RESET}\n" "OK"
    else
        printf "${C_YELLOW}  ║  Anthropic API : %-30s  ║${C_RESET}\n" "indisponible"
    fi

    if [[ "$HF_OK" == true ]]; then
        printf "${C_GREEN}  ║  HF Router     : %-30s  ║${C_RESET}\n" "OK"
    else
        printf "${C_YELLOW}  ║  HF Router     : %-30s  ║${C_RESET}\n" "indisponible"
    fi

    echo -e "  ║                                                  ║"
    if [[ "$SCRIPT_ERRORS" -eq 0 ]]; then
        echo -e "${C_GREEN}  ║  [OK] Environnement pret et pipeline lance       ║${C_RESET}"
    else
        printf "${C_RED}  ║  [%d erreur(s)] - voir details ci-dessus         ║${C_RESET}\n" "$SCRIPT_ERRORS"
    fi
    echo -e "${C_CYAN}  ╚══════════════════════════════════════════════════╝${C_RESET}"
    echo ""

    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        echo -e "${C_CYAN}  Serveur local actif sur http://localhost:8080/dashboard.html${C_RESET}"
        echo -e "${C_WHITE}  Appuyer sur Entree pour arreter le serveur et quitter...${C_RESET}"
        read -r
        kill "$SERVER_PID" 2>/dev/null || true
        echo -e "  Serveur arrete."
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Recuperation manuelle (si dependances manquantes apres le script)
# ─────────────────────────────────────────────────────────────────────────────
show_manual_recovery() {
    if "$VENV_PYTHON" -c "import typer" 2>/dev/null; then
        return
    fi

    echo ""
    echo -e "${C_YELLOW}  ================================================================${C_RESET}"
    echo -e "${C_YELLOW}  ATTENTION : dependances Python manquantes.${C_RESET}"
    echo -e "${C_YELLOW}  Copier-coller ces commandes dans le terminal :${C_RESET}"
    echo ""
    echo -e "${C_CYAN}    cd \"$INSTALL_DIR\"${C_RESET}"
    echo -e "${C_CYAN}    source .venv/bin/activate${C_RESET}"
    echo -e "${C_CYAN}    pip install -r requirements.txt${C_RESET}"
    echo ""
    echo -e "${C_YELLOW}  Puis lancer le pipeline :${C_RESET}"
    echo -e "${C_CYAN}    python main.py --target $TARGET --sprints $SPRINTS${C_RESET}"
    echo -e "${C_YELLOW}  ================================================================${C_RESET}"
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# Nettoyage a la sortie (Ctrl+C, etc.)
# ─────────────────────────────────────────────────────────────────────────────
cleanup() {
    echo ""
    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        write_step "Arret du serveur HTTP local (PID $SERVER_PID)..."
        kill "$SERVER_PID" 2>/dev/null || true
        write_ok "Serveur arrete"
    fi
}
trap cleanup EXIT INT TERM

# =============================================================================
# POINT D'ENTREE PRINCIPAL
# =============================================================================

write_banner

check_prerequisites

if [[ "$SKIP_INSTALL" == false ]]; then
    install_system_tools
    sync_repository
    install_python_env
fi

test_api_keys

if [[ "$SKIP_SCAN" == false ]]; then
    run_tests
    run_pipeline
fi

show_manual_recovery
open_dashboard
write_final_summary