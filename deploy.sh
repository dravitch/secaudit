#!/usr/bin/env bash
# deploy.sh — Script de déploiement SECAUDIT
#
# Rôle : commit et push automatique depuis l'environnement de développement.
#        Vérifie l'absence de conflits avant de pousser.
#        En cas d'échec rebase : fallback automatique Option B
#        (rescue branch → rebase --abort → reset --hard origin/main → cherry-pick).
# Usage : ./deploy.sh [message de commit optionnel]
#   ./deploy.sh                    # stage+commit+sync+push
#   ./deploy.sh --status           # status + last commits
#   ./deploy.sh --pull             # pull (ff-only)
#   ./deploy.sh -m "msg"           # custom commit message
#   ./deploy.sh --no-push          # commit+sync but do not push
#   ./deploy.sh --push             # push only (after manual resolve)
#   ./deploy.sh --no-verify        # bypass hooks (NOT recommended)
# Auteur : généré par Claude Code (Sprint merge, Avril 2026)

set -euo pipefail

# --- Helpers -------------------------------------------------
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
info() { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }

die() { err "$*"; exit 1; }

# --- Repo root ------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

# --- Args -----------------------------------------------------
CUSTOM_MSG=""
MODE="deploy"
DO_PUSH=1
NO_VERIFY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -m|--message) CUSTOM_MSG="${2:-}"; shift 2 ;;
    --status) MODE="status"; shift ;;
    --pull) MODE="pull"; shift ;;
    --push) MODE="push"; shift ;;
    --no-push) DO_PUSH=0; shift ;;
    --no-verify) NO_VERIFY=1; shift ;;
    *) warn "Unknown arg: $1 (ignored)"; shift ;;
  esac
done

# --- Banner ---------------------------------------------------
info "Repository : $REPO_ROOT"
info "Branch     : $(git branch --show-current 2>/dev/null || echo 'unknown')"
info "User       : $(whoami)"
echo ""

# --- Preconditions -------------------------------------------
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "Not a git repository."

# Ensure we have an origin
git remote get-url origin >/dev/null 2>&1 || die "Remote 'origin' not configured."

# --- Conflict marker check (real markers only) ----------------
# IMPORTANT: anchor patterns to avoid false positives like '======' in banners.
# Detects actual git conflict markers in file content.
check_conflict_markers() {
  if git grep -nE '^(<<<<<<< |=======|>>>>>>> )' -- ':!*.sh' ':!*.md' >/dev/null 2>&1; then
    err "Merge conflict markers found in tracked files."
    git grep -nE '^(<<<<<<< |=======|>>>>>>> )' -- ':!*.sh' ':!*.md' | head -n 80
    return 1
  fi
  return 0
}

# --- Modes ----------------------------------------------------
if [[ "$MODE" == "status" ]]; then
  git status
  echo ""
  git log --oneline --decorate -8 || true
  exit 0
fi

if [[ "$MODE" == "pull" ]]; then
  info "Fetching remote state..."
  git fetch origin
  info "Fast-forward pulling origin/main..."
  git pull --ff-only origin main
  ok "Up to date"
  exit 0
fi

if [[ "$MODE" == "push" ]]; then
  info "Pushing to origin/main..."
  git push origin main
  ok "Pushed"
  exit 0
fi

# --- Deploy flow ---------------------------------------------
info "Fetching remote state..."
git fetch origin

# If no local changes, just fast-forward and exit
LOCAL_CHANGES="$(git status --porcelain)"
if [[ -z "$LOCAL_CHANGES" ]]; then
  info "No local changes – pulling latest (ff-only)..."
  git pull --ff-only origin main
  ok "Repository clean and up to date"
  git log --oneline --decorate -3 || true
  exit 0
fi

info "Local changes:"
git status --short
echo ""

# Stage all
info "Staging changes..."
git add --all

# Abort early if real conflict markers are present
check_conflict_markers || die "Commit aborted (conflict markers)."

# Build commit message if none
if [[ -z "$CUSTOM_MSG" ]]; then
  HOST="$(hostname | tr '[:upper:]' '[:lower:]' || true)"
  TS="$(date '+%Y-%m-%d %H:%M')"
  CUSTOM_MSG="deploy: ${HOST} ${TS}"
fi

info "Commit: $CUSTOM_MSG"

# Commit (optionally bypass hooks)
if [[ "$NO_VERIFY" -eq 1 ]]; then
  warn "Bypassing hooks (--no-verify)."
  git commit -m "$CUSTOM_MSG" --no-verify
else
  git commit -m "$CUSTOM_MSG"
fi

# Rebase onto origin/main (autostash on just in case)
info "Rebasing on origin/main..."
set +e
git pull --rebase --autostash origin main
REB_RC=$?
set -e

if [[ "$REB_RC" -ne 0 ]]; then
  # If conflicts, apply Option B automatically
  warn "Rebase failed. Attempting automatic Option B recovery..."

  # Detect if we are in a rebase
  if git rev-parse --verify REBASE_HEAD >/dev/null 2>&1 || [[ -d .git/rebase-apply || -d .git/rebase-merge ]]; then
    # Create rescue branch at current HEAD (detached or not)
    RESCUE="rescue/rebase-$(date +%Y%m%d-%H%M%S)"
    warn "Creating rescue branch: $RESCUE"
    git branch "$RESCUE" HEAD || true

    warn "Aborting rebase..."
    git rebase --abort || true

    warn "Resetting local main to origin/main..."
    git fetch origin
    git checkout main
    git reset --hard origin/main

    warn "Cherry-picking rescue commit(s) back..."
    # Cherry-pick only the tip commit from rescue; if multiple commits were intended,
    # user can cherry-pick a range manually.
    git cherry-pick "$RESCUE" || {
      err "Cherry-pick failed. Resolve conflicts, then run:"
      err "  git add --all && git cherry-pick --continue"
      err "After that, re-run: ./deploy.sh --push"
      exit 1
    }

    ok "Option B applied successfully (reset + cherry-pick)."
  else
    err "Rebase failed but no rebase state detected. Please inspect manually."
    exit 1
  fi
else
  ok "Rebase clean"
fi

# Final conflict-marker check before push
check_conflict_markers || die "Push aborted (conflict markers)."

# Push
if [[ "$DO_PUSH" -eq 1 ]]; then
  info "Pushing to origin/main..."
  git push origin main
  ok "Deployed successfully"
else
  warn "Skipping push (--no-push)."
fi

echo ""
ok "=== DEPLOY COMPLETE ==="
git log --oneline --decorate -3 || true

[mifdal@mif-dal:~/mif-dal]$ 
