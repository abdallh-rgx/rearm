#!/bin/bash
# rearm auto-sync: commit + push everything, never lose work.
# Runs in background loop every 90 seconds, and one-shot via `sync now`.
set -u
cd /home/z/rearm
export GIT_AUTHOR_NAME="rearm-autosync"
export GIT_AUTHOR_EMAIL="autosync@rearm.local"
export GIT_COMMITTER_NAME="rearm-autosync"
export GIT_COMMITTER_EMAIL="autosync@rearm.local"

do_sync() {
  rm -f .git/index.lock 2>/dev/null || true
  local tag="wip: auto-sync checkpoint $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  git add -A >/dev/null 2>&1
  if ! git diff --cached --quiet 2>/dev/null || [ "$(git ls-files --others --exclude-standard | head -1)" != "" ]; then
    git commit -m "$tag" >/dev/null 2>&1
    for i in 1 2 3; do
      if git push origin HEAD:main >/dev/null 2>&1; then
        echo "[$(date -u +%H:%M:%S)] pushed: $tag"
        return 0
      fi
      sleep 3
    done
    echo "[$(date -u +%H:%M:%S)] PUSH FAILED: $tag"
    return 1
  fi
  echo "[$(date -u +%H:%M:%S)] clean"
}

case "${1:-loop}" in
  now) do_sync ;;
  loop)
    echo "auto-sync loop started (pid $$)"
    while true; do
      do_sync
      sleep 90
    done ;;
esac
