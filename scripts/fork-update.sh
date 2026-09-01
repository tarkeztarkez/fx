#!/bin/sh
set -eu

repo=${FX_FORK_REPO:-"$HOME/Projects/fx"}
target=${1:?missing installed fx path}

prompt() {
  printf '\nPaste this prompt into fx:\n\n%s\n' "$1"
}

cd "$repo"

if [ -n "$(git status --porcelain)" ]; then
  echo "The fork has uncommitted changes, so /update stopped without merging."
  prompt "Inspect the uncommitted changes in $repo. Preserve them, commit them if appropriate, then run /update again. Follow AGENTS.md and minimize conflicts with upstream."
  exit 1
fi

echo "Fetching upstream/main..."
git fetch upstream main

if git merge-base --is-ancestor upstream/main HEAD; then
  echo "The fork already contains upstream/main. Rebuilding anyway..."
else
  echo "Merging upstream/main..."
  if ! git merge --no-edit upstream/main; then
    conflicts=$(git diff --name-only --diff-filter=U | tr '\n' ' ')
    echo "The upstream merge has conflicts: ${conflicts:-unknown files}"
    prompt "Resolve the merge conflicts in $repo. Follow AGENTS.md. Preserve the fork's ~/.codex/auth.json support and /update workflow while taking upstream changes wherever possible. Then run zig fmt src/, zig build test, and zig build -Doptimize=ReleaseSafe. Install zig-out/bin/fx over $target atomically, commit the merge, and push main to origin."
    exit 2
  fi
fi

echo "Building the release binary..."
if ! zig build -Doptimize=ReleaseSafe; then
  prompt "Fix the build failure in $repo after the upstream merge. Follow AGENTS.md and keep the repair narrow. Then run zig fmt src/ and zig build -Doptimize=ReleaseSafe. Install zig-out/bin/fx over $target atomically, commit any repair, and push main to origin."
  exit 3
fi

target_dir=$(dirname "$target")
tmp="$target_dir/.fx-update-$$"
trap 'rm -f "$tmp"' EXIT HUP INT TERM
install -m 755 zig-out/bin/fx "$tmp"
mv -f "$tmp" "$target"
trap - EXIT HUP INT TERM

echo "Pushing the synchronized fork..."
git push origin main
echo "fx was rebuilt and installed at $target. Restart fx to run the new binary."
