#!/usr/bin/env bash
# Runs "$@" against a THROWAWAY Secret Service: private $HOME, private session
# bus, private gnome-keyring daemon.
#
# Tests that LOCK the collection have to run in here. Locking the default
# collection is a global act — doing it on a developer's real session would lock
# their login keyring out from under every other app, and in CI it would leave
# the keyring locked for whatever test ran next. Isolation confines it.
#
# Exits 77 (ctest's SKIP_RETURN_CODE) when the tooling isn't installed, so a
# machine without gnome-keyring skips rather than fails.
set -euo pipefail

for tool in dbus-run-session gnome-keyring-daemon gdbus; do
  command -v "$tool" >/dev/null || { echo "SKIP: $tool not installed"; exit 77; }
done

here=$(cd "$(dirname "$0")" && pwd)

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/run"   # before dbus-run-session, or dbus warns it can't use XDG_RUNTIME_DIR

# Under the asan preset this test trips a leak inside libsecret itself: it
# allocates a prompt object to unlock the collection and leaks it when no
# prompter can be reached — which is precisely what a headless locked keyring
# means. Suppressed narrowly by symbol; see tests/lsan.supp.
lsan="suppressions=$here/lsan.supp"
[ -n "${LSAN_OPTIONS:-}" ] && lsan="$LSAN_OPTIONS:$lsan"

# KEYWARD_ISOLATED_KEYRING is the test's proof it is somewhere disposable; it
# refuses to lock anything without it. env -i so no ambient DBUS_SESSION_BUS_
# ADDRESS or XDG_DATA_HOME can leak the real session in.
exec env -i \
  HOME="$tmp" \
  XDG_DATA_HOME="$tmp/.local/share" \
  XDG_RUNTIME_DIR="$tmp/run" \
  PATH="$PATH" \
  KEYWARD_ISOLATED_KEYRING=1 \
  LSAN_OPTIONS="$lsan" \
  UBSAN_OPTIONS="${UBSAN_OPTIONS:-}" \
  ASAN_OPTIONS="${ASAN_OPTIONS:-}" \
  dbus-run-session -- bash -c '
    mkdir -p "$XDG_RUNTIME_DIR"
    # Non-empty password on purpose: with an empty one gnome-keyring will not
    # create the login keyring itself and defers to the GTK prompter, which
    # cannot run headless. Same trap as the CI job.
    echo -n "keyward-locktest" | gnome-keyring-daemon --unlock --components=secrets --daemonize
    exec "$@"' _ "$@"
