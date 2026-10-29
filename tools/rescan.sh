#!/bin/sh
# Rescan every corpus into the database, keeping its symbol surface and
# symbol_intro, and print the checks to read afterwards.
#
# Usage: tools/rescan.sh [db] [corpus-root] [log]

set -e

DB=${1:-data/symuse.db}
CORPUS=${2:-$HOME/corpus}
LOG=${3:-$HOME/symuse-rescan.log}
TOOLS=$(dirname "$0")

sqlite3 "$DB" "DELETE FROM usage; DELETE FROM project;"
: > "$LOG"
for corpus in brew debian openbsd; do
    echo "scanning $corpus" | tee -a "$LOG"
    python3 "$TOOLS/symuse.py" scan "$DB" "$CORPUS/$corpus" \
        --corpus "$corpus" >> "$LOG" 2>&1 || {
        echo "scan of $corpus failed; end of $LOG:" >&2
        tail -15 "$LOG" >&2
        exit 1
    }
done
sqlite3 "$DB" "UPDATE project SET is_binding = 1 WHERE name = 'dlang-openssl'"

echo
echo "== scan summaries"
grep '^scan:' "$LOG"
echo "== projects per corpus"
sqlite3 -box "$DB" "SELECT corpus, count(*) AS projects, sum(is_binding) AS bindings FROM project GROUP BY corpus"
echo "== wolfssl projects (expect none)"
sqlite3 -box "$DB" "SELECT name, corpus FROM project WHERE name LIKE '%wolf%'"
echo "== EVP_aria users"
sqlite3 -box "$DB" "SELECT p.name, u.symbol FROM usage u JOIN project p ON p.id = u.project_id WHERE u.symbol LIKE 'EVP_aria%' ORDER BY 1, 2"
