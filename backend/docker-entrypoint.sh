#!/bin/sh
# Prepares the database, then runs the command (the server, by default).
set -eu

alembic upgrade head

# LOG_ANALYZER_LOAD: log files to load before the server starts, separated by
# spaces. Loading a file again adds nothing, so this is safe on every start.
if [ -n "${LOG_ANALYZER_LOAD:-}" ]; then
    # shellcheck disable=SC2086  # the list is meant to be split into words
    python -m app.load ${LOG_ANALYZER_LOAD_YEAR:+--year "$LOG_ANALYZER_LOAD_YEAR"} $LOG_ANALYZER_LOAD \
        || echo "docker-entrypoint: not every file in LOG_ANALYZER_LOAD could be loaded" >&2
fi

exec "$@"
