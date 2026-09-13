#!/bin/sh
set -eu

# Keep the database and its sibling lock/restore staging paths on one volume.
# Refuse an old volume layout instead of silently opening an empty child DB.
if [ -f /var/lib/chirondb/catalog.json ] || [ -d /var/lib/chirondb/catalog_wal ] || [ -f /var/lib/chirondb/CURRENT ]; then
    echo "ChironDB found a database at the volume root. The container expects /var/lib/chirondb/data." >&2
    echo "Stop the old server and copy its database into a data/ subdirectory of a new volume; see docs/GETTING_STARTED.md#docker-volume-layout." >&2
    exit 1
fi

exec chirondb "$@"
