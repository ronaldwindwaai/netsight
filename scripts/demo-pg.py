"""DEMO ONLY: start a throwaway PostgreSQL on loopback for scripts/demo-local.py and keep it running.

Needs the `pgserver` package (embedded PostgreSQL, Python 3.9 to 3.12). No Docker required:

    uv run --python 3.12 --with pgserver python scripts/demo-pg.py

Prints the DSN to export as NETSIGHT_DEMO_PG_DSN, then waits; Ctrl+C stops it. Data lives in
.demo/pg, so it survives restarts; delete that folder for a clean database.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pgserver

PGDATA = (
    Path(
        os.environ.get(
            "NETSIGHT_DEMO_DIR", Path(__file__).resolve().parents[1] / ".demo"
        )
    )
    / "pg"
)


def main() -> int:
    PGDATA.mkdir(parents=True, exist_ok=True)
    server = pgserver.get_server(PGDATA, cleanup_mode="stop")
    print(f"NETSIGHT_DEMO_PG_DSN={server.get_uri()}", flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
