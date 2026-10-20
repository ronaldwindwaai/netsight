"""The kill switch (Step 12): one flag that stops remote actions.

Engaged, no request can be created, approved or executed. Reads, rejection and cancellation still
work, so people can see what is waiting and withdraw it. Two sources:

* ``NETSIGHT_ACTIONS_KILL_SWITCH`` (``1|true|yes|on``) set in the environment: engaged from start-up
  and **not releasable through the API**, so a compromised session cannot undo an operator's stop;
* a runtime switch an administrator can engage and release (release needs step-up at the route).

The state is per process, whichever action store is in use (the PostgreSQL store does not share it
either). Engaging the runtime switch on one worker does not engage the others: the environment variable
plus a restart is the hard stop across workers. Persisting the flag (a one-row table read inside each
decision transaction) is a documented follow-up, not built. This is a limitation, not hidden.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from datetime import datetime
from typing import Final

from netsight_api.actions.errors import KillSwitchLocked
from netsight_api.schemas_actions import KillSwitchStatus

ENV_VAR: Final = "NETSIGHT_ACTIONS_KILL_SWITCH"
_TRUE: Final = frozenset({"1", "true", "yes", "on"})
_FALSE: Final = frozenset({"0", "false", "no", "off", ""})


def env_engaged(env: Mapping[str, str]) -> bool:
    raw = env.get(ENV_VAR, "").strip().lower()
    # An unreadable value must not silently mean "off" for a safety switch: fail closed.
    return raw not in _FALSE


class KillSwitch:
    def __init__(self, env_engaged: bool = False) -> None:
        self._env = env_engaged
        self._lock = threading.Lock()
        self._runtime_since: datetime | None = None

    @property
    def engaged(self) -> bool:
        with self._lock:
            return self._env or self._runtime_since is not None

    def engage(self, now: datetime) -> None:
        with self._lock:
            if self._runtime_since is None:
                self._runtime_since = now

    def release(self) -> None:
        with self._lock:
            if self._env:
                raise KillSwitchLocked
            self._runtime_since = None

    def status(self) -> KillSwitchStatus:
        with self._lock:
            if self._env:
                return KillSwitchStatus(engaged=True, source="environment", since=None)
            if self._runtime_since is not None:
                return KillSwitchStatus(engaged=True, source="runtime", since=self._runtime_since)
            return KillSwitchStatus(engaged=False, source="none", since=None)
