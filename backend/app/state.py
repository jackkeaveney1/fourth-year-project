"""In-memory run registry shared by the API layer.

A real deployment would back this with Redis (as noted in the project
doc's tech list) so multiple API workers can share state and the event
stream survives a restart. For the scaffold, an in-process store keeps
the moving parts easy to reason about; `RunStore` is the one seam to
swap out for a Redis-backed implementation later.
"""

from __future__ import annotations

import asyncio
import threading
from dataclasses import dataclass, field

from app.models.schemas import RunReport, RunStatus, Scenario, TrajectoryStep


@dataclass
class RunRecord:
    run_id: str
    status: RunStatus = RunStatus.PENDING
    report: RunReport | None = None
    trajectory_so_far: list[TrajectoryStep] = field(default_factory=list)
    subscribers: list[asyncio.Queue] = field(default_factory=list)
    loop: asyncio.AbstractEventLoop | None = None


class RunStore:
    def __init__(self) -> None:
        self._runs: dict[str, RunRecord] = {}
        self._lock = threading.Lock()

    def create(self, run_id: str, loop: asyncio.AbstractEventLoop) -> RunRecord:
        with self._lock:
            record = RunRecord(run_id=run_id, loop=loop)
            self._runs[run_id] = record
            return record

    def get(self, run_id: str) -> RunRecord | None:
        with self._lock:
            return self._runs.get(run_id)

    def set_status(self, run_id: str, status: RunStatus) -> None:
        with self._lock:
            if run_id in self._runs:
                self._runs[run_id].status = status

    def set_report(self, run_id: str, report: RunReport) -> None:
        with self._lock:
            record = self._runs.get(run_id)
            if record is not None:
                record.report = report
                record.status = report.status

    def push_step(self, run_id: str, step: TrajectoryStep) -> None:
        """Called from the worker thread running the agent loop."""
        with self._lock:
            record = self._runs.get(run_id)
            if record is None:
                return
            record.trajectory_so_far.append(step)
            loop = record.loop
            subscribers = list(record.subscribers)

        if loop is None:
            return
        for queue in subscribers:
            loop.call_soon_threadsafe(queue.put_nowait, step)

    def subscribe(self, run_id: str) -> asyncio.Queue | None:
        with self._lock:
            record = self._runs.get(run_id)
            if record is None:
                return None
            queue: asyncio.Queue = asyncio.Queue()
            record.subscribers.append(queue)
            return queue

    def unsubscribe(self, run_id: str, queue: asyncio.Queue) -> None:
        with self._lock:
            record = self._runs.get(run_id)
            if record is not None and queue in record.subscribers:
                record.subscribers.remove(queue)


class ScenarioStore:
    """Holds generated scenarios so a run request can look one up by id."""

    def __init__(self) -> None:
        self._scenarios: dict[str, Scenario] = {}
        self._lock = threading.Lock()

    def add(self, scenario: Scenario) -> None:
        with self._lock:
            self._scenarios[scenario.id] = scenario

    def get(self, scenario_id: str) -> Scenario | None:
        with self._lock:
            return self._scenarios.get(scenario_id)


run_store = RunStore()
scenario_store = ScenarioStore()
