"""HTTP + WebSocket API.

Kept intentionally thin: every route either delegates to the deterministic
`ScenarioEngine` / `AgentOrchestrator`, or reads from the shared in-memory
`RunStore`. No agent or provisioning logic lives here.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect

from app.agents.llm_client import AnthropicLLMClient, LLMClient, ScriptedLLMClient
from app.agents.orchestrator import AgentOrchestrator
from app.config import settings
from app.models.schemas import Difficulty, LaunchRunRequest, RunStatus, Scenario
from app.agents.scenario_generator import generate_scenario
from app.state import run_store, scenario_store

router = APIRouter()
_executor = ThreadPoolExecutor(max_workers=4)


def _build_llm_client() -> LLMClient:
    if settings.use_scripted_llm:
        # Deterministic stub: reports the goal unreachable after a no-op
        # recon step. Good enough to exercise the API/orchestration wiring
        # without an API key; swap USE_SCRIPTED_LLM off to run for real.
        return ScriptedLLMClient(
            script=[
                ("Reconnaissance first.", "scan_ports", {"host": "web"}),
                ("No further scripted steps configured for this demo run.", None, None),
            ]
        )
    return AnthropicLLMClient(model=settings.anthropic_model, api_key=settings.anthropic_api_key)


_orchestrator: AgentOrchestrator | None = None


def get_orchestrator() -> AgentOrchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = AgentOrchestrator(llm=_build_llm_client())
    return _orchestrator


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.post("/scenarios/generate", response_model=Scenario)
def generate(difficulty: Difficulty) -> Scenario:
    scenario = generate_scenario(difficulty)
    scenario_store.add(scenario)
    return scenario


@router.get("/scenarios/{scenario_id}", response_model=Scenario)
def get_scenario(scenario_id: str) -> Scenario:
    scenario = scenario_store.get(scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")
    return scenario


@router.post("/runs")
async def launch_run(request: LaunchRunRequest) -> dict[str, str]:
    scenario = scenario_store.get(request.scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")

    orchestrator = get_orchestrator()
    loop = asyncio.get_running_loop()

    # run_id is only known once the orchestrator generates it inside
    # run_red_team, so pre-register under a client-visible pending id and
    # relabel once provisioning starts.
    pending_id = f"pending-{id(request)}"
    record = run_store.create(pending_id, loop)
    record.status = RunStatus.PENDING

    def on_step(step):
        run_store.push_step(pending_id, step)

    def work() -> None:
        report, _provisioned = orchestrator.run_red_team(scenario, request, on_step=on_step)
        # The orchestrator mints its own internal run_id for container/network
        # naming; relabel the report with the client-visible id it was
        # launched under so GET /runs/{run_id} is self-consistent.
        report = report.model_copy(update={"run_id": pending_id})
        run_store.set_report(pending_id, report)

    loop.run_in_executor(_executor, work)
    return {"run_id": pending_id}


@router.get("/runs/{run_id}")
def get_run(run_id: str) -> dict:
    record = run_store.get(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return {
        "run_id": run_id,
        "status": record.status,
        "report": record.report,
        "steps_so_far": len(record.trajectory_so_far),
    }


@router.websocket("/runs/{run_id}/live")
async def run_live(websocket: WebSocket, run_id: str) -> None:
    await websocket.accept()
    record = run_store.get(run_id)
    if record is None:
        await websocket.close(code=4404)
        return

    for step in record.trajectory_so_far:
        await websocket.send_json(step.model_dump(mode="json"))

    queue = run_store.subscribe(run_id)
    if queue is None:
        await websocket.close(code=4404)
        return

    try:
        while True:
            done = record.report is not None
            try:
                step = await asyncio.wait_for(queue.get(), timeout=1.0)
                await websocket.send_json(step.model_dump(mode="json"))
            except asyncio.TimeoutError:
                if done:
                    await websocket.send_json({"event": "run_complete", "status": record.status})
                    break
    except WebSocketDisconnect:
        pass
    finally:
        run_store.unsubscribe(run_id, queue)
