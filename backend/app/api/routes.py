"""HTTP + WebSocket API.

Kept intentionally thin: every route either delegates to the deterministic
`ScenarioEngine` / `AgentOrchestrator`, or reads from the shared in-memory
`RunStore`. No agent or provisioning logic lives here.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect

from app.agents.llm_client import (
    AionLabsLLMClient,
    AnthropicLLMClient,
    GeminiLLMClient,
    GroqLLMClient,
    LLMClient,
    ScriptedLLMClient,
)
from app.agents.orchestrator import AgentOrchestrator
from app.config import settings
from app.models.schemas import Difficulty, LaunchRunRequest, RunStatus, Scenario
from app.agents.scenario_generator import generate_scenario
from app.state import run_store, scenario_store

router = APIRouter()
_executor = ThreadPoolExecutor(max_workers=4)
BLUE_TEAM_MAX_STEPS = 8


def _build_llm_client() -> LLMClient:
    if settings.use_scripted_llm:
        # Deterministic stub: reports the goal unreachable after a no-op
        # recon step. Good enough to exercise the API/orchestration wiring
        # without an API key; set GROQ_API_KEY or ANTHROPIC_API_KEY to run
        # for real.
        return ScriptedLLMClient(
            script=[
                ("Reconnaissance first.", "scan_ports", {"host": "web"}),
                ("No further scripted steps configured for this demo run.", None, None),
            ]
        )
    if settings.aionlabs_api_key is not None:
        return AionLabsLLMClient(model=settings.aionlabs_model, api_key=settings.aionlabs_api_key)
    if settings.groq_api_key is not None:
        return GroqLLMClient(model=settings.groq_model, api_key=settings.groq_api_key)
    if settings.gemini_api_key is not None:
        # Tried and confirmed working for tool-calling, but Gemini's own
        # safety training refuses the "attack a target" framing this agent
        # needs outright (verified via a live run — it declines before
        # making a single tool call), so it's a fallback, not the default.
        return GeminiLLMClient(model=settings.gemini_model, api_key=settings.gemini_api_key)
    return AnthropicLLMClient(model=settings.anthropic_model, api_key=settings.anthropic_api_key)


def _build_blue_llm_client() -> LLMClient | None:
    # Groq enforces its rate limits per-model, so giving the blue-team agent
    # a different model than the red team keeps its assessment from being
    # starved by whatever daily budget the attack run already burned through.
    if not settings.use_scripted_llm and settings.groq_api_key is not None:
        return GroqLLMClient(model=settings.groq_blue_model, api_key=settings.groq_api_key)
    return None


_orchestrator: AgentOrchestrator | None = None


def get_orchestrator() -> AgentOrchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = AgentOrchestrator(
            llm=_build_llm_client(), blue_llm=_build_blue_llm_client()
        )
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
    record.max_steps = request.max_steps

    first_step_seen = False

    def on_step(step):
        nonlocal first_step_seen
        if not first_step_seen:
            first_step_seen = True
            run_store.set_phase(pending_id, "running")
        run_store.push_step(pending_id, step)

    def on_phase(phase: str) -> None:
        max_steps = BLUE_TEAM_MAX_STEPS if phase == "assessing" else None
        run_store.set_phase(pending_id, phase, max_steps=max_steps)

    def work() -> None:
        run_store.set_phase(pending_id, "provisioning")
        report, _provisioned = orchestrator.run_red_team(
            scenario,
            request,
            on_step=on_step,
            on_phase=on_phase,
            blue_max_steps=BLUE_TEAM_MAX_STEPS,
        )
        # The orchestrator mints its own internal run_id for container/network
        # naming; relabel the report with the client-visible id it was
        # launched under so GET /runs/{run_id} is self-consistent.
        report = report.model_copy(update={"run_id": pending_id})
        run_store.set_report(pending_id, report)
        run_store.set_phase(pending_id, "done")

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
        "phase": record.phase,
        "max_steps": record.max_steps,
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

    await websocket.send_json({"event": "phase", "phase": record.phase, "max_steps": record.max_steps})
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
                item = await asyncio.wait_for(queue.get(), timeout=1.0)
                payload = item if isinstance(item, dict) else item.model_dump(mode="json")
                await websocket.send_json(payload)
            except asyncio.TimeoutError:
                if done:
                    await websocket.send_json({"event": "run_complete", "status": record.status})
                    break
    except WebSocketDisconnect:
        pass
    finally:
        run_store.unsubscribe(run_id, queue)
