"""HTTP + WebSocket API.

Kept intentionally thin: every route either delegates to the deterministic
`ScenarioEngine` / `AgentOrchestrator`, or reads from the shared in-memory
`RunStore`. No agent or provisioning logic lives here.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor

import docker
from docker.errors import DockerException
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
from app.models.schemas import (
    CustomScenarioRequest,
    Difficulty,
    ImportedScenarioRequest,
    LaunchRunRequest,
    LLMProvider,
    LLMSelection,
    RunStatus,
    Scenario,
    Vulnerability,
)
from app.agents.scenario_generator import (
    CustomScenarioError,
    CustomServiceInput,
    VULNERABILITY_CATALOG,
    build_custom_scenario,
    build_imported_scenario,
    generate_scenario,
)
from app.scenario_engine.image_builder import ImageBuildError, build_image_from_context
from app.state import run_store, scenario_store

router = APIRouter()
_executor = ThreadPoolExecutor(max_workers=4)
BLUE_TEAM_MAX_STEPS = 8

_docker_client: docker.DockerClient | None = None


def get_docker_client() -> docker.DockerClient:
    global _docker_client
    if _docker_client is None:
        _docker_client = docker.from_env()
    return _docker_client


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


_DEFAULT_MODELS = {
    LLMProvider.GROQ: lambda: settings.groq_model,
    LLMProvider.ANTHROPIC: lambda: settings.anthropic_model,
    LLMProvider.GEMINI: lambda: settings.gemini_model,
    LLMProvider.AIONLABS: lambda: settings.aionlabs_model,
}
_DEFAULT_KEYS = {
    LLMProvider.GROQ: lambda: settings.groq_api_key,
    LLMProvider.ANTHROPIC: lambda: settings.anthropic_api_key,
    LLMProvider.GEMINI: lambda: settings.gemini_api_key,
    LLMProvider.AIONLABS: lambda: settings.aionlabs_api_key,
}
_CLIENT_CLASSES = {
    LLMProvider.GROQ: GroqLLMClient,
    LLMProvider.ANTHROPIC: AnthropicLLMClient,
    LLMProvider.GEMINI: GeminiLLMClient,
    LLMProvider.AIONLABS: AionLabsLLMClient,
}


def _build_client_from_selection(selection: LLMSelection) -> LLMClient:
    """Builds a client for an explicit per-run provider choice.

    The caller's own `api_key`, if given, is used only to construct this
    one client (never written to disk/settings) — falls back to the
    server-configured key for that provider when omitted.
    """
    api_key = (selection.api_key or "").strip() or None
    if api_key is None:
        api_key = _DEFAULT_KEYS[selection.provider]()
    if api_key is None:
        raise HTTPException(
            status_code=400,
            detail=(
                f"No API key available for provider '{selection.provider.value}' — "
                "enter one in Advanced Settings or configure it on the server."
            ),
        )
    model = selection.model or _DEFAULT_MODELS[selection.provider]()
    return _CLIENT_CLASSES[selection.provider](model=model, api_key=api_key)


def _resolve_red_llm(request: LaunchRunRequest) -> LLMClient:
    if request.red_llm is not None and not settings.use_scripted_llm:
        return _build_client_from_selection(request.red_llm)
    return _build_llm_client()


def _resolve_blue_llm(request: LaunchRunRequest) -> LLMClient | None:
    if request.blue_llm is not None and not settings.use_scripted_llm:
        return _build_client_from_selection(request.blue_llm)
    return _build_blue_llm_client()


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


@router.get("/vulnerabilities", response_model=list[Vulnerability])
def list_vulnerabilities() -> list[Vulnerability]:
    """The catalog a custom scenario's services can be built from."""
    return list(VULNERABILITY_CATALOG.values())


@router.post("/scenarios/custom", response_model=Scenario)
def create_custom_scenario(request: CustomScenarioRequest) -> Scenario:
    try:
        scenario = build_custom_scenario(
            title=request.title,
            objective=request.objective,
            services=[
                CustomServiceInput(
                    name=s.name,
                    role=s.role,
                    vulnerability_ids=s.vulnerability_ids,
                    exposed_to=s.exposed_to,
                )
                for s in request.services
            ],
        )
    except CustomScenarioError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    scenario_store.add(scenario)
    return scenario


@router.post("/scenarios/imported", response_model=Scenario)
def create_imported_scenario(request: ImportedScenarioRequest) -> Scenario:
    """Build an image from the user's own build context and wrap it as a scenario.

    The built image becomes the `web` entry point, so the per-run SUCCESS_MARKER
    is injected into it and goal-checking/scoring run through the same path as
    the built-in targets (see build_imported_scenario). A bad path or failing
    `docker build` surfaces as a 400 with the build-log tail, not a 500.
    """
    try:
        image = build_image_from_context(request.build_context, get_docker_client())
    except ImageBuildError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    scenario = build_imported_scenario(
        title=request.title,
        objective=request.objective,
        image=image,
        app_port=request.app_port,
        include_db=request.include_db,
    )
    scenario_store.add(scenario)
    return scenario


@router.post("/runs")
async def launch_run(request: LaunchRunRequest) -> dict[str, str]:
    scenario = scenario_store.get(request.scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")

    # Built fresh per request (not cached) since red_llm/blue_llm can select a
    # different provider/model/key on every launch.
    red_llm = _resolve_red_llm(request)
    blue_llm = _resolve_blue_llm(request)
    orchestrator = AgentOrchestrator(llm=red_llm, docker_client=get_docker_client(), blue_llm=blue_llm)
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

    def on_provisioned(provisioned) -> None:
        # "attacker" first — it's the agents' operating box, always present —
        # then the scenario's own services in topology order.
        run_store.set_infra(
            pending_id,
            internal_run_id=provisioned.run_id,
            compose_project=provisioned.project_name,
            subnet_base=provisioned.subnet_base,
            expected_services=["attacker", *(s.name for s in scenario.services)],
        )

    def work() -> None:
        run_store.set_phase(pending_id, "provisioning")
        report, _provisioned = orchestrator.run_red_team(
            scenario,
            request,
            on_step=on_step,
            on_phase=on_phase,
            on_provisioned=on_provisioned,
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


@router.get("/runs/{run_id}/infrastructure")
def get_infrastructure(run_id: str) -> dict:
    """Live state of the Docker containers + isolated network for a run.

    Read-only: queries Docker by the `cyber_range.run` label the compose
    template stamps on every container. Returns a row per *expected* service
    so a container that hasn't come up yet shows as "pending" rather than
    being omitted. Once a run is torn down the containers are gone, so this
    goes back to all-pending/empty — that's expected, the final topology
    lives in the run report.
    """
    record = run_store.get(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Run not found")

    if record.internal_run_id is None:
        # Provisioning hasn't started yet (or this run never provisions).
        return {"provisioned": False, "network": None, "containers": []}

    subnet = f"{record.subnet_base}.0/24" if record.subnet_base else None
    try:
        containers = get_docker_client().containers.list(
            all=True, filters={"label": f"cyber_range.run={record.internal_run_id}"}
        )
    except DockerException:
        containers = []

    found: dict[str, dict] = {}
    network_name: str | None = None
    for container in containers:
        service = container.labels.get("com.docker.compose.service") or container.name.removeprefix(
            f"{record.internal_run_id}-"
        )
        state = container.attrs.get("State", {})
        health = (state.get("Health") or {}).get("Status")
        ip: str | None = None
        networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})
        for net_name, meta in networks.items():
            network_name = net_name
            ip = meta.get("IPAddress") or (meta.get("IPAMConfig") or {}).get("IPv4Address")
        found[service] = {
            "service": service,
            "container_name": container.name,
            "image": container.attrs.get("Config", {}).get("Image"),
            "status": container.status,
            "health": health,
            "ip": ip or None,
        }

    def pending(service: str) -> dict:
        return {
            "service": service,
            "container_name": f"{record.internal_run_id}-{service}",
            "image": None,
            "status": "pending",
            "health": None,
            "ip": None,
        }

    ordered = [found.get(service, pending(service)) for service in record.expected_services]
    # Surface anything running under this run's label that we didn't expect.
    ordered.extend(info for service, info in found.items() if service not in record.expected_services)

    return {
        "provisioned": True,
        "network": {"name": network_name, "subnet": subnet, "internal": True},
        "containers": ordered,
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
