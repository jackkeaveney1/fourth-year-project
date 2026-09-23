export type Difficulty = "easy" | "medium" | "hard" | "expert";

export type RunStatus =
  | "pending"
  | "provisioning"
  | "running"
  | "succeeded"
  | "failed"
  | "killed"
  | "torn_down";

export interface Vulnerability {
  id: string;
  name: string;
  description: string;
  cwe: string | null;
  remediation: string[];
}

export interface ScenarioService {
  name: string;
  image: string;
  internal_hostname: string;
  vulnerabilities: Vulnerability[];
  exposed_to: string[];
}

export interface Scenario {
  id: string;
  title: string;
  difficulty: Difficulty;
  objective: string;
  services: ScenarioService[];
  compose_path: string;
}

export interface ToolCall {
  name: string;
  arguments: Record<string, unknown>;
}

export interface TrajectoryStep {
  step: number;
  role: "red" | "blue" | "generator";
  thought: string;
  tool_call: ToolCall | null;
  observation: string | null;
  timestamp: string;
}

export interface ScoreEntry {
  label: string;
  points: number;
  achieved: boolean;
}

export interface ScoreCard {
  entries: ScoreEntry[];
  total_points: number;
  max_points: number;
}

export type AttackOutcome = "succeeded" | "failed" | "blocked";

export interface AttackAttempt {
  step: number;
  action: string;
  target: string | null;
  outcome: AttackOutcome;
  detail: string;
}

export interface AttackReport {
  breached: boolean;
  summary: string;
  attempts: AttackAttempt[];
  successful_attempts: AttackAttempt[];
  failed_attempts: AttackAttempt[];
  blocked_attempts: AttackAttempt[];
  recommendations: string[];
}

export interface RunReport {
  run_id: string;
  scenario_id: string;
  status: RunStatus;
  objective: string;
  goal_achieved: boolean;
  trajectory: TrajectoryStep[];
  vulnerabilities_exploited: string[];
  privilege_escalation: boolean;
  detected_by_blue_team: boolean;
  time_to_compromise_seconds: number | null;
  agent_step_count: number;
  started_at: string;
  ended_at: string | null;
  scorecard: ScoreCard | null;
  blue_team_trajectory: TrajectoryStep[];
  blue_team_summary: string | null;
  blue_team_error: string | null;
  attack_report: AttackReport | null;
}

export type RunPhase = "pending" | "provisioning" | "running" | "assessing" | "done";

export interface RunStatusResponse {
  run_id: string;
  status: RunStatus;
  phase: RunPhase;
  max_steps: number;
  report: RunReport | null;
  steps_so_far: number;
}

export interface PhaseEvent {
  event: "phase";
  phase: RunPhase;
  max_steps?: number;
}

export interface RunCompleteEvent {
  event: "run_complete";
  status: RunStatus;
}

export type LiveMessage = TrajectoryStep | PhaseEvent | RunCompleteEvent;
