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
}

export interface RunStatusResponse {
  run_id: string;
  status: RunStatus;
  report: RunReport | null;
  steps_so_far: number;
}
