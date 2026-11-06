import * as core from "./stars-core.js";

export interface EcosystemConfig {
  owner: string;
  repos: string[];
}

export interface StarSnapshot {
  date: string;
  total: number;
  repos: Record<string, number>;
}

export interface StarHistory {
  schemaVersion: 1;
  snapshots: StarSnapshot[];
}

export interface StarRepo {
  name: string;
  fullName: string;
  url: string;
  stars: number;
}

export interface StarDelta {
  since: string | null;
  stars: number | null;
}

export interface StarsResponse {
  schemaVersion: 1;
  asOf: string;
  source: "github" | "snapshot";
  stale: boolean;
  total: number;
  repoCount: number;
  repos: StarRepo[];
  history: StarSnapshot[];
  delta: StarDelta;
}

export interface LiveStars {
  ok: true;
  fetchedAt: string;
  total: number;
  repos: StarRepo[];
  snapshot: StarSnapshot;
}

export interface StarsFailure {
  ok: false;
  reason: string;
  missing?: string;
}

export const STAR_SCHEMA_VERSION = core.STAR_SCHEMA_VERSION as 1;
export const STAR_HISTORY_URL = core.STAR_HISTORY_URL as string;

export const utcDate = core.utcDate as (now?: Date) => string;
export const formatUtcDate = core.formatUtcDate as (value: string) => string;
export const formatUtcTimestamp = core.formatUtcTimestamp as (value: string) => string;
export const formatStarCount = core.formatStarCount as (value: number) => string;
export const githubToken = core.githubToken as (env: NodeJS.ProcessEnv | undefined) => string;
export const parseConfig = core.parseConfig as (value: unknown) => EcosystemConfig | null;
export const parseHistory = core.parseHistory as (value: unknown) => StarHistory | null;
export const mergeHistories = core.mergeHistories as (histories: Array<StarHistory | null | undefined>) => StarHistory;
export const upsertSnapshot = core.upsertSnapshot as (history: StarHistory, snapshot: StarSnapshot) => StarHistory;
export const deltaFor = core.deltaFor as (snapshots: StarSnapshot[]) => StarDelta;
export const collectPublicStars = core.collectPublicStars as (config: unknown, orgRepos: readonly { name: string; private: boolean; visibility?: string; stargazers_count: number }[]) =>
  | { ok: true; total: number; repos: StarRepo[]; snapshotRepos: Record<string, number> }
  | StarsFailure;
export const fetchPublicStars = core.fetchPublicStars as (input: {
  config: unknown;
  fetchImpl: typeof fetch;
  token: string;
  now?: Date;
}) => Promise<LiveStars | StarsFailure>;
export const payloadFromHistory = core.payloadFromHistory as (history: unknown, options?: { stale?: boolean; asOf?: string }) => StarsResponse | null;
export const payloadFromLive = core.payloadFromLive as (history: unknown, live: LiveStars | StarsFailure | null) => StarsResponse | null;
export const isStarsResponse = core.isStarsResponse as (value: unknown) => value is StarsResponse;
export const chartPoints = core.chartPoints as (snapshots: StarSnapshot[]) => Array<{ date: string; total: number; x: number; y: number }>;
