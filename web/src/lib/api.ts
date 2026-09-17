import type { Stats, ThreatList } from "./types";
import { SAMPLE_STATS, SAMPLE_THREATS } from "./sample";

const BASE = process.env.NEXT_PUBLIC_API_BASE?.replace(/\/$/, "") ?? "";

export interface ThreatQuery {
  brand?: string;
  confidence?: string;
  min_score?: number;
  limit?: number;
  offset?: number;
}

function qs(params: ThreatQuery): string {
  const p = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== "" && v !== null) p.set(k, String(v));
  });
  const s = p.toString();
  return s ? `?${s}` : "";
}

/** Fetch findings; fall back to bundled sample data if the API is unreachable. */
export async function fetchThreats(
  query: ThreatQuery = {},
): Promise<{ data: ThreatList; live: boolean }> {
  if (BASE) {
    try {
      const res = await fetch(`${BASE}/api/v1/threats${qs(query)}`, {
        cache: "no-store",
      });
      if (res.ok) return { data: await res.json(), live: true };
    } catch {
      /* fall through to sample */
    }
  }
  return {
    data: {
      total: SAMPLE_THREATS.length,
      limit: query.limit ?? 50,
      offset: 0,
      items: SAMPLE_THREATS,
    },
    live: false,
  };
}

export async function fetchStats(): Promise<{ data: Stats; live: boolean }> {
  if (BASE) {
    try {
      const res = await fetch(`${BASE}/api/v1/stats`, { cache: "no-store" });
      if (res.ok) return { data: await res.json(), live: true };
    } catch {
      /* fall through */
    }
  }
  return { data: SAMPLE_STATS, live: false };
}
