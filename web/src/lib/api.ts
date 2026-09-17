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

// --- Posture ---------------------------------------------------------------
import type { Posture, PostureList } from "./types";
import { SAMPLE_POSTURE } from "./postureSample";

export interface PostureQuery {
  category?: string;
  grade?: string;
  brand?: string;
}

export async function fetchPosture(
  query: PostureQuery = {},
): Promise<{ data: PostureList; live: boolean }> {
  if (BASE) {
    try {
      const p = new URLSearchParams();
      Object.entries(query).forEach(([k, v]) => {
        if (v) p.set(k, String(v));
      });
      const q = p.toString() ? `?${p.toString()}` : "";
      const res = await fetch(`${BASE}/api/v1/posture${q}`, {
        cache: "no-store",
      });
      if (res.ok) return { data: await res.json(), live: true };
    } catch {
      /* fall through */
    }
  }
  return { data: SAMPLE_POSTURE, live: false };
}

/** Does this posture record have an enforced/valid DMARC policy? */
export function hasDmarc(p: Posture): boolean {
  return p.findings.some(
    (f) => f.check.toUpperCase() === "DMARC" && f.status === "ok",
  );
}

/** Record a community "this is a scam" report (increments the counter). */
export async function reportThreat(id: number): Promise<number | null> {
  if (!BASE) return null; // sample mode: no backend to record against
  try {
    const res = await fetch(`${BASE}/api/v1/threats/${id}/report`, {
      method: "POST",
    });
    if (res.ok) {
      const data = await res.json();
      return data.report_count as number;
    }
  } catch {
    /* ignore */
  }
  return null;
}

export interface SubmitResult {
  matched: boolean;
  message: string;
  domain?: string;
  brand_name?: string;
  risk_score?: number;
  confidence?: string;
  report_count?: number;
}

/** Submit a scam URL (e.g. from an SMS). Adds it to the feed if it matches. */
export async function submitScam(url: string): Promise<SubmitResult> {
  if (!BASE) {
    return {
      matched: false,
      message: "Submissions need the live backend (sample mode is read-only).",
    };
  }
  try {
    const res = await fetch(`${BASE}/api/v1/submit`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    if (res.ok) return await res.json();
    return { matched: false, message: `Submission failed (${res.status}).` };
  } catch {
    return { matched: false, message: "Could not reach the server." };
  }
}
