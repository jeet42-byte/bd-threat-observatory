"use client";

import { useEffect, useMemo, useState } from "react";
import {
  Copy,
  Check,
  X,
  ExternalLink,
  ShieldCheck,
  ShieldX,
  Siren,
} from "lucide-react";
import type { IntelItem, Posture, Stats, Threat } from "@/lib/types";
import {
  fetchPosture,
  fetchStats,
  fetchThreats,
  hasDmarc,
  reportThreat,
} from "@/lib/api";
import { abuseReport } from "@/lib/abuse";
import { AUTO_REPORT_THRESHOLD, reportTargets } from "@/lib/report";
import { Nav } from "@/components/Nav";
import { RiskBadge } from "@/components/RiskBadge";
import { StatCard } from "@/components/StatCard";

const CONFIDENCES = ["all", "critical", "high", "medium", "low"] as const;
const REGISTERED = [
  { value: "all", label: "Any age" },
  { value: "30", label: "Last 30 days" },
  { value: "90", label: "Last 90 days" },
  { value: "established", label: "Established (>1yr)" },
] as const;

/** Best available "went live" date for a finding. */
function regDate(t: Threat): Date {
  return new Date(t.domain_created_at ?? t.issued_at ?? t.first_seen_at);
}
function ageDays(t: Threat): number {
  return (Date.now() - regDate(t).getTime()) / 86400000;
}

export default function ThreatsPage() {
  const [threats, setThreats] = useState<Threat[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [live, setLive] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(true);

  const [brand, setBrand] = useState<string>("");
  const [confidence, setConfidence] = useState<string>("all");
  const [minScore, setMinScore] = useState<number>(0);
  const [selected, setSelected] = useState<Threat | null>(null);
  const [registered, setRegistered] = useState<string>("all");
  const [sortBy, setSortBy] = useState<string>("risk");
  const [brandPosture, setBrandPosture] = useState<Record<string, Posture>>({});

  useEffect(() => {
    let active = true;
    setLoading(true);
    Promise.all([
      fetchThreats({
        brand: brand || undefined,
        confidence: confidence === "all" ? undefined : confidence,
        min_score: minScore || undefined,
        limit: 100,
      }),
      fetchStats(),
      fetchPosture(),
    ]).then(([t, s, p]) => {
      if (!active) return;
      setThreats(t.data.items);
      setLive(t.live && s.live);
      setStats(s.data);
      const map: Record<string, Posture> = {};
      p.data.items.forEach((row) => {
        if (row.brand_slug) map[row.brand_slug] = row;
      });
      setBrandPosture(map);
      setLoading(false);
    });
    return () => {
      active = false;
    };
  }, [brand, confidence, minScore]);

  // Client-side filter + sort (also drives sample-mode).
  const visible = useMemo(() => {
    const list = threats.filter((t) => {
      if (brand && t.brand_slug !== brand) return false;
      if (confidence !== "all" && t.confidence !== confidence) return false;
      if (t.risk_score < minScore) return false;
      if (registered === "30" && ageDays(t) > 30) return false;
      if (registered === "90" && ageDays(t) > 90) return false;
      if (registered === "established" && ageDays(t) < 365) return false;
      return true;
    });
    if (sortBy === "newest") {
      list.sort((a, b) => regDate(b).getTime() - regDate(a).getTime());
    } else {
      list.sort((a, b) => b.risk_score - a.risk_score);
    }
    return list;
  }, [threats, brand, confidence, minScore, registered, sortBy]);

  const newCount = useMemo(
    () => threats.filter((t) => ageDays(t) <= 30).length,
    [threats],
  );

  const brandOptions = useMemo(() => {
    const m = new Map<string, string>();
    threats.forEach((t) => m.set(t.brand_slug, t.brand_name));
    return Array.from(m.entries());
  }, [threats]);

  const criticalCount =
    stats?.by_confidence.find((c) => c.confidence === "critical")?.count ?? 0;

  return (
    <main className="mx-auto max-w-6xl px-4 py-8">
      <Nav live={live} />
      <p className="mt-4 text-sm text-slate-400">
        Live phishing/scam domains impersonating monitored BD brands, from
        Certificate Transparency.
      </p>

      <section className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <StatCard label="Findings" value={stats?.total_findings ?? "—"} />
        <StatCard
          label="Critical"
          value={criticalCount}
          accent="text-red-300"
        />
        <StatCard label="Domains seen" value={stats?.total_domains ?? "—"} />
        <StatCard
          label="New (<30d)"
          value={newCount}
          accent="text-sky-300"
        />
      </section>

      <section className="mt-6 flex flex-wrap items-end gap-3 rounded-xl border border-edge bg-panel p-4">
        <Field label="Brand">
          <select
            value={brand}
            onChange={(e) => setBrand(e.target.value)}
            className="input"
          >
            <option value="">All brands</option>
            {brandOptions.map(([slug, name]) => (
              <option key={slug} value={slug}>
                {name}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Confidence">
          <select
            value={confidence}
            onChange={(e) => setConfidence(e.target.value)}
            className="input"
          >
            {CONFIDENCES.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </Field>
        <Field label={`Min score: ${minScore}`}>
          <input
            type="range"
            min={0}
            max={100}
            step={5}
            value={minScore}
            onChange={(e) => setMinScore(Number(e.target.value))}
            className="w-40 accent-sky-500"
          />
        </Field>
        <Field label="Registered">
          <select
            value={registered}
            onChange={(e) => setRegistered(e.target.value)}
            className="input"
          >
            {REGISTERED.map((r) => (
              <option key={r.value} value={r.value}>
                {r.label}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Sort by">
          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
            className="input"
          >
            <option value="risk">Risk</option>
            <option value="newest">Newest</option>
          </select>
        </Field>
        <div className="ml-auto text-sm text-slate-400">
          {loading ? "Loading…" : `${visible.length} shown`}
        </div>
      </section>

      <section className="mt-4 overflow-x-auto rounded-xl border border-edge">
        <table className="w-full min-w-[980px] text-sm">
          <thead className="bg-panel text-left text-xs uppercase tracking-wide text-slate-400">
            <tr>
              <th className="px-4 py-3">Domain</th>
              <th className="px-4 py-3">Brand</th>
              <th className="px-4 py-3">Risk</th>
              <th className="px-4 py-3">Signals</th>
              <th className="px-4 py-3" title="Domain registrar and registration date (RDAP)">
                Registrar
              </th>
              <th className="px-4 py-3" title="What open threat-intel sources report">
                Open-source intel
              </th>
              <th className="px-4 py-3" title="Registration / cert-issuance date">
                Registered
              </th>
              <th className="px-4 py-3" title="Community scam reports">Reports</th>
              <th className="px-4 py-3">Brand defense</th>
              <th className="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-edge">
            {visible.map((t) => (
              <tr key={t.id} className="bg-base/40 hover:bg-panel/60">
                <td className="px-4 py-3 font-mono text-sky-200">
                  <div className="flex items-center gap-2">
                    <span>{t.domain}</span>
                    {ageDays(t) <= 30 && (
                      <span className="rounded bg-sky-500/20 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-sky-300 ring-1 ring-sky-500/40">
                        New
                      </span>
                    )}
                  </div>
                </td>
                <td className="px-4 py-3">
                  <div>{t.brand_name}</div>
                  <div className="text-xs text-slate-500">{t.category}</div>
                </td>
                <td className="px-4 py-3">
                  <RiskBadge confidence={t.confidence} score={t.risk_score} />
                </td>
                <td className="px-4 py-3">
                  <div className="flex max-w-sm flex-wrap gap-1">
                    {t.reasons.slice(0, 4).map((r, i) => (
                      <span
                        key={i}
                        className="rounded bg-slate-700/40 px-1.5 py-0.5 text-[11px] text-slate-300"
                      >
                        {r}
                      </span>
                    ))}
                    {t.reasons.length > 4 && (
                      <span className="text-[11px] text-slate-500">
                        +{t.reasons.length - 4}
                      </span>
                    )}
                  </div>
                </td>
                <td className="px-4 py-3">
                  <Registrar threat={t} />
                </td>
                <td className="px-4 py-3">
                  <IntelCell items={t.intel} />
                </td>
                <td className="px-4 py-3 text-slate-400">
                  {(t.domain_created_at
                    ? new Date(t.domain_created_at)
                    : t.issued_at
                      ? new Date(t.issued_at)
                      : new Date(t.first_seen_at)
                  )
                    .toISOString()
                    .slice(0, 10)}
                </td>
                <td className="px-4 py-3">
                  {t.report_count > 0 ? (
                    <span className="inline-flex items-center gap-1 rounded-full bg-red-500/15 px-2 py-0.5 text-xs font-semibold text-red-300 ring-1 ring-red-500/30">
                      {t.report_count}
                    </span>
                  ) : (
                    <span className="text-xs text-slate-600">0</span>
                  )}
                </td>
                <td className="px-4 py-3">
                  <BrandDefense posture={brandPosture[t.brand_slug]} />
                </td>
                <td className="px-4 py-3">
                  <button
                    onClick={() => setSelected(t)}
                    className="rounded border border-edge px-2 py-1 text-xs text-slate-300 hover:border-sky-500 hover:text-sky-300"
                  >
                    Abuse report
                  </button>
                </td>
              </tr>
            ))}
            {!loading && visible.length === 0 && (
              <tr>
                <td
                  colSpan={10}
                  className="px-4 py-10 text-center text-slate-500"
                >
                  No findings match these filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </section>

      <p className="mt-6 text-xs text-slate-500">
        Passive OSINT from Certificate Transparency. Domains shown are candidate
        impersonations flagged by heuristics; they are not a determination of
        wrongdoing. Verify before acting.
      </p>

      {selected && (
        <AbusePanel threat={selected} onClose={() => setSelected(null)} />
      )}

      <style jsx global>{`
        .input {
          background: #0b0f1a;
          border: 1px solid #243049;
          border-radius: 0.5rem;
          padding: 0.4rem 0.6rem;
          color: #e6edf6;
          font-size: 0.875rem;
        }
      `}</style>
    </main>
  );
}

function Registrar({ threat }: { threat: Threat }) {
  if (!threat.registrar && !threat.registrant_org) {
    return <span className="text-xs text-slate-600">—</span>;
  }
  return (
    <div className="text-xs">
      <div className="text-slate-300">{threat.registrar ?? "unknown registrar"}</div>
      {threat.registrant_org && (
        <div className="text-slate-500">{threat.registrant_org}</div>
      )}
      {threat.registrant_country && (
        <div className="text-slate-500">{threat.registrant_country}</div>
      )}
    </div>
  );
}

const INTEL_STYLE: Record<string, string> = {
  malicious: "bg-red-500/15 text-red-300 ring-red-500/30",
  listed: "bg-yellow-500/15 text-yellow-200 ring-yellow-500/30",
  clean: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30",
  unknown: "bg-slate-600/20 text-slate-400 ring-slate-600/30",
};

function IntelCell({ items }: { items: IntelItem[] }) {
  const real = items.filter((i) => i.status !== "unknown");
  if (real.length === 0) {
    return <span className="text-xs text-slate-600">not listed</span>;
  }
  return (
    <div className="flex max-w-[240px] flex-wrap gap-1">
      {real.map((i, idx) => (
        <a
          key={idx}
          href={i.url}
          target="_blank"
          rel="noreferrer"
          title={`${i.source}: ${i.detail}`}
          className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-medium ring-1 ${INTEL_STYLE[i.status] ?? INTEL_STYLE.unknown}`}
        >
          {i.source}: {i.status}
        </a>
      ))}
    </div>
  );
}

function BrandDefense({ posture }: { posture?: Posture }) {
  if (!posture) {
    return <span className="text-xs text-slate-600">—</span>;
  }
  const protectedByDmarc = hasDmarc(posture);
  return (
    <span
      className={`inline-flex items-center gap-1 text-xs ${
        protectedByDmarc ? "text-emerald-300" : "text-red-300"
      }`}
      title={
        protectedByDmarc
          ? `${posture.target} enforces DMARC (grade ${posture.grade})`
          : `${posture.target} has no enforced DMARC — spoofing not blunted (grade ${posture.grade})`
      }
    >
      {protectedByDmarc ? <ShieldCheck size={13} /> : <ShieldX size={13} />}
      {protectedByDmarc ? "DMARC" : "no DMARC"} · {posture.grade}
    </span>
  );
}

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <label className="flex flex-col gap-1 text-xs text-slate-400">
      {label}
      {children}
    </label>
  );
}

function AbusePanel({
  threat,
  onClose,
}: {
  threat: Threat;
  onClose: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const [reportCount, setReportCount] = useState(threat.report_count);
  const report = abuseReport(threat);
  const eligible = threat.risk_score >= AUTO_REPORT_THRESHOLD;
  const targets = reportTargets(threat);

  async function copy() {
    try {
      await navigator.clipboard.writeText(report);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard may be unavailable */
    }
  }

  async function onReport() {
    // Record the community report (increments the counter) when the user
    // sends it to one of the gateways.
    const updated = await reportThreat(threat.id);
    setReportCount(updated ?? reportCount + 1);
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={onClose}
    >
      <div
        className="max-h-[85vh] w-full max-w-2xl overflow-auto rounded-xl border border-edge bg-panel p-5"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between">
          <h2 className="font-semibold">
            Abuse report ·{" "}
            <span className="font-mono text-sky-200">{threat.domain}</span>
          </h2>
          <button onClick={onClose} className="text-slate-400 hover:text-white">
            <X size={18} />
          </button>
        </div>
        <div className="mt-3 flex gap-2">
          <button
            onClick={copy}
            className="inline-flex items-center gap-1.5 rounded bg-sky-500 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-400"
          >
            {copied ? <Check size={15} /> : <Copy size={15} />}
            {copied ? "Copied" : "Copy report"}
          </button>
          <a
            href={`https://urlscan.io/search/#${threat.domain}`}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1.5 rounded border border-edge px-3 py-1.5 text-sm text-slate-300 hover:border-sky-500 hover:text-sky-300"
          >
            <ExternalLink size={15} /> urlscan
          </a>
        </div>

        {eligible ? (
          <div className="mt-4 rounded-lg border border-red-500/30 bg-red-500/5 p-3">
            <div className="flex items-center gap-2 text-sm font-medium text-red-300">
              <Siren size={16} />
              High risk ({threat.risk_score}) — report to a gateway
            </div>
            <p className="mt-1 text-xs text-slate-400">
              Sends this domain to real abuse channels. Community reports so far:{" "}
              <span className="font-semibold text-red-300">{reportCount}</span>
            </p>
            <div className="mt-2 flex flex-wrap gap-2">
              {targets.map((tg) => (
                <a
                  key={tg.label}
                  href={tg.href}
                  target="_blank"
                  rel="noreferrer"
                  onClick={onReport}
                  title={tg.note}
                  className="inline-flex items-center gap-1.5 rounded bg-red-500/90 px-3 py-1.5 text-sm font-medium text-white hover:bg-red-500"
                >
                  <ExternalLink size={14} /> {tg.label}
                </a>
              ))}
            </div>
          </div>
        ) : (
          <p className="mt-4 text-xs text-slate-500">
            Below the auto-report threshold ({AUTO_REPORT_THRESHOLD}). Copy the
            report above to escalate manually if warranted.
          </p>
        )}

        <pre className="mt-3 whitespace-pre-wrap rounded-lg bg-base p-4 text-xs leading-relaxed text-slate-300">
          {report}
        </pre>
      </div>
    </div>
  );
}
