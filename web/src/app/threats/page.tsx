"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  ShieldAlert,
  Radio,
  Copy,
  Check,
  X,
  ExternalLink,
} from "lucide-react";
import type { Stats, Threat } from "@/lib/types";
import { fetchStats, fetchThreats } from "@/lib/api";
import { abuseReport } from "@/lib/abuse";
import { RiskBadge } from "@/components/RiskBadge";
import { StatCard } from "@/components/StatCard";

const CONFIDENCES = ["all", "critical", "high", "medium", "low"] as const;

export default function ThreatsPage() {
  const [threats, setThreats] = useState<Threat[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [live, setLive] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(true);

  const [brand, setBrand] = useState<string>("");
  const [confidence, setConfidence] = useState<string>("all");
  const [minScore, setMinScore] = useState<number>(0);
  const [selected, setSelected] = useState<Threat | null>(null);

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
    ]).then(([t, s]) => {
      if (!active) return;
      setThreats(t.data.items);
      setLive(t.live && s.live);
      setStats(s.data);
      setLoading(false);
    });
    return () => {
      active = false;
    };
  }, [brand, confidence, minScore]);

  // Client-side filter too, so sample-mode filtering still works.
  const visible = useMemo(() => {
    return threats.filter(
      (t) =>
        (!brand || t.brand_slug === brand) &&
        (confidence === "all" || t.confidence === confidence) &&
        t.risk_score >= minScore,
    );
  }, [threats, brand, confidence, minScore]);

  const brandOptions = useMemo(() => {
    const m = new Map<string, string>();
    threats.forEach((t) => m.set(t.brand_slug, t.brand_name));
    return Array.from(m.entries());
  }, [threats]);

  const criticalCount =
    stats?.by_confidence.find((c) => c.confidence === "critical")?.count ?? 0;

  return (
    <main className="mx-auto max-w-6xl px-4 py-8">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <ShieldAlert className="text-sky-400" size={26} />
          <div>
            <Link href="/" className="text-lg font-bold hover:text-sky-300">
              BD Threat Observatory
            </Link>
            <p className="text-xs text-slate-400">
              Phishing &amp; scam-domain feed · passive OSINT
            </p>
          </div>
        </div>
        <span
          className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium ring-1 ${
            live
              ? "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30"
              : "bg-slate-500/15 text-slate-300 ring-slate-500/30"
          }`}
        >
          <Radio size={13} /> {live ? "Live data" : "Sample data"}
        </span>
      </header>

      <section className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <StatCard label="Findings" value={stats?.total_findings ?? "—"} />
        <StatCard
          label="Critical"
          value={criticalCount}
          accent="text-red-300"
        />
        <StatCard label="Domains seen" value={stats?.total_domains ?? "—"} />
        <StatCard
          label="Certificates"
          value={stats?.total_certificates ?? "—"}
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
        <div className="ml-auto text-sm text-slate-400">
          {loading ? "Loading…" : `${visible.length} shown`}
        </div>
      </section>

      <section className="mt-4 overflow-x-auto rounded-xl border border-edge">
        <table className="w-full min-w-[720px] text-sm">
          <thead className="bg-panel text-left text-xs uppercase tracking-wide text-slate-400">
            <tr>
              <th className="px-4 py-3">Domain</th>
              <th className="px-4 py-3">Brand</th>
              <th className="px-4 py-3">Risk</th>
              <th className="px-4 py-3">Signals</th>
              <th className="px-4 py-3">First seen</th>
              <th className="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-edge">
            {visible.map((t) => (
              <tr key={t.id} className="bg-base/40 hover:bg-panel/60">
                <td className="px-4 py-3 font-mono text-sky-200">{t.domain}</td>
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
                <td className="px-4 py-3 text-slate-400">
                  {new Date(t.first_seen_at).toISOString().slice(0, 10)}
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
                  colSpan={6}
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
  const report = abuseReport(threat);

  async function copy() {
    try {
      await navigator.clipboard.writeText(report);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard may be unavailable */
    }
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
        <pre className="mt-3 whitespace-pre-wrap rounded-lg bg-base p-4 text-xs leading-relaxed text-slate-300">
          {report}
        </pre>
      </div>
    </div>
  );
}
