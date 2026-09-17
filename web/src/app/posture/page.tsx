"use client";

import { useEffect, useMemo, useState } from "react";
import { X, ShieldCheck, ShieldX } from "lucide-react";
import type { Posture } from "@/lib/types";
import { fetchPosture, hasDmarc } from "@/lib/api";
import { Nav } from "@/components/Nav";
import { GradeBadge } from "@/components/GradeBadge";
import { ScoreBar } from "@/components/ScoreBar";
import { StatCard } from "@/components/StatCard";

const GRADE_COLORS: Record<string, string> = {
  A: "#34d399", B: "#a3e635", C: "#facc15", D: "#fb923c", E: "#fb7185", F: "#ef4444",
};

export default function PosturePage() {
  const [items, setItems] = useState<Posture[]>([]);
  const [dist, setDist] = useState<{ grade: string; count: number }[]>([]);
  const [avg, setAvg] = useState<number | null>(null);
  const [live, setLive] = useState(false);
  const [loading, setLoading] = useState(true);
  const [category, setCategory] = useState("");
  const [selected, setSelected] = useState<Posture | null>(null);

  useEffect(() => {
    let active = true;
    setLoading(true);
    fetchPosture().then(({ data, live }) => {
      if (!active) return;
      setItems(data.items);
      setDist(data.grade_distribution);
      setAvg(data.average_score);
      setLive(live);
      setLoading(false);
    });
    return () => {
      active = false;
    };
  }, []);

  const categories = useMemo(
    () => Array.from(new Set(items.map((i) => i.category))).sort(),
    [items],
  );
  const visible = useMemo(
    () => items.filter((i) => !category || i.category === category),
    [items, category],
  );

  const worst = useMemo(
    () => items.filter((i) => ["E", "F"].includes(i.grade)).length,
    [items],
  );

  // Always show A-F in order (fill gaps with 0) so bars align under labels.
  const fullDist = useMemo(() => {
    const by = new Map(dist.map((d) => [d.grade, d.count]));
    return ["A", "B", "C", "D", "E", "F"].map((g) => ({
      grade: g,
      count: by.get(g) ?? 0,
    }));
  }, [dist]);

  return (
    <main className="mx-auto max-w-6xl px-4 py-8">
      <Nav live={live} />

      <h1 className="mt-6 text-xl font-bold">Security posture observatory</h1>
      <p className="text-sm text-slate-400">
        Passive A–F grading of Bangladeshi banks, MFS, telcos, and government
        sites — HTTP security headers, TLS version, and SPF/DMARC email auth.
      </p>

      <section className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <StatCard label="Orgs graded" value={items.length} />
        <StatCard label="Average score" value={avg ?? "—"} />
        <StatCard label="Grade E–F" value={worst} accent="text-red-300" />
        <StatCard
          label="Grade A"
          value={dist.find((d) => d.grade === "A")?.count ?? 0}
          accent="text-emerald-300"
        />
      </section>

      <section className="mt-4 grid gap-4 lg:grid-cols-[1fr_320px]">
        {/* Table */}
        <div className="overflow-x-auto rounded-xl border border-edge">
          <div className="flex items-center justify-between gap-3 border-b border-edge bg-panel px-4 py-2">
            <span className="text-sm font-medium">Organisations</span>
            <select
              value={category}
              onChange={(e) => setCategory(e.target.value)}
              className="rounded-md border border-edge bg-base px-2 py-1 text-xs text-slate-200"
            >
              <option value="">All categories</option>
              {categories.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          </div>
          <table className="w-full min-w-[560px] text-sm">
            <tbody className="divide-y divide-edge">
              {visible.map((p) => (
                <tr
                  key={p.target}
                  className="cursor-pointer bg-base/40 hover:bg-panel/60"
                  onClick={() => setSelected(p)}
                >
                  <td className="px-4 py-3">
                    <GradeBadge grade={p.grade} />
                  </td>
                  <td className="px-4 py-3">
                    <div className="font-mono text-sky-200">{p.target}</div>
                    <div className="text-xs text-slate-500">{p.category}</div>
                  </td>
                  <td className="w-64 px-4 py-3">
                    <div className="space-y-1">
                      <ScoreBar label="Headers" value={p.headers_score} />
                      <ScoreBar label="TLS" value={p.tls_score} />
                      <ScoreBar label="Email" value={p.email_score} />
                    </div>
                  </td>
                  <td className="px-4 py-3 text-right">
                    {hasDmarc(p) ? (
                      <span className="inline-flex items-center gap-1 text-xs text-emerald-300">
                        <ShieldCheck size={14} /> DMARC
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-xs text-red-300">
                        <ShieldX size={14} /> no DMARC
                      </span>
                    )}
                  </td>
                </tr>
              ))}
              {!loading && visible.length === 0 && (
                <tr>
                  <td colSpan={4} className="px-4 py-10 text-center text-slate-500">
                    No organisations in this category.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Distribution */}
        <div className="rounded-xl border border-edge bg-panel p-4">
          <div className="text-sm font-medium">Grade distribution</div>
          <div className="mt-4 space-y-2.5">
            {fullDist.map((d) => {
              const max = Math.max(1, ...fullDist.map((x) => x.count));
              const pct = (d.count / max) * 100;
              return (
                <div key={d.grade} className="flex items-center gap-3">
                  <span className="w-4 text-sm font-bold text-slate-300">
                    {d.grade}
                  </span>
                  <div className="h-4 flex-1 overflow-hidden rounded bg-slate-700/40">
                    <div
                      className="h-full rounded"
                      style={{
                        width: `${pct}%`,
                        background: GRADE_COLORS[d.grade] ?? "#64748b",
                        minWidth: d.count > 0 ? "6px" : "0",
                      }}
                    />
                  </div>
                  <span className="w-5 text-right text-xs tabular-nums text-slate-400">
                    {d.count}
                  </span>
                </div>
              );
            })}
          </div>
          <p className="mt-4 text-xs text-slate-500">
            Higher grade = stronger public web-security configuration.
          </p>
        </div>
      </section>

      <p className="mt-6 text-xs text-slate-500">
        Grades reflect only passively observable configuration (headers, TLS
        version, public DNS email-auth records). They are not a full security
        assessment.
      </p>

      {selected && (
        <FindingsPanel posture={selected} onClose={() => setSelected(null)} />
      )}
    </main>
  );
}

const STATUS_STYLE: Record<string, string> = {
  ok: "text-emerald-300",
  warn: "text-yellow-300",
  fail: "text-red-300",
};

function FindingsPanel({
  posture,
  onClose,
}: {
  posture: Posture;
  onClose: () => void;
}) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={onClose}
    >
      <div
        className="max-h-[85vh] w-full max-w-lg overflow-auto rounded-xl border border-edge bg-panel p-5"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <GradeBadge grade={posture.grade} />
            <div>
              <div className="font-mono text-sky-200">{posture.target}</div>
              <div className="text-xs text-slate-500">
                {posture.category} · score {posture.score}/100
              </div>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white">
            <X size={18} />
          </button>
        </div>
        <ul className="mt-4 space-y-1.5 text-sm">
          {posture.findings.map((f, i) => (
            <li
              key={i}
              className="flex items-center justify-between rounded bg-base px-3 py-2"
            >
              <span className="text-slate-300">{f.check}</span>
              <span className={STATUS_STYLE[f.status] ?? "text-slate-400"}>
                {f.detail}
              </span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
