import type { Confidence } from "@/lib/types";

const STYLES: Record<Confidence, string> = {
  critical: "bg-red-500/15 text-red-300 ring-red-500/30",
  high: "bg-orange-500/15 text-orange-300 ring-orange-500/30",
  medium: "bg-yellow-500/15 text-yellow-200 ring-yellow-500/30",
  low: "bg-slate-500/15 text-slate-300 ring-slate-500/30",
};

export function RiskBadge({
  confidence,
  score,
}: {
  confidence: Confidence;
  score: number;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold ring-1 ${STYLES[confidence]}`}
    >
      <span className="tabular-nums">{score}</span>
      <span className="uppercase tracking-wide">{confidence}</span>
    </span>
  );
}
