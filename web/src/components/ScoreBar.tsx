export function ScoreBar({ label, value }: { label: string; value: number }) {
  const color =
    value >= 80 ? "bg-emerald-500" : value >= 50 ? "bg-yellow-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-2">
      <span className="w-16 shrink-0 text-[11px] uppercase tracking-wide text-slate-400">
        {label}
      </span>
      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-slate-700/50">
        <div
          className={`h-full rounded-full ${color}`}
          style={{ width: `${Math.max(0, Math.min(100, value))}%` }}
        />
      </div>
      <span className="w-8 text-right text-[11px] tabular-nums text-slate-400">
        {value}
      </span>
    </div>
  );
}
