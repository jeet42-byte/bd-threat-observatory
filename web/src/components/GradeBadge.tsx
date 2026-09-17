import type { Grade } from "@/lib/types";

const STYLES: Record<Grade, string> = {
  A: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/40",
  B: "bg-lime-500/15 text-lime-300 ring-lime-500/40",
  C: "bg-yellow-500/15 text-yellow-200 ring-yellow-500/40",
  D: "bg-orange-500/15 text-orange-300 ring-orange-500/40",
  E: "bg-rose-500/15 text-rose-300 ring-rose-500/40",
  F: "bg-red-500/20 text-red-300 ring-red-500/50",
};

export function GradeBadge({ grade, size = "md" }: { grade: Grade; size?: "sm" | "md" }) {
  const dim = size === "sm" ? "h-6 w-6 text-xs" : "h-9 w-9 text-base";
  return (
    <span
      className={`inline-flex ${dim} items-center justify-center rounded-lg font-bold ring-1 ${STYLES[grade]}`}
    >
      {grade}
    </span>
  );
}
