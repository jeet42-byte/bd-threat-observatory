"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ShieldAlert, Radio } from "lucide-react";

const LINKS = [
  { href: "/threats", label: "Phishing feed" },
  { href: "/posture", label: "Posture grades" },
  { href: "/about", label: "About" },
];

export function Nav({ live }: { live?: boolean }) {
  const path = usePathname();
  return (
    <header className="flex flex-wrap items-center justify-between gap-3 border-b border-edge pb-4">
      <div className="flex items-center gap-4">
        <Link href="/" className="flex items-center gap-2">
          <ShieldAlert className="text-sky-400" size={22} />
          <span className="font-bold">BD Threat Observatory</span>
        </Link>
        <nav className="flex gap-1">
          {LINKS.map((l) => {
            const active = path === l.href;
            return (
              <Link
                key={l.href}
                href={l.href}
                className={`rounded-md px-3 py-1.5 text-sm transition ${
                  active
                    ? "bg-sky-500/15 text-sky-300"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                {l.label}
              </Link>
            );
          })}
        </nav>
      </div>
      {live !== undefined && (
        <span
          className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium ring-1 ${
            live
              ? "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30"
              : "bg-slate-500/15 text-slate-300 ring-slate-500/30"
          }`}
        >
          <Radio size={13} /> {live ? "Live data" : "Sample data"}
        </span>
      )}
    </header>
  );
}
