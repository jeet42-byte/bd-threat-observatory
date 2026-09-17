import Link from "next/link";
import { ShieldAlert, ArrowRight } from "lucide-react";

export default function Home() {
  return (
    <main className="mx-auto max-w-3xl px-4 py-24">
      <div className="flex items-center gap-3 text-sky-400">
        <ShieldAlert size={28} />
        <span className="text-sm font-medium uppercase tracking-widest">
          Passive OSINT
        </span>
      </div>
      <h1 className="mt-6 text-4xl font-bold sm:text-5xl">
        BD Threat Observatory
      </h1>
      <p className="mt-4 text-lg text-slate-300">
        A live feed of phishing and scam domains impersonating Bangladeshi
        banks, mobile financial services, telcos, and government portals —
        detected from public Certificate Transparency logs as their
        certificates appear.
      </p>
      <p className="mt-3 text-sm text-slate-500">
        Reads only public data. No scanning, probing, or unauthorised access.
      </p>
      <Link
        href="/threats"
        className="mt-10 inline-flex items-center gap-2 rounded-lg bg-sky-500 px-5 py-3 font-medium text-white transition hover:bg-sky-400"
      >
        View the live feed <ArrowRight size={18} />
      </Link>
    </main>
  );
}
