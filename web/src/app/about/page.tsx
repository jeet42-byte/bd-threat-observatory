import { Nav } from "@/components/Nav";

export const metadata = {
  title: "About · BD Threat Observatory",
};

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mt-8">
      <h2 className="text-lg font-semibold text-slate-100">{title}</h2>
      <div className="mt-2 space-y-2 text-sm leading-relaxed text-slate-300">
        {children}
      </div>
    </section>
  );
}

export default function AboutPage() {
  return (
    <main className="mx-auto max-w-3xl px-4 py-8">
      <Nav />

      <h1 className="mt-6 text-2xl font-bold">About & methodology</h1>
      <p className="mt-2 text-sm text-slate-400">
        How the BD Threat Observatory works, what it does and does not do.
      </p>

      <Section title="What this is">
        <p>
          A passive security-intelligence project focused on Bangladesh&apos;s
          public web. It runs two things off one pipeline: a live feed of
          phishing/scam domains impersonating Bangladeshi brands, and an A–F
          grading of the public web-security posture of those brands&apos; real
          sites.
        </p>
      </Section>

      <Section title="Ethics & legality">
        <p>
          Everything here is <strong>passive OSINT</strong>. It reads only
          public data and never scans, probes, exploits, or attempts any
          unauthorised access — consistent with Bangladesh&apos;s Cyber Security
          Act. Every request it makes is the kind an ordinary browser or mail
          system already makes.
        </p>
      </Section>

      <Section title="Data sources">
        <ul className="list-disc space-y-1 pl-5">
          <li>
            <strong>Certificate Transparency</strong> (crt.sh) — newly issued
            TLS certificates, used to discover both phishing lookalikes and the
            legitimate attack surface.
          </li>
          <li>
            <strong>HTTP response headers</strong> — from a normal HTTPS GET, to
            check HSTS, CSP, and related protections.
          </li>
          <li>
            <strong>TLS handshake</strong> — the negotiated protocol version.
          </li>
          <li>
            <strong>Public DNS</strong> — SPF and DMARC TXT records for email
            authentication.
          </li>
        </ul>
      </Section>

      <Section title="How phishing is scored">
        <p>
          A domain must first show a brand-identity signal — the brand name
          verbatim, a typosquat/homoglyph variant, or a close lookalike — before
          any risk is assigned. Suspicious TLDs, financial-lure keywords, and
          structural quirks then raise the score. Each finding lists the exact
          signals that fired.
        </p>
      </Section>

      <Section title="How posture is graded">
        <p>
          A weighted score across HTTP security headers (45%), TLS version
          (30%), and SPF/DMARC email authentication (25%), mapped to an A–F
          grade. It reflects observable configuration only, not a full security
          assessment.
        </p>
      </Section>

      <Section title="Disclaimer">
        <p>
          Flagged domains are <strong>candidate</strong> impersonations produced
          by heuristics, not a determination of wrongdoing. Grades are a
          configuration snapshot, not an audit. Verify before acting on anything
          here.
        </p>
      </Section>
    </main>
  );
}
