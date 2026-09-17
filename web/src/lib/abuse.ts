import type { Threat } from "./types";

/** Build a ready-to-send abuse / takedown report for a finding. */
export function abuseReport(t: Threat): string {
  const seen = new Date(t.first_seen_at).toISOString().slice(0, 10);
  return `Subject: Phishing domain impersonating ${t.brand_name} — ${t.domain}

To whom it may concern,

The domain below appears to impersonate ${t.brand_name} (${t.category}) for the
purpose of phishing / financial fraud targeting users in Bangladesh.

  Domain:            ${t.domain}
  Registrable domain:${t.registrable_domain}
  Impersonated brand:${t.brand_name}
  First observed:    ${seen} (via Certificate Transparency)
  Risk score:        ${t.risk_score}/100 (${t.confidence})

Indicators observed:
${t.reasons.map((r) => `  - ${r}`).join("\n")}

This report is based solely on passively observed public data (Certificate
Transparency logs). We request review and, if confirmed, suspension of the
domain and/or its certificate.

Regards,
BD Threat Observatory`;
}
