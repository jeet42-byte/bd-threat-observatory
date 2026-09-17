// Auto-reporting: where a high-risk phishing domain should be reported.
//
// We route to real, appropriate destinations rather than fabricated inboxes:
//  - Google Safe Browsing phishing report (gets the URL flagged in Chrome/Android)
//  - BD e-GOV CIRT, Bangladesh's national cyber incident response team
//  - the impersonated brand's own official site (contact/complaint channel)
import type { Threat } from "./types";

// Score at/above which a finding warrants active reporting (not just a copyable note).
export const AUTO_REPORT_THRESHOLD = 70;

// Brand slug -> the brand's official site (real domains, used for their own
// fraud/abuse reporting channel). Presentation-only; safe if a slug is missing.
const BRAND_SITE: Record<string, string> = {
  bkash: "https://www.bkash.com/support/contact-us",
  nagad: "https://nagad.com.bd",
  "rocket-dbbl": "https://www.dutchbanglabank.com",
  upay: "https://www.upaybd.com",
  dbbl: "https://www.dutchbanglabank.com",
  "brac-bank": "https://www.bracbank.com",
  ibbl: "https://www.islamibankbd.com",
  "city-bank": "https://www.thecitybank.com",
  "sonali-bank": "https://www.sonalibank.com.bd",
  grameenphone: "https://www.grameenphone.com",
  robi: "https://www.robi.com.bd",
  banglalink: "https://www.banglalink.net",
  "nid-ec": "https://www.ec.gov.bd",
  "gov-bd": "https://bangladesh.gov.bd",
  daraz: "https://www.daraz.com.bd",
  pathao: "https://pathao.com",
};

export interface ReportTarget {
  label: string;
  href: string;
  note: string;
}

export function reportTargets(t: Threat): ReportTarget[] {
  const url = `https://${t.domain}`;
  const targets: ReportTarget[] = [
    {
      label: "Google Safe Browsing",
      href: `https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent(url)}`,
      note: "Flags the URL as phishing in Chrome & Android",
    },
    {
      label: "BD e-GOV CIRT",
      href: "https://www.cirt.gov.bd/incident-reporting/",
      note: "Bangladesh national cyber incident response team",
    },
  ];
  const site = BRAND_SITE[t.brand_slug];
  if (site) {
    targets.push({
      label: `Notify ${t.brand_name}`,
      href: site,
      note: "The impersonated brand's official channel",
    });
  }
  return targets;
}
