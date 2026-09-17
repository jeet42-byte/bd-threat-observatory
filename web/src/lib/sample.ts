// Bundled fallback so the dashboard renders even before the backend is live
// (e.g. a Vercel preview deploy). All domains are fictional/illustrative.
import type { Stats, Threat } from "./types";

export const SAMPLE_THREATS: Threat[] = [
  {
    id: 1, domain: "secure-bkash-reward.xyz", registrable_domain: "secure-bkash-reward.xyz",
    tld: "xyz", brand_slug: "bkash", brand_name: "bKash", category: "mfs",
    risk_score: 91, confidence: "critical",
    reasons: ["contains brand keyword 'bkash'", "suspicious TLD '.xyz'", "lure token 'secure'", "lure token 'reward'", "multiple hyphens"],
    status: "new", report_count: 12, issued_at: "2026-09-15T00:00:00Z", first_seen_at: "2026-09-16T21:40:00Z", updated_at: "2026-09-16T21:40:00Z",
  },
  {
    id: 2, domain: "islamibank-otp-verify.top", registrable_domain: "islamibank-otp-verify.top",
    tld: "top", brand_slug: "ibbl", brand_name: "Islami Bank Bangladesh", category: "bank",
    risk_score: 95, confidence: "critical",
    reasons: ["contains brand keyword 'islamibank'", "suspicious TLD '.top'", "lure token 'otp'", "lure token 'verify'", "multiple hyphens", "unusually long domain"],
    status: "new", report_count: 8, issued_at: "2026-09-13T00:00:00Z", first_seen_at: "2026-09-16T20:05:00Z", updated_at: "2026-09-16T20:05:00Z",
  },
  {
    id: 3, domain: "my-nagad-verify.click", registrable_domain: "my-nagad-verify.click",
    tld: "click", brand_slug: "nagad", brand_name: "Nagad", category: "mfs",
    risk_score: 79, confidence: "high",
    reasons: ["contains brand keyword 'nagad'", "suspicious TLD '.click'", "lure token 'verify'", "multiple hyphens"],
    status: "new", report_count: 5, issued_at: "2026-09-15T00:00:00Z", first_seen_at: "2026-09-16T18:22:00Z", updated_at: "2026-09-16T18:22:00Z",
  },
  {
    id: 4, domain: "nagad-cashback.online", registrable_domain: "nagad-cashback.online",
    tld: "online", brand_slug: "nagad", brand_name: "Nagad", category: "mfs",
    risk_score: 73, confidence: "high",
    reasons: ["contains brand keyword 'nagad'", "suspicious TLD '.online'", "lure token 'cashback'"],
    status: "new", report_count: 3, issued_at: "2026-09-14T00:00:00Z", first_seen_at: "2026-09-16T15:10:00Z", updated_at: "2026-09-16T15:10:00Z",
  },
  {
    id: 5, domain: "bkosh-helpline.info", registrable_domain: "bkosh-helpline.info",
    tld: "info", brand_slug: "bkash", brand_name: "bKash", category: "mfs",
    risk_score: 66, confidence: "high",
    reasons: ["typosquat of 'bkash' ('bkosh')", "suspicious TLD '.info'", "lure token 'helpline'"],
    status: "new", report_count: 1, issued_at: "2026-09-11T00:00:00Z", first_seen_at: "2026-09-16T12:48:00Z", updated_at: "2026-09-16T12:48:00Z",
  },
  {
    id: 6, domain: "grameenphone-recharge-bonus.xyz", registrable_domain: "grameenphone-recharge-bonus.xyz",
    tld: "xyz", brand_slug: "grameenphone", brand_name: "Grameenphone", category: "telco",
    risk_score: 87, confidence: "critical",
    reasons: ["contains brand keyword 'grameenphone'", "suspicious TLD '.xyz'", "lure token 'recharge'", "lure token 'bonus'", "multiple hyphens", "unusually long domain"],
    status: "new", report_count: 6, issued_at: "2026-09-12T00:00:00Z", first_seen_at: "2026-09-16T09:31:00Z", updated_at: "2026-09-16T09:31:00Z",
  },
  {
    id: 7, domain: "daraz-gift-winner.shop", registrable_domain: "daraz-gift-winner.shop",
    tld: "shop", brand_slug: "daraz", brand_name: "Daraz Bangladesh", category: "ecommerce",
    risk_score: 91, confidence: "critical",
    reasons: ["contains brand keyword 'daraz'", "suspicious TLD '.shop'", "lure token 'gift'", "lure token 'winner'", "multiple hyphens"],
    status: "new", report_count: 9, issued_at: "2026-09-10T00:00:00Z", first_seen_at: "2026-09-15T22:14:00Z", updated_at: "2026-09-15T22:14:00Z",
  },
];

export const SAMPLE_STATS: Stats = {
  total_findings: SAMPLE_THREATS.length,
  total_domains: 42,
  total_certificates: 118,
  by_confidence: [
    { confidence: "critical", count: 4 },
    { confidence: "high", count: 3 },
    { confidence: "medium", count: 0 },
    { confidence: "low", count: 0 },
  ],
  top_brands: [
    { brand_slug: "bkash", brand_name: "bKash", count: 2 },
    { brand_slug: "nagad", brand_name: "Nagad", count: 2 },
    { brand_slug: "ibbl", brand_name: "Islami Bank Bangladesh", count: 1 },
  ],
  latest_finding_at: "2026-09-16T21:40:00Z",
};
