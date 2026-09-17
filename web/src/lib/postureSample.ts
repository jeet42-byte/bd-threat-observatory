// Bundled fallback posture data (illustrative), mirrors the backend seed so the
// /posture dashboard renders before the API is live.
import type { PostureList } from "./types";

export const SAMPLE_POSTURE: PostureList = {
  total: 6,
  average_score: 51.7,
  grade_distribution: [
    { grade: "A", count: 1 },
    { grade: "B", count: 1 },
    { grade: "D", count: 1 },
    { grade: "E", count: 1 },
    { grade: "F", count: 2 },
  ],
  items: [
    {
      target: "bkash.com", brand_slug: "bkash", category: "mfs", grade: "A",
      score: 100, headers_score: 100, tls_score: 100, email_score: 100,
      reachable: true, checked_at: "2026-09-17T03:30:00Z",
      findings: [
        { check: "HSTS", status: "ok", detail: "present" },
        { check: "Content-Security-Policy", status: "ok", detail: "present" },
        { check: "X-Frame-Options", status: "ok", detail: "present" },
        { check: "TLS version", status: "ok", detail: "TLSv1.3" },
        { check: "SPF", status: "ok", detail: "present" },
        { check: "DMARC", status: "ok", detail: "policy=reject" },
      ],
    },
    {
      target: "grameenphone.com", brand_slug: "grameenphone", category: "telco", grade: "B",
      score: 85, headers_score: 66, tls_score: 100, email_score: 100,
      reachable: true, checked_at: "2026-09-17T03:30:00Z",
      findings: [
        { check: "HSTS", status: "ok", detail: "present" },
        { check: "Content-Security-Policy", status: "fail", detail: "missing" },
        { check: "TLS version", status: "ok", detail: "TLSv1.3" },
        { check: "DMARC", status: "ok", detail: "policy=quarantine" },
      ],
    },
    {
      target: "bracbank.com", brand_slug: "brac-bank", category: "bank", grade: "D",
      score: 58, headers_score: 40, tls_score: 80, email_score: 65,
      reachable: true, checked_at: "2026-09-17T03:30:00Z",
      findings: [
        { check: "HSTS", status: "ok", detail: "present" },
        { check: "Content-Security-Policy", status: "fail", detail: "missing" },
        { check: "TLS version", status: "ok", detail: "TLSv1.2" },
        { check: "DMARC", status: "warn", detail: "policy=none (monitoring only)" },
      ],
    },
    {
      target: "nagad.com.bd", brand_slug: "nagad", category: "mfs", grade: "E",
      score: 39, headers_score: 12, tls_score: 80, email_score: 40,
      reachable: true, checked_at: "2026-09-17T03:30:00Z",
      findings: [
        { check: "HSTS", status: "fail", detail: "missing" },
        { check: "TLS version", status: "ok", detail: "TLSv1.2" },
        { check: "SPF", status: "ok", detail: "present" },
        { check: "DMARC", status: "fail", detail: "no DMARC record" },
      ],
    },
    {
      target: "sonalibank.com.bd", brand_slug: "sonali-bank", category: "bank", grade: "F",
      score: 24, headers_score: 0, tls_score: 80, email_score: 0,
      reachable: true, checked_at: "2026-09-17T03:30:00Z",
      findings: [
        { check: "HSTS", status: "fail", detail: "missing" },
        { check: "TLS version", status: "ok", detail: "TLSv1.2" },
        { check: "SPF", status: "fail", detail: "no SPF record" },
        { check: "DMARC", status: "fail", detail: "no DMARC record" },
      ],
    },
    {
      target: "ec.gov.bd", brand_slug: "nid-ec", category: "gov", grade: "F",
      score: 4, headers_score: 0, tls_score: 15, email_score: 0,
      reachable: true, checked_at: "2026-09-17T03:30:00Z",
      findings: [
        { check: "HSTS", status: "fail", detail: "missing" },
        { check: "TLS version", status: "fail", detail: "TLSv1" },
        { check: "SPF", status: "fail", detail: "no SPF record" },
        { check: "DMARC", status: "fail", detail: "no DMARC record" },
      ],
    },
  ],
};
