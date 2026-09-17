export type Confidence = "low" | "medium" | "high" | "critical";

export interface Threat {
  id: number;
  domain: string;
  registrable_domain: string;
  tld: string;
  brand_slug: string;
  brand_name: string;
  category: string;
  risk_score: number;
  confidence: Confidence;
  reasons: string[];
  status: string;
  report_count: number;
  issued_at: string | null;
  first_seen_at: string;
  updated_at: string;
}

export interface ThreatList {
  total: number;
  limit: number;
  offset: number;
  items: Threat[];
}

export interface Stats {
  total_findings: number;
  total_domains: number;
  total_certificates: number;
  by_confidence: { confidence: string; count: number }[];
  top_brands: { brand_slug: string; brand_name: string; count: number }[];
  latest_finding_at: string | null;
}

export type Grade = "A" | "B" | "C" | "D" | "E" | "F";

export interface PostureFinding {
  check: string;
  status: "ok" | "warn" | "fail";
  detail: string;
}

export interface Posture {
  target: string;
  brand_slug: string | null;
  category: string;
  grade: Grade;
  score: number;
  headers_score: number;
  tls_score: number;
  email_score: number;
  reachable: boolean;
  findings: PostureFinding[];
  checked_at: string;
}

export interface PostureList {
  total: number;
  items: Posture[];
  grade_distribution: { grade: string; count: number }[];
  average_score: number | null;
}
