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
