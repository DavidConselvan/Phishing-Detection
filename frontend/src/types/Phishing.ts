// Types matching backend response
export interface WhoisResult { age_days: number; creation_date: string; is_suspicious: boolean; registrar: string; expiration_date: string; organization?: string; country?: string; }
export interface SSLResult { is_valid: boolean; is_expired: boolean; is_not_valid_yet: boolean; issuer?: string; valid_from?: string; valid_until?: string; domain_match: boolean; is_suspicious: boolean; }
export interface RedirectResult { is_suspicious: boolean; reasons: string[]; redirect_chain: string[]; domains_visited: string[]; final_url?: string; }
export interface DynamicDNSResult { is_dynamic_dns: boolean; domain: string; }
export interface BrandSimilarityResult { is_suspicious: boolean; reasons: string[]; similar_brands: { label: string; distance: number }[]; target_domain: string; }
export interface ContentAnalysisResult { is_suspicious: boolean; reasons: string[]; suspicious_text: string[]; suspicious_forms: string[]; }
export interface PhishTankResult { in_database: boolean; valid?: boolean; phish_id?: number; phish_detail_page?: string; verified?: boolean; verified_at?: string; }
export interface PhishingCheckResult {
  url: string;
  isPhishing: boolean;
  reasons: string[];
  phishtank?: PhishTankResult;
  whois: WhoisResult;
  ssl: SSLResult;
  redirects: RedirectResult;
  dynamic_dns: DynamicDNSResult;
  brand_similarity: BrandSimilarityResult;
  content_analysis: ContentAnalysisResult;
}