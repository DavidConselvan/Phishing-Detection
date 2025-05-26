import React, { useState, useEffect } from 'react';
import { UrlValidator } from '../services/urlValidator';

// Types matching backend response
export interface WhoisResult {
  age_days: number;
  creation_date: string;
  is_suspicious: boolean;
  registrar: string;
  expiration_date: string;
  organization?: string;
  country?: string;
}
export interface SSLResult {
  is_valid: boolean;
  is_expired: boolean;
  is_not_valid_yet: boolean;
  issuer?: string;
  valid_from?: string;
  valid_until?: string;
  domain_match: boolean;
  is_suspicious: boolean;
}
export interface RedirectResult {
  is_suspicious: boolean;
  reasons: string[];
  redirect_chain: string[];
  domains_visited: string[];
  final_url?: string;
}
export interface DynamicDNSResult {
  is_dynamic_dns: boolean;
  domain: string;
}
export interface BrandSimilarityResult {
  is_suspicious: boolean;
  reasons: string[];
  similar_brands: { label: string; distance: number }[];
  target_domain: string;
}
export interface ContentAnalysisResult {
  is_suspicious: boolean;
  reasons: string[];
  suspicious_text: string[];
  suspicious_forms: string[];
}
export interface PhishTankResult {
  in_database: boolean;
  valid?: boolean;
  phish_id?: number;
  phish_detail_page?: string;
  verified?: boolean;
  verified_at?: string;
}
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

export const UrlChecker: React.FC = () => {
  const [inputUrl, setInputUrl] = useState<string>('');
  const [history, setHistory] = useState<PhishingCheckResult[]>([]);
  const [error, setError] = useState<string | null>(null);

  // Explanation map for each risk reason
  const EXPLANATIONS: Record<string, string> = {
    'URL found in PhishTank database':
      'This URL has been reported and verified by the community as a phishing page.',
    'Domain is less than 30 days old':
      'Newly registered domains are often used in short-lived phishing campaigns before they can be blacklisted.',
    'Certificate domain mismatch':
      "An SSL certificate must match the site's hostname; a mismatch breaks trust and could allow interception.",
    'Certificate expired':
      'Expired certificates no longer guarantee encryption or authenticity—attackers can exploit this lapse to intercept or modify traffic.',
    'Certificate not yet valid':
      'Certificates are only valid after their start date—premature use can indicate misissuance or tampering.',
    'Domain uses Dynamic-DNS provider':
      'Dynamic-DNS services allow IPs to change rapidly, often used by attackers to evade takedowns.',
    'Form contains password field':
      'Login forms on untrusted domains can harvest your credentials.',
    'Form requests sensitive information':
      'Requesting personal data (credit card, CPF/CNPJ, etc.) outside an official site is a common identity-theft tactic.',
    'Label similar to':
      'Domains that closely resemble known brands are used by attackers to trick users into giving up credentials.',
    'Uses suspicious domain':
      'Unexpected redirects to unknown or malicious hosts indicate attempts to evade detection.',
  };

  // Load/persist history
  useEffect(() => {
    const stored = localStorage.getItem('urlCheckHistory');
    if (stored) setHistory(JSON.parse(stored));
  }, []);
  useEffect(() => {
    localStorage.setItem('urlCheckHistory', JSON.stringify(history));
  }, [history]);

  const checkUrl = async () => {
    setError(null);
    if (!UrlValidator.isValidUrl(inputUrl)) {
      setError('Please enter a valid URL (including http:// or https://)');
      return;
    }
    try {
      const resp = await fetch('http://localhost:3001/api/check-phishing', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: inputUrl }),
      });
      const result: PhishingCheckResult = await resp.json();
      setHistory(prev => [{ ...result }, ...prev]);
      setInputUrl('');
    } catch (e: any) {
      setError(`Error checking URL: ${e.message}`);
    }
  };

  const renderReasons = (reasons: string[]) => (
    <ul className="list-disc ml-4">
      {reasons.map((reason, i) => {
        let explanation = EXPLANATIONS[reason];
        if (!explanation) {
          for (const key in EXPLANATIONS) {
            if (reason.startsWith(key)) {
              explanation = EXPLANATIONS[key];
              break;
            }
          }
        }
        return (
          <li key={i} className="mb-2">
            {reason}
            {explanation && (
              <p className="text-sm text-gray-600 ml-4">{explanation}</p>
            )}
          </li>
        );
      })}
    </ul>
  );

  return (
    <div className="container mx-auto p-4">
      <h1 className="text-2xl font-bold mb-4">URL Phishing Checker</h1>

      <div className="flex mb-4">
        <input
          type="text"
          className="border p-2 flex-grow mr-2"
          placeholder="https://example.com"
          value={inputUrl}
          onChange={e => setInputUrl(e.target.value)}
        />
        <button className="bg-blue-500 text-white px-4 rounded" onClick={checkUrl}>
          Check URL
        </button>
      </div>

      {error && <p className="text-red-500 mb-4">{error}</p>}

      <table className="min-w-full bg-white">
        <thead>
          <tr>
            <th className="py-2">URL</th>
            <th className="py-2">Status</th>
            <th className="py-2">Analysis</th>
          </tr>
        </thead>
        <tbody>
          {history.map((entry, idx) => (
            <tr key={idx} className={entry.phishtank?.in_database && entry.phishtank?.valid ? 'bg-red-50' : 'bg-green-50'}>
              <td className="border px-2 py-1 align-top">{entry.url}</td>
              <td className="border px-2 py-1 align-top">
                {entry.phishtank?.in_database && entry.phishtank?.valid ? (
                  <span className="text-red-600 font-semibold">Suspicious</span>
                ) : (
                  <span className="text-green-600 font-semibold">Safe</span>
                )}
              </td>
              <td className="border px-2 py-1">
                <details>
                  <summary className="cursor-pointer font-medium">View full analysis</summary>
                  <div className="mt-2 space-y-4">
                    {/* PhishTank */}
                    <div>
                      <h4 className="font-semibold">PhishTank</h4>
                      {entry.phishtank?.in_database && entry.phishtank?.valid ? (
                        renderReasons(['URL found in PhishTank database'])
                      ) : (
                        <p>Not listed in PhishTank</p>
                      )}
                    </div>

                    {/* WHOIS */}
                    <div>
                      <h4 className="font-semibold">WHOIS</h4>
                      <p>Age: {entry.whois.age_days} days</p>
                      {entry.whois.is_suspicious ? (
                        renderReasons([
                          'Domain is less than 30 days old'
                        ])
                      ) : (
                        <p>Domain age OK</p>
                      )}
                    </div>

                    {/* SSL */}
                    <div>
                      <h4 className="font-semibold">SSL</h4>
                      <p>Valid: {entry.ssl.is_valid ? 'Yes' : 'No'}</p>
                      {!entry.ssl.is_valid && renderReasons([
                        !entry.ssl.domain_match && 'Certificate domain mismatch',
                        entry.ssl.is_expired && 'Certificate expired',
                        entry.ssl.is_not_valid_yet && 'Certificate not yet valid',
                      ].filter(Boolean) as string[])}
                    </div>

                    {/* Redirects */}
                    <div>
                      <h4 className="font-semibold">Redirects</h4>
                      <p>Chain: {entry.redirects.redirect_chain.join(' → ')}</p>
                      {entry.redirects.reasons.length > 0 ? (
                        renderReasons(entry.redirects.reasons)
                      ) : (
                        <p>No suspicious redirects</p>
                      )}
                    </div>

                    {/* Dynamic DNS */}
                    <div>
                      <h4 className="font-semibold">Dynamic DNS</h4>
                      {entry.dynamic_dns.is_dynamic_dns ? (
                        renderReasons([
                          'Domain uses Dynamic-DNS provider'
                        ])
                      ) : (
                        <p>No DDNS detected</p>
                      )}
                    </div>

                    {/* Brand Similarity */}
                    <div>
                      <h4 className="font-semibold">Brand Similarity</h4>
                      {entry.brand_similarity.reasons.length > 0 ? (
                        renderReasons(entry.brand_similarity.reasons)
                      ) : (
                        <p>No brand-similarity risk detected</p>
                      )}
                    </div>

                    {/* Content Analysis */}
                    <div>
                      <h4 className="font-semibold">Content</h4>
                      {entry.content_analysis.reasons.length > 0 ? (
                        renderReasons(entry.content_analysis.reasons)
                      ) : (
                        <p>No suspicious forms or fields detected</p>
                      )}
                    </div>
                  </div>
                </details>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default UrlChecker;
