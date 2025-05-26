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
export interface PhishingCheckResult {
  url: string;
  isPhishing: boolean;
  reasons: string[];
  phishtank?: any;
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
  const [inPhishTank, setInPhishTank] = useState<boolean>(false);

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
        body: JSON.stringify({ url: inputUrl })
      });
      const result: PhishingCheckResult = await resp.json();
      setInPhishTank(result.phishtank.valid && result.phishtank.in_database);
      // console.log("result: ", result)
      setHistory(prev => [{ ...result }, ...prev]);
      setInputUrl('');
    } catch (e: any) {
      setError(`Error checking URL: ${e.message}`);
    }
  };

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
        <button
          className="bg-blue-500 text-white px-4 rounded"
          onClick={checkUrl}
        >
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
            <tr key={idx} className={inPhishTank ? 'bg-red-50' : 'bg-green-50'}>
              <td className="border px-2 py-1 align-top">{entry.url}</td>
              <td className="border px-2 py-1 align-top">
                {inPhishTank ? (
                  <span className="text-red-600 font-semibold">Suspicious</span>
                ) : (
                  <span className="text-green-600 font-semibold">Safe</span>
                )}
              </td>
              <td className="border px-2 py-1">
                <details>
                  <summary className="cursor-pointer font-medium">View full analysis</summary>
                  <div className="mt-2 space-y-2">
                    <div>
                      <h4 className="font-semibold">PhishTank</h4>
                      <p>{inPhishTank ? 'URL found in PhishTank' : 'Not listed in PhishTank'}</p>
                    </div>

                    <div>
                      <h4 className="font-semibold">WHOIS</h4>
                      <p>Age: {entry.whois.age_days} days</p>
                      <p>{entry.whois.is_suspicious ? `Domain <30d (created ${entry.whois.creation_date})` : 'Domain age OK'}</p>
                    </div>

                    <div>
                      <h4 className="font-semibold">SSL</h4>
                      <p>Valid: {entry.ssl.is_valid ? 'Yes' : 'No'}</p>
                      {!entry.ssl.is_valid && (
                        <ul className="list-disc ml-4">
                          {(!entry.ssl.domain_match) && <li>Certificate domain mismatch</li>}
                          {entry.ssl.is_expired && <li>Certificate expired</li>}
                          {entry.ssl.is_not_valid_yet && <li>Certificate not yet valid</li>}
                        </ul>
                      )}
                    </div>

                    <div>
                      <h4 className="font-semibold">Redirects</h4>
                      <p>Chain: {entry.redirects.redirect_chain.join(' → ')}</p>
                      {entry.redirects.reasons.length > 0 ? (
                        <ul className="list-disc ml-4">
                          {entry.redirects.reasons.map((r,i) => <li key={i}>{r}</li>)}
                        </ul>
                      ) : (
                        <p>No suspicious redirects</p>
                      )}
                    </div>

                    <div>
                      <h4 className="font-semibold">Dynamic DNS</h4>
                      {entry.dynamic_dns ? (
                        entry.dynamic_dns.is_dynamic_dns ? (
                          <p>Uses DDNS: {entry.dynamic_dns.domain}</p>
                        ) : (
                          <p>No DDNS detected</p>
                        )
                      ) : (
                        <p>Dynamic DNS check not available</p>
                      )}
                    </div>

                    <div>
                      <h4 className="font-semibold">Brand Similarity</h4>
                      {entry.brand_similarity.reasons.length > 0 ? (
                        <ul className="list-disc ml-4">
                          {entry.brand_similarity.reasons.map((r,i) => <li key={i}>{r}</li>)}
                        </ul>
                      ) : (
                        <p>No brand-similarity risk detected</p>
                      )}
                    </div>

                    <div>
                      <h4 className="font-semibold">Content</h4>
                      {entry.content_analysis.reasons.length > 0 ? (
                        <ul className="list-disc ml-4">
                          {entry.content_analysis.reasons.map((r,i) => <li key={i}>{r}</li>)}
                        </ul>
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
