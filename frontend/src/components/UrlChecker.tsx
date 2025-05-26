import React, { useState, useEffect } from 'react';
import { UrlValidator } from '../services/urlValidator';
import { AnalysisCharts } from './PhishingCharts';
import type { PhishingCheckResult } from '../types/Phishing';


export const UrlChecker: React.FC = () => {
  const [inputUrl, setInputUrl] = useState<string>('');
  const [history, setHistory] = useState<PhishingCheckResult[]>([]);
  const [error, setError] = useState<string | null>(null);
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

  // Load history on mount
  useEffect(() => {
    const stored = localStorage.getItem('urlCheckHistory');
    if (stored) {
      setHistory(JSON.parse(stored));
    }
  }, []);

  // Save history when it changes (skip initial empty state)
  useEffect(() => {
    if (history.length > 0) {
      localStorage.setItem('urlCheckHistory', JSON.stringify(history));
    }
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
      // console.log("Result: ", result);
      setHistory(prev => [result, ...prev]);
      setInputUrl('');
    } catch (e: any) {
      setError(`Error checking URL: ${e.message}`);
    }
  };

  // Export history as JSON
  const exportJSON = () => {
    const dataStr = JSON.stringify(history, null, 2);
    const blob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'url_history.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  // Export history as CSV
    // Export history as CSV
    // Export history as CSV (improved flattening)
  // Export history as CSV (fixed ordering and escaping)
  const exportCSV = () => {
    if (history.length === 0) return;

    // Define headers explicitly in the desired order
    const headers = [
      'url',
      'status',
      'reasons',
      'phishtank_in_database',
      'phishtank_verified_at',
      'whois_age_days',
      'whois_is_suspicious',
      'whois_creation_date',
      'whois_registrar',
      'whois_organization',
      'whois_country',
      'ssl_is_valid',
      'ssl_domain_match',
      'ssl_is_expired',
      'ssl_not_valid_yet',
      'redirect_chain',
      'redirect_reasons',
      'dynamic_dns',
      'brand_similarity_reasons',
      'content_reasons'
    ];

    // Build rows array
    const rows = history.map(e => [
      e.url,
      e.isPhishing ? 'Suspicious' : 'Safe',
      e.reasons.join('; '),
      e.phishtank?.in_database?.toString() ?? 'false',
      e.phishtank?.verified_at ?? '',
      e.whois.age_days != null ? e.whois.age_days.toString() : '',
      e.whois.is_suspicious.toString(),
      e.whois.creation_date ?? '',
      e.whois.registrar ?? '',
      e.whois.organization ?? '',
      e.whois.country ?? '',
      e.ssl.is_valid.toString(),
      e.ssl.domain_match.toString(),
      e.ssl.is_expired.toString(),
      e.ssl.is_not_valid_yet.toString(),
      e.redirects.redirect_chain.join(' > '),
      e.redirects.reasons.join('; '),
      e.dynamic_dns.is_dynamic_dns ? e.dynamic_dns.domain : 'false',
      e.brand_similarity.reasons.join('; '),
      e.content_analysis.reasons.join('; ')
    ]);

    // Helper to escape any quotes in field
    const escape = (str: string) => `"${str.replace(/"/g, '""')}"`;

    // Compose CSV content
    const csvContent = [
      headers.map(escape).join(','),
      ...rows.map(row => row.map(escape).join(','))
    ].join('\r\n');

    // Trigger file download
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'url_history.csv';
    a.click();
    URL.revokeObjectURL(url);
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

      <div className="flex mb-4 space-x-2">
        <input
          type="text"
          className="border p-2 flex-grow"
          placeholder="https://example.com"
          value={inputUrl}
          onChange={e => setInputUrl(e.target.value)}
        />
        <button className="bg-blue-500 text-white px-4 rounded" onClick={checkUrl}>
          Check URL
        </button>
        <button className="bg-green-500 text-white px-4 rounded" onClick={exportJSON}>
          Export JSON
        </button>
        <button className="bg-green-700 text-white px-4 rounded" onClick={exportCSV}>
          Export CSV
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
            <tr key={idx} className={entry.isPhishing ? 'bg-red-50' : 'bg-green-50'}>
              <td className="border px-2 py-1 align-top">{entry.url}</td>
              <td className="border px-2 py-1 align-top">
                {entry.isPhishing ? (
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
                      <p>Age: {entry.whois.age_days ?? 'N/A'} days</p>
                      {entry.whois.is_suspicious ? (
                        renderReasons(['Domain is less than 30 days old'])
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
                        entry.ssl.is_not_valid_yet && 'Certificate not yet valid'
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
                        renderReasons(['Domain uses Dynamic-DNS provider'])
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
                  <div>
                    <h4 className="font-semibold">ML Model</h4>
                    {entry.ml_model ? (
                      entry.ml_model.error ? (
                        <p className="text-red-600">Model error: {entry.ml_model.error}</p>
                      ) : (
                        <p>
                          Label: {entry.ml_model.label} | Score: {entry.ml_model.score}%
                          {entry.ml_model.is_suspicious && (
                            <span className="text-red-500 ml-2 font-semibold">(Phishing)</span>
                          )}
                        </p>
                      )
                    ) : (
                      <p>ML analysis not available</p>
                    )}
                  </div>
                </details>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {history.length > 0 && <AnalysisCharts history={history} />}
    </div>
  );
};

export default UrlChecker;
