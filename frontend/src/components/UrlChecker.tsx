import React, { useState, useEffect } from 'react';
import { UrlValidator } from '../services/urlValidator';
import { AnalysisCharts } from './PhishingCharts';
import type { PhishingCheckResult } from '../types/Phishing';


export const UrlChecker: React.FC = () => {
  const [inputUrl, setInputUrl] = useState<string>('');
  const [history, setHistory] = useState<PhishingCheckResult[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [validatorResults, setValidatorResults] = useState<{ [url: string]: string[] }>({});
  const [modalEntry, setModalEntry] = useState<PhishingCheckResult | null>(null);
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
              <p className="text-sm text-gray-400 ml-4">{explanation}</p>
            )}
          </li>
        );
      })}
    </ul>
  );

  React.useEffect(() => {
    if (modalEntry) {
      document.body.classList.add('overflow-hidden');
    } else {
      document.body.classList.remove('overflow-hidden');
    }
    return () => document.body.classList.remove('overflow-hidden');
  }, [modalEntry]);

  return (
    <div className="min-h-screen bg-[#181c25] flex flex-col items-center justify-start py-10">
      <div className="w-full max-w-6xl mx-auto rounded-2xl bg-[#23283a] p-10 shadow-2xl border border-[#232c43]">
        <h1 className="text-5xl font-extrabold mb-10 text-blue-200 text-center tracking-tight">URL Phishing Checker</h1>
        {/* Search bar and buttons at the top */}
        <div className="flex flex-col md:flex-row gap-4 mb-8">
          <input
            type="text"
            className="border border-blue-200 bg-[#232c43] text-gray-700 p-4 flex-grow rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-300 transition"
            placeholder="https://example.com"
            value={inputUrl}
            onChange={e => setInputUrl(e.target.value)}
          />
          <button className="bg-blue-500 hover:bg-blue-600 text-white font-semibold px-6 py-3 rounded-lg shadow transition" onClick={checkUrl}>
            Check URL
          </button>
          <button className="bg-yellow-400 hover:bg-yellow-500 text-gray-900 font-semibold px-6 py-3 rounded-lg shadow transition" onClick={exportJSON}>
            Export JSON
          </button>
          <button className="bg-green-400 hover:bg-green-500 text-gray-900 font-semibold px-6 py-3 rounded-lg shadow transition" onClick={exportCSV}>
            Export CSV
          </button>
        </div>
        {/* Consultations Card */}
        <div className="bg-[#20243a] border border-[#232c43] rounded-xl p-4 w-full max-h-[400px] flex flex-col mb-8 overflow-y-auto">
          <div className="font-bold text-blue-200 text-lg mb-4">Consultation History</div>
          <div className="flex h-[400px] overflow-y-auto min-h-0">
            
            <table className="w-full table-fixed border-collapse bg-[#20243a] rounded-xl">
              <thead>
                <tr className="bg-[#232c43]">
                  <th className="py-4 px-5 text-left font-semibold text-blue-200 text-lg">URL</th>
                  <th className="py-4 px-5 text-left font-semibold text-blue-200 text-lg">Status</th>
                  <th className="py-4 px-5 text-left font-semibold text-blue-200 text-lg">Analysis</th>
                </tr>
              </thead>
              <tbody>
                {history.map((entry, idx) => (
                  <tr key={idx} className={idx % 2 === 0 ? 'bg-[#20243a]' : 'bg-[#232c43]'}>
                    <td className="border-b border-[#232c43] px-5 py-3 align-top text-gray-100 text-base">{entry.url}</td>
                    <td className="border-b border-[#232c43] px-5 py-3 align-top">
                      {entry.isPhishing ? (
                        <span className="text-red-400 font-semibold">Suspicious</span>
                      ) : (
                        <span className="text-blue-400 font-semibold">Safe</span>
                      )}
                    </td>
                    <td className="border-b border-[#232c43] px-5 py-3 align-top">
                      <button
                        className="cursor-pointer font-medium text-blue-300 py-2 outline-none underline"
                        onClick={() => setModalEntry(entry)}
                      >
                        View full analysis
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
        {/* Charts Card below */}
        {history.length > 0 && (
          <div className="bg-[#20243a] border border-[#232c43] rounded-xl p-4 w-full flex-shrink-0 flex flex-col justify-center mb-8">
            <AnalysisCharts history={history} />
          </div>
        )}
        {error && <p className="text-red-400 mt-6 text-center text-lg">{error}</p>}
      </div>
      {/* Modal for full analysis */}
      {modalEntry && (
        <div
          className="fixed inset-0 z-50 overflow-y-auto bg-black bg-opacity-95"
          onClick={() => setModalEntry(null)}
        >
          {}
          <div className="flex min-h-screen items-center justify-center p-4">
            <div
              className="
                relative
                w-full max-w-3xl
                max-h-[90vh] overflow-y-auto
                bg-[#232c43] border border-[#334155]
                rounded-xl p-6
                shadow-2xl
              "
              onClick={e => e.stopPropagation()}
            >
              {/* Close button */}
              <button
                className="absolute top-4 right-4 text-gray-400 hover:text-white text-2xl"
                onClick={() => setModalEntry(null)}
                aria-label="Close"
              >
                &times;
              </button>

              <div className="space-y-6">
                {/* --- ML Model --- */}
                <div>
                  <h4 className="font-semibold text-blue-200 mb-1">Machine Learning Model</h4>
                  <p className="text-gray-300 text-sm mb-1">
                    The machine learning model analyzes the URL and its features using patterns learned from large datasets of phishing and safe websites. It predicts whether the URL is likely to be safe (benign) or suspicious (phishing), and provides a confidence score for its decision.
                  </p>
                  {modalEntry.ml_model ? (
                    modalEntry.ml_model.error ? (
                      <p className="text-red-600">Model error: {modalEntry.ml_model.error}</p>
                    ) : (
                      <div>
                        <p>
                          <span className="font-semibold">Decision:</span>{' '}
                          {modalEntry.ml_model.label === 'phishing' || modalEntry.ml_model.is_suspicious ? (
                            <span className="text-red-400 font-semibold"> Phishing</span>
                          ) : (
                            <span className="text-blue-400 font-semibold"> Benign (Safe)</span>
                          )}
                        </p>
                        <p>
                          <span className="font-semibold">Confidence Score:</span> {modalEntry.ml_model.score}%
                        </p>
                        <p className="text-gray-400 text-xs mt-1">
                          {modalEntry.ml_model.label === 'phishing' || modalEntry.ml_model.is_suspicious
                            ? 'The model detected patterns commonly associated with phishing attacks. Exercise caution with this URL.'
                            : 'The model did not detect suspicious patterns. This URL is likely safe, but always verify before entering sensitive information.'}
                        </p>
                      </div>
                    )
                  ) : (
                    <p>ML analysis not available</p>
                  )}
                </div>

                {/* --- PhishTank --- */}
                <div>
                  <h4 className="font-semibold text-blue-200 mb-1">PhishTank</h4>
                  {modalEntry.phishtank?.in_database && modalEntry.phishtank.valid ? (
                    renderReasons(['URL found in PhishTank database'])
                  ) : (
                    <p className="text-gray-300">Not listed in PhishTank</p>
                  )}
                </div>

                {/* --- WHOIS --- */}
                <div>
                  <h4 className="font-semibold text-blue-200 mb-1">WHOIS</h4>
                  <p className="text-gray-300">Age: {modalEntry.whois.age_days ?? 'N/A'} days</p>
                  {modalEntry.whois.is_suspicious ? (
                    renderReasons(['Domain is less than 30 days old'])
                  ) : (
                    <p className="text-gray-300">Domain age OK</p>
                  )}
                </div>

                {/* --- SSL --- */}
                <div>
                  <h4 className="font-semibold text-blue-200 mb-1">SSL</h4>
                  <p className="text-gray-300">Valid: {modalEntry.ssl.is_valid ? 'Yes' : 'No'}</p>
                  {!modalEntry.ssl.is_valid &&
                    renderReasons(
                      [
                        !modalEntry.ssl.domain_match && 'Certificate domain mismatch',
                        modalEntry.ssl.is_expired && 'Certificate expired',
                        modalEntry.ssl.is_not_valid_yet && 'Certificate not yet valid',
                      ].filter(Boolean) as string[]
                    )}
                </div>

                {/* --- Redirects --- */}
                <div>
                  <h4 className="font-semibold text-blue-200 mb-1">Redirects</h4>
                  <p className="text-gray-300">
                    Chain: {modalEntry.redirects.redirect_chain.join(' → ')}
                  </p>
                  {modalEntry.redirects.reasons.length > 0 ? (
                    renderReasons(modalEntry.redirects.reasons)
                  ) : (
                    <p className="text-gray-300">No suspicious redirects</p>
                  )}
                </div>

                {/* --- Dynamic DNS --- */}
                <div>
                  <h4 className="font-semibold text-blue-200 mb-1">Dynamic DNS</h4>
                  {modalEntry.dynamic_dns.is_dynamic_dns ? (
                    renderReasons(['Domain uses Dynamic-DNS provider'])
                  ) : (
                    <p className="text-gray-300">No DDNS detected</p>
                  )}
                </div>

                {/* --- Brand Similarity --- */}
                <div>
                  <h4 className="font-semibold text-blue-200 mb-1">Brand Similarity</h4>
                  {modalEntry.brand_similarity.reasons.length > 0 ? (
                    renderReasons(modalEntry.brand_similarity.reasons)
                  ) : (
                    <p className="text-gray-300">No brand-similarity risk detected</p>
                  )}
                </div>

                {/* --- Content Analysis --- */}
                <div>
                  <h4 className="font-semibold text-blue-200 mb-1">Content</h4>
                  {modalEntry.content_analysis.reasons.length > 0 ? (
                    renderReasons(modalEntry.content_analysis.reasons)
                  ) : (
                    <p className="text-gray-300">No suspicious forms or fields detected</p>
                  )}
                </div>

                {/* --- Basic URL Analysis (frontend only) --- */}
                <ModalValidatorAnalysis
                  modalEntry={modalEntry}
                  validatorResults={validatorResults}
                  setValidatorResults={setValidatorResults}
                />
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
export default UrlChecker;
function ModalValidatorAnalysis({ modalEntry, validatorResults, setValidatorResults }: { modalEntry: PhishingCheckResult, validatorResults: { [url: string]: string[] }, setValidatorResults: React.Dispatch<React.SetStateAction<{ [url: string]: string[] }>> }) {
  React.useEffect(() => {
    if (modalEntry && !validatorResults[modalEntry.url]) {
      (async () => {
        const res = await UrlValidator.checkUrl(modalEntry.url);
        setValidatorResults(prev => ({ ...prev, [modalEntry.url]: res.reasons }));
      })();
    }
  }, [modalEntry, validatorResults, setValidatorResults]);

  if (!validatorResults[modalEntry.url]) {
    return <div className="mt-6 text-gray-400">Loading basic URL analysis...</div>;
  }
  return (
    <div className={`mt-6 p-3 rounded border-2 shadow-lg ${modalEntry.isPhishing ? 'bg-red-950/80 border-red-500' : 'bg-blue-950/80 border-blue-500'}`}>
      <h4 className="font-bold text-lg mb-1 text-white">Basic URL Analysis</h4>
      <ul className="list-disc ml-6 text-gray-200">
        {validatorResults[modalEntry.url].length > 0
          ? validatorResults[modalEntry.url].map((reason, idx) => <li key={idx}>{reason}</li>)
          : <li>URL appears safe</li>
        }
      </ul>
    </div>
  );
}
