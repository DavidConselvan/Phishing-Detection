import { useState } from 'react';
import { UrlValidator } from '../services/urlValidator';
import type { UrlCheckResult } from '../services/urlValidator';

export function UrlChecker() {
  const [url, setUrl] = useState('');
  const [results, setResults] = useState<UrlCheckResult[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [validFormat, setValidFormat] = useState(true);

  const checkUrl = async (url: string) => {
    setIsLoading(true);
    try {
      // 1. Run local checks
      const localResult = await UrlValidator.checkUrl(url);
      let reasons = [...localResult.reasons];
      let isSafe = localResult.isSafe;

      // 2. Call backend for PhishTank check
      let phishtankError = false;
      try {
        const response = await fetch('http://localhost:3001/api/check-phishing', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url }),
        });
        const data = await response.json();

        if (data.isPhishing) {
          reasons.push('URL found in PhishTank database');
          isSafe = false;
        } else {
          reasons.push('URL not found in PhishTank database');
        }
      } catch (error) {
        reasons.push('Could not check PhishTank (service unavailable)');
        phishtankError = true;
      }

      setResults(prev => [
        {
          url,
          isSafe,
          reasons,
          phishtankError,
        },
        ...prev,
      ]);
    } catch (error) {
      setResults(prev => [
        {
          url,
          isSafe: false,
          reasons: ['Error checking PhishTank'],
        },
        ...prev,
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (url) {
      if (!UrlValidator.isValidUrl(url)) {
        setValidFormat(false);
        return;
      } else {
        setValidFormat(true);
      }
      checkUrl(url);
      setUrl('');
    }
  };

  return (
    <div className="max-w-4xl mx-auto p-4">
      <h1 className="text-3xl font-bold text-center mb-8">URL Phishing Checker</h1>
      
      <form onSubmit={handleSubmit} className="mb-8">
        <div className="flex flex-row gap-2 items-end h-full">
          <input
            type="text"
            value={url}
            onChange={(e) => {
              setUrl(e.target.value);
              setValidFormat(UrlValidator.isValidUrl(e.target.value));
            }}
            placeholder="https://example.com"
            className="p-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 w-full h-10"
            required
          />
          <button
            type="submit"
            disabled={isLoading || !validFormat}
            className="h-10 px-4 bg-blue-500 hover:bg-blue-600 disabled:bg-gray-300 disabled:text-gray-300 text-white rounded-lg flex items-center justify-center text-sm font-medium"
          >
            {isLoading ? 'Checking...' : 'Check URL'}
          </button>
        </div>
        <p className={`text-sm px-2 mt-1 ${validFormat ? 'text-green-600' : 'text-red-500'}`}>
          {validFormat ? '' : 'Invalid URL format'}
        </p>
      </form>

      <div className="overflow-x-auto">
        <table className="min-w-full bg-white border rounded-lg">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">URL</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {results.map((result, index) => (
              <tr key={index}>
                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{result.url}</td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                    result.isSafe ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                  }`}>
                    {result.isSafe ? 'Safe' : 'Suspicious'}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm text-gray-500">
                  <ul className="list-disc list-inside">
                    {result.reasons.map((reason, i) => (
                      <li
                        key={i}
                        className={
                          reason.includes('Could not check PhishTank')
                            ? 'text-yellow-600 font-semibold'
                            : ''
                        }
                      >
                        {reason}
                      </li>
                    ))}
                  </ul>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
} 