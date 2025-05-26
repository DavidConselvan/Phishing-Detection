import requests
from bs4 import BeautifulSoup
from typing import Dict, List
from urllib.parse import urlparse, quote

class ContentService:
    def __init__(self):
        # Legitimate domains that should not be flagged for login forms
        self.legitimate_domains = {
            'google.com', 'accounts.google.com', 'gmail.com',
            'microsoft.com', 'outlook.com', 'hotmail.com',
            'apple.com', 'icloud.com',
            'amazon.com', 'amazon.com.br',
            'facebook.com', 'fb.com',
            'netflix.com',
            'spotify.com',
            'nubank.com.br',
            'itau.com.br',
            'bradesco.com.br',
            'santander.com.br',
            'bb.com.br',
            'caixa.gov.br'
        }

        # Domains to ignore in content analysis
        self.ignored_domains = {
            'example.com',
            'example.org',
            'example.net',
            'test.com',
            'test.org',
            'test.net',
            'localhost',
            '127.0.0.1'
        }

        # Sensitive information fields to look for
        self.sensitive_fields = {
            'credit', 'cartão', 'card', 'cc', 'cvv', 'cvc',
            'cpf', 'cnpj', 'document', 'documento', 'id', 'identity',
            'bank', 'banco', 'account', 'conta', 'agency', 'agência',
            'mother', 'mãe', 'father', 'pai', 'birth', 'nascimento',
            'social', 'social security', 'security', 'segurança'
        }

    def _clean_url(self, url: str) -> str:
        """Clean and properly encode the URL."""
        url = url.strip()
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{quote(parsed.path)}{'?' + quote(parsed.query) if parsed.query else ''}{'#' + quote(parsed.fragment) if parsed.fragment else ''}"

    def _is_legitimate_domain(self, url: str) -> bool:
        """Check if the domain is in our list of legitimate domains."""
        domain = urlparse(url).netloc.lower()
        return domain in self.legitimate_domains

    def _should_ignore_domain(self, url: str) -> bool:
        """Check if the domain should be ignored in content analysis."""
        domain = urlparse(url).netloc.lower()
        return domain in self.ignored_domains

    def _fetch_content(self, url: str) -> Dict:
        """Fetch and parse webpage content."""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            clean_url = self._clean_url(url)
            response = requests.get(clean_url, headers=headers, timeout=10)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            return {
                'success': True,
                'soup': soup,
                'forms': soup.find_all('form')
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def _check_forms(self, forms: List, url: str) -> List[str]:
        """Check for login forms and sensitive information requests."""
        reasons = []
        is_legitimate = self._is_legitimate_domain(url)
        
        for form in forms:
            # Only check password fields on non-legitimate domains
            if not is_legitimate:
                password_fields = form.find_all('input', {'type': 'password'})
                if password_fields:
                    reasons.append("Form contains password field")
            
            # Check for sensitive information fields on all domains
            inputs = form.find_all('input')
            for input_field in inputs:
                field_name = input_field.get('name', '').lower()
                if field_name in self.sensitive_fields:
                    reasons.append(f"Form requests sensitive information: {field_name}")

        return reasons

    def analyze_content(self, url: str) -> Dict:
        """
        Basic content analysis to detect login forms and sensitive information requests.
        Returns a dictionary with analysis results.
        """
        # Skip analysis for ignored domains
        if self._should_ignore_domain(url):
            return {
                "is_suspicious": False,
                "reasons": [],
                "suspicious_forms": []
            }

        try:
            # Fetch and parse content
            content = self._fetch_content(url)
            if not content['success']:
                return {
                    "is_suspicious": True,
                    "reasons": [f"Error analyzing content: {content['error']}"],
                    "suspicious_forms": []
                }

            # Check for suspicious forms
            form_reasons = self._check_forms(content['forms'], url)
            
            data = {
                "is_suspicious": bool(form_reasons),
                "reasons": form_reasons,
                "suspicious_forms": form_reasons,
                "suspicious_text": []
            }
            print("content data", data)
            print("--------------------------------")
            return data

        except Exception as e:
            print(f"Error analyzing content: {str(e)}")
            return {
                "is_suspicious": True,
                "reasons": [f"Error analyzing content: {str(e)}"],
                "suspicious_forms": [],
                "suspicious_text": []
            } 