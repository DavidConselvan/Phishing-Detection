import Levenshtein
from typing import Dict, List
from urllib.parse import urlparse

class BrandService:
    def __init__(self):
        # Known brands and their domains
        self.brands = {
            'google': ['google.com', 'gmail.com'],
            'microsoft': ['microsoft.com', 'outlook.com', 'hotmail.com'],
            'apple': ['apple.com', 'icloud.com'],
            'amazon': ['amazon.com', 'amazon.com.br'],
            'facebook': ['facebook.com', 'fb.com'],
            'netflix': ['netflix.com'],
            'spotify': ['spotify.com'],
            'nubank': ['nubank.com.br'],
            'itau': ['itau.com.br'],
            'bradesco': ['bradesco.com.br'],
            'santander': ['santander.com.br'],
            'bb': ['bb.com.br'],
            'caixa': ['caixa.gov.br']
        }
        
        # Domains to ignore in similarity checks
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

    def _get_domain(self, url: str) -> str:
        """Extract domain from URL."""
        return urlparse(url).netloc.lower()

    def _should_ignore_domain(self, domain: str) -> bool:
        """Check if domain should be ignored in similarity checks."""
        return domain in self.ignored_domains

    def _calculate_similarity(self, domain1: str, domain2: str) -> int:
        """Calculate Levenshtein distance between two domains."""
        return Levenshtein.distance(domain1, domain2)

    def check_similarity(self, url: str) -> Dict:
        """
        Check if the domain is similar to any known brand domains.
        Returns a dictionary with similarity analysis results.
        """
        target_domain = self._get_domain(url)
        
        # Ignore example and test domains
        if self._should_ignore_domain(target_domain):
            return {
                "is_suspicious": False,
                "reasons": [],
                "similar_brands": [],
                "target_domain": target_domain
            }

        similar_brands = []
        reasons = []

        for brand, domains in self.brands.items():
            for domain in domains:
                similarity = self._calculate_similarity(target_domain, domain)
                if similarity <= 3:  # Threshold for similarity
                    similar_brands.append({
                        "brand": brand,
                        "original_domain": domain,
                        "similarity_score": similarity
                    })
                    reasons.append(f"Domain similar to {brand} ({domain}) - similarity score: {similarity}")

        return {
            "is_suspicious": bool(similar_brands),
            "reasons": reasons,
            "similar_brands": similar_brands,
            "target_domain": target_domain
        } 