import requests
import tldextract
from urllib.parse import urljoin, urlparse, quote
from typing import List, Dict, Set

class RedirectService:
    def __init__(self):
        self.max_redirects = 5
        self.session = requests.Session()
        self.suspicious = {
            "bit.ly", "tinyurl.com", "goo.gl", "t.co",  
            "freehosting.com", "000webhost.com",  
            "herokuapp.com", "netlify.app", "vercel.app"  
        }
        
        # Domains that commonly use multiple redirects for legitimate purposes
        self.legitimate_auth_domains = {
            'accounts.google.com',
            'login.microsoftonline.com',
            'login.live.com',
            'appleid.apple.com',
            'auth.amazon.com',
            'facebook.com',
            'accounts.spotify.com',
            'login.nubank.com.br',
            'login.itau.com.br',
            'login.bradesco.com.br',
            'login.bb.com.br',
            'login.caixa.gov.br'
        }

    def _registered(self, hostname: str) -> str:
        ext = tldextract.extract(hostname)
        return f"{ext.domain}.{ext.suffix}"

    def _is_www_redirect(self, domain1: str, domain2: str) -> bool:
        d1 = domain1.lower()
        d2 = domain2.lower()
        if d1.startswith('www.'):
            d1 = d1[4:]
        if d2.startswith('www.'):
            d2 = d2[4:]
        return d1 == d2

    def _is_auth_flow(self, url: str) -> bool:
        """Check if the URL is part of a legitimate authentication flow."""
        domain = urlparse(url).netloc.lower()
        return domain in self.legitimate_auth_domains

    def _clean_url(self, url: str) -> str:
        url = url.strip()
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{quote(parsed.path)}{'?' + quote(parsed.query) if parsed.query else ''}{'#' + quote(parsed.fragment) if parsed.fragment else ''}"

    def check_redirects(self, url: str) -> Dict:
        chain, domains = [], set()
        current = self._clean_url(url)
        is_auth_flow = self._is_auth_flow(current)

        try:
            for _ in range(self.max_redirects):
                chain.append(current)
                dom = urlparse(current).netloc.lower()
                domains.add(dom)

                resp = self.session.head(current, allow_redirects=False, timeout=3)
                if not (300 <= resp.status_code < 400):
                    break

                loc = resp.headers.get("Location")
                if not loc:
                    resp = self.session.get(current, allow_redirects=False, timeout=3)
                    loc = resp.headers.get("Location")
                if not loc:
                    break

                next_url = loc if loc.startswith(("http://", "https://")) else urljoin(current, loc)
                next_url = self._clean_url(next_url)
                
                if next_url in chain:
                    chain.append(next_url)
                    return {
                        "is_suspicious": True,
                        "reasons": ["Redirect loop detected"],
                        "redirect_chain": chain,
                        "domains_visited": list(domains),
                        "final_url": next_url
                    }

                current = next_url

            final = chain[-1]
            reasons = []

            # Only check number of redirects if it's not an auth flow
            if not is_auth_flow and len(chain) > 3:
                reasons.append(f"Too many redirects ({len(chain)})")

            init_dom = urlparse(url).netloc.lower()
            final_dom = urlparse(final).netloc.lower()
            if final_dom != init_dom and not self._is_www_redirect(init_dom, final_dom):
                # For auth flows, only flag if redirecting to a suspicious domain
                if is_auth_flow:
                    if self._registered(final_dom) in self.suspicious:
                        reasons.append(f"Auth flow redirects to suspicious domain: {final_dom}")
                else:
                    reasons.append(f"Redirects to different domain (from {init_dom} to {final_dom})")

            for domain in domains:
                if self._registered(domain) in self.suspicious:
                    reasons.append(f"Uses suspicious domain: {domain}")

            data = {
                "is_suspicious": bool(reasons),
                "reasons": reasons,
                "redirect_chain": chain,
                "domains_visited": list(domains),
                "final_url": final
            }
            print("redirects data", data)
            print("--------------------------------")
            return data

        except Exception as e:
            print(f"Error checking redirects: {str(e)}")
            return {
                "is_suspicious": True,
                "reasons": [f"Error checking redirects: {str(e)}"],
                "redirect_chain": [url],
                "domains_visited": [urlparse(url).netloc],
                "final_url": url
            } 