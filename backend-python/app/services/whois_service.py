import whois
from datetime import datetime
from typing import Dict, Any

class WhoisService:
    def check_domain(self, domain: str) -> Dict[str, Any]:
        try:
            domain = domain.replace('www.', '')
            w = whois.whois(domain)
            
            if not w.creation_date:
                return {
                    "age_days": None,
                    "creation_date": None,
                    "is_suspicious": False,
                    "error": "No creation date found"
                }
                
            creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            expiration_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
            
            age_days = (datetime.now() - creation_date).days
            
            data = {
                "age_days": age_days,
                "creation_date": str(creation_date),
                "is_suspicious": age_days < 30,
                "registrar": w.registrar,
                "expiration_date": str(expiration_date) if expiration_date else None,
                "organization": w.org,
                "country": w.country
            }
            # print(f"WHOIS data for {domain}:", data)
            # print("--------------------------------")
            return data
            
        except Exception as e:
            # print(f"Error checking WHOIS: {str(e)}")
            return {
                "age_days": None,
                "creation_date": None,
                "is_suspicious": False,
                "error": str(e)
            } 