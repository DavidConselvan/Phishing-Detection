import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, Any

class SSLService:
    def check_certificate(self, url: str) -> Dict[str, Any]:
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    current_time = datetime.now()
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    
                    is_expired = current_time > not_after
                    is_not_valid_yet = current_time < not_before
                    
                    issuer = dict(x[0] for x in cert['issuer'])
                    
                    domain_match = False
                    if 'subjectAltName' in cert:
                        for san in cert['subjectAltName']:
                            if san[0] == 'DNS' and (san[1] == domain or san[1] == f'*.{domain}'):
                                domain_match = True
                                break
                    
                    data = {
                        "is_valid": not (is_expired or is_not_valid_yet),
                        "is_expired": is_expired,
                        "is_not_valid_yet": is_not_valid_yet,
                        "issuer": issuer.get('organizationName', 'Unknown'),
                        "valid_from": not_before.isoformat(),
                        "valid_until": not_after.isoformat(),
                        "domain_match": domain_match,
                        "is_suspicious": is_expired or is_not_valid_yet or not domain_match
                    }
                    print(f"SSL data for {domain}:", data)
                    return data
                    

        except Exception as e:
            print(f"Error checking SSL: {str(e)}")
            return {
                "is_valid": False,
                "error": f"Error checking SSL: {str(e)}",
                "is_suspicious": True
            } 