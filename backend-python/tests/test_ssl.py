from app.services.ssl_service import SSLService

def test_ssl_checks():
    ssl_service = SSLService()
    
    # Test cases
    test_urls = [
        "https://www.google.com",  
        "https://expired.badssl.com",  
        "https://wrong.host.badssl.com",  
        "https://self-signed.badssl.com",  
        "http://example.com"  
    ]
    
    print("\nTesting SSL Certificate Checks:")
    print("-" * 50)
    
    for url in test_urls:
        print(f"\nTesting URL: {url}")
        result = ssl_service.check_certificate(url)
        
        print(f"Valid: {result.get('is_valid', False)}")
        print(f"Expired: {result.get('is_expired', False)}")
        print(f"Not Valid Yet: {result.get('is_not_valid_yet', False)}")
        print(f"Issuer: {result.get('issuer', 'Unknown')}")
        print(f"Domain Match: {result.get('domain_match', False)}")
        print(f"Suspicious: {result.get('is_suspicious', False)}")
        if result.get('error'):
            print(f"Error: {result.get('error')}")
        print("-" * 50)

if __name__ == "__main__":
    test_ssl_checks() 