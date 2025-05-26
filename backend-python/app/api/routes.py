from fastapi import APIRouter
from app.models.schemas import URLRequest, PhishingCheckResult
from app.services.phishtank_service import PhishTankService
from app.services.whois_service import WhoisService
from app.services.ssl_service import SSLService
from app.services.redirect_service import RedirectService
from app.services.brand_service import BrandService
from app.services.content_service import ContentService
from urllib.parse import urlparse
from app.services.dynamic_dns_service import DynamicDnsService
from app.services.ml_model_service import MLModelService

router = APIRouter()
phishtank_service = PhishTankService()
whois_service = WhoisService()
ssl_service = SSLService()
redirect_service = RedirectService()
brand_service = BrandService()
content_service = ContentService()
dynamic_dns_service = DynamicDnsService()
ml_model_service = MLModelService()
@router.get("/test")
async def test():
    return {"message": "API is working!"}

@router.post("/check-phishing", response_model=PhishingCheckResult)
async def check_phishing(request: URLRequest):
    url = request.url
    domain = urlparse(url).netloc
    
    phishtank_result = phishtank_service.check_url(url)
    whois_result = whois_service.check_domain(domain)
    ssl_result = ssl_service.check_certificate(url)
    redirect_result = redirect_service.check_redirects(url)
    brand_result = brand_service.check_similarity(url)
    content_result = content_service.analyze_content(url)
    ddns_result = dynamic_dns_service.check_domain(domain)
    ml_result = ml_model_service.classify_url(url)

    if not ml_result or ml_result.get("label") == "error":
        ml_result = {
            "label": "error",
            "score": 0,
            "is_suspicious": False,
            "error": "ML model unavailable"
        }

    print("PhishTank:", phishtank_result.get("isPhishing"))
    print("WHOIS:", whois_result.get("is_suspicious"))
    print("SSL:", ssl_result.get("is_suspicious"))
    print("Redirects:", redirect_result.get("is_suspicious"))
    print("Brand:", brand_result.get("is_suspicious"))
    print("Content:", content_result.get("is_suspicious"))
    print("DDNS:", ddns_result.get("is_dynamic_dns"))
    print("ML:", ml_result)

    isPhishing = (
        phishtank_result.get("isPhishing", False) or 
        whois_result.get("is_suspicious", False) or
        ssl_result.get("is_suspicious", False) or
        redirect_result.get("is_suspicious", False) or
        brand_result.get("is_suspicious", False) or
        content_result.get("is_suspicious", False) or
        ddns_result.get("is_dynamic_dns", False) or
        ml_result.get("is_suspicious", False)
    )


    reasons = []

    if phishtank_result.get("isPhishing"):
        reasons.append("URL found in PhishTank database")
    
    if whois_result.get("is_suspicious"):
        reasons.append(f"Domain is less than 30 days old (created: {whois_result.get('creation_date')})")
    
    if ssl_result.get("is_suspicious"):
        if ssl_result.get("is_expired"):
            reasons.append("SSL certificate is expired")
        if ssl_result.get("is_not_valid_yet"):
            reasons.append("SSL certificate is not yet valid")
        if not ssl_result.get("domain_match"):
            reasons.append("SSL certificate domain doesn't match website domain")

    if redirect_result.get("is_suspicious"):
        reasons.extend(redirect_result.get("reasons", []))

    if brand_result.get("is_suspicious"):
        reasons.extend(brand_result.get("reasons", []))

    if content_result.get("is_suspicious"):
        reasons.extend(content_result.get("reasons", []))

    if ddns_result["is_dynamic_dns"]:
         reasons.append(f"Domain uses Dynamic-DNS provider ({ddns_result['domain']})")

    if ml_result.get("is_suspicious"):
        reasons.append(f"ML model flagged this as phishing (score: {ml_result.get('score')})")

    result = PhishingCheckResult(
         url=url,
         isPhishing=isPhishing,
         reasons=reasons,
         phishtank=phishtank_result.get("phishtank"),
         whois=whois_result,
         ssl=ssl_result,
         redirects=redirect_result,
         dynamic_dns=ddns_result,  
         brand_similarity=brand_result,
         content_analysis=content_result,
         ml_model=ml_result
     )
    # print("Result: ", result)
    return result