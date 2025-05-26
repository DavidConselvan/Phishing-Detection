import requests
from typing import Dict, Any

class PhishTankService:
    def __init__(self, api_key: str = ""):
        self.api_key = api_key

    def check_url(self, url: str) -> Dict[str, Any]:
        params = {
            "url": url,
            "format": "json"
        }
        if self.api_key:
            params["app_key"] = self.api_key

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "phishtank/davidconselvan"
        }

        try:
            response = requests.post(
                "https://checkurl.phishtank.com/checkurl/",
                data=params,
                headers=headers,
                timeout=10
            )
            if response.status_code != 200:
                return {
                    "isPhishing": False,
                    "error": f"PhishTank responded with status {response.status_code}"
                }
            
            data = response.json()
            isPhishing = data["results"]["in_database"] and data["results"]["valid"]
            return {
                "isPhishing": data["results"]["in_database"] and data["results"]["valid"],
                "phishtank": data["results"]    # <-- you return only the inner results here
            }

        except Exception as e:
            return {
                "isPhishing": False,
                "error": f"Could not check PhishTank: {str(e)}"
            } 