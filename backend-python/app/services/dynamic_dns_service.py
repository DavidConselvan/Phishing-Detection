# app/services/dynamic_dns_service.py
from pathlib import Path
from typing import Set, Dict, Any

class DynamicDnsService:
    def __init__(self, links_path: Path = None):
        if links_path is None:
            links_path = (
                Path(__file__)
                .parent       
                .parent       
                / "core"
                / "dyn-dns-list.txt"
            )
        self.domains = self._load_domains(links_path)

    def _load_domains(self, path: Path) -> Set[str]:
        return {
            line.strip().lower()
            for line in path.read_text(encoding="utf8").splitlines()
            if line.strip() and not line.startswith("#")
        }

    def is_dynamic_dns(self, domain: str) -> bool:
        domain = domain.lower().lstrip("www.")
        return any(
            domain == dd or domain.endswith(f".{dd}")
            for dd in self.domains
        )

    def check_domain(self, domain: str) -> Dict[str, Any]:
        is_dd = self.is_dynamic_dns(domain)
        # print("is_dd: ", is_dd)
        return {"is_dynamic_dns": is_dd, "domain": domain}
