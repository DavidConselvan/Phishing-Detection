import csv
from pathlib import Path
from typing import List, Dict, Tuple
from urllib.parse import urlparse
import Levenshtein


class BrandService:
    def __init__(
        self,
        csv_path: Path = None,
        similarity_threshold: int = 2,
        max_suggestions: int = 3
    ):
        # 1) Locate the top-50k CSV
        if csv_path is None:
            csv_path = Path(__file__).parent.parent / "core" / "top-50k.csv"

        if not csv_path.exists():
            raise FileNotFoundError(f"Brand CSV not found at {csv_path!r}")

        # 2) Load known domains
        with csv_path.open(newline="", encoding="utf8") as f:
            reader = csv.reader(f)
            headers = next(reader)
            if not headers[0].lower().startswith("rank"):
                f.seek(0)
                reader = csv.reader(f)

            self.known_domains: List[str] = [row[1].strip().lower() for row in reader]

        # 3) Extract unique second-level labels (e.g., "google" from "google.com")
        self.known_labels: List[str] = list({
            domain.split(".", 1)[0] for domain in self.known_domains
        })

        self.threshold = similarity_threshold
        self.max_suggestions = max_suggestions

        # 4) Domains we don't analyze
        self.ignored_domains = {
            "example.com", "example.org", "example.net",
            "test.com", "test.org", "test.net",
            "localhost", "127.0.0.1"
        }

        # 5) Optional whitelist of fully trusted domains (always safe)
        self.whitelisted_domains = {
            "google.com", "google.com.br", "www.google.com", "www.google.com.br",
            "facebook.com", "microsoft.com", "apple.com", "amazon.com",
            "netflix.com", "spotify.com"
        }

    def _get_domain(self, url: str) -> str:
        return urlparse(url).netloc.lower()

    def _get_significant_labels(self, domain: str) -> List[str]:
        """Extract meaningful labels from a domain, ignoring common subdomains."""
        ignored = {"www", "mail", "login", "ftp"}
        return [label for label in domain.split(".") if label not in ignored and len(label) > 2]

    def check_similarity(self, url: str) -> Dict:
        target_domain = self._get_domain(url)

        # 1) Ignore if in known top-50k domains (safe)
        if target_domain in self.known_domains:
            return {
                "is_suspicious": False,
                "reasons": [],
                "similar_brands": [],
                "target_domain": target_domain
            }

        # 2) Ignore if explicitly whitelisted
        if target_domain in self.whitelisted_domains:
            return {
                "is_suspicious": False,
                "reasons": [],
                "similar_brands": [],
                "target_domain": target_domain
            }

        # 3) Ignore internal/test domains
        if target_domain in self.ignored_domains:
            return {
                "is_suspicious": False,
                "reasons": [],
                "similar_brands": [],
                "target_domain": target_domain
            }

        # 4) Fuzzy-match on significant labels
        labels = self._get_significant_labels(target_domain)
        candidates: List[Tuple[str, int]] = []

        for label in labels:
            tlen = len(label)
            for known_label in self.known_labels:
                if abs(len(known_label) - tlen) > self.threshold:
                    continue
                dist = Levenshtein.distance(label, known_label)
                if 0 < dist <= self.threshold:
                    candidates.append((known_label, dist))

        # 5) Sort by similarity and limit suggestions
        candidates.sort(key=lambda x: x[1])
        suggestions = candidates[:self.max_suggestions]

        # 6) Format result
        reasons = [
            f"Label similar to “{label}” (distance={dist})"
            for label, dist in suggestions
        ]
        similar_brands = [
            {"label": label, "distance": dist}
            for label, dist in suggestions
        ]

        return {
            "is_suspicious": bool(similar_brands),
            "reasons": reasons,
            "similar_brands": similar_brands,
            "target_domain": target_domain
        }
