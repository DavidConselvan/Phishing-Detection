import csv
from pathlib import Path
from typing import List, Dict
from urllib.parse import urlparse
import Levenshtein

class BrandService:
    def __init__(
        self,
        csv_path: Path = None,
        similarity_threshold: int = 2,
        max_suggestions: int = 3
    ):
        # 1) Locate the “top-50k.csv”
        if csv_path is None:
            csv_path = (
                Path(__file__).parent.parent
                / "core" / "top-50k.csv"
            )
        if not csv_path.exists():
            raise FileNotFoundError(f"Brand CSV not found at {csv_path!r}")

        # 2) Load known domains
        with csv_path.open(newline="", encoding="utf8") as f:
            reader = csv.reader(f)
            headers = next(reader)
            if headers[0].lower().startswith("rank"):
                pass  # header consumed
            else:
                # rewind if no header
                f.seek(0)
                reader = csv.reader(f)

            self.known_domains: List[str] = [row[1].lower() for row in reader]

        # 3) Extract unique second‐level labels
        self.known_labels: List[str] = list({
            domain.split(".", 1)[0]
            for domain in self.known_domains
        })

        self.threshold = similarity_threshold
        self.max_suggestions = max_suggestions

        self.ignored_domains = {
            "example.com", "example.org", "example.net",
            "test.com", "test.org", "test.net",
            "localhost", "127.0.0.1"
        }

    def _get_domain(self, url: str) -> str:
        return urlparse(url).netloc.lower()

    def check_similarity(self, url: str) -> Dict:
        target = self._get_domain(url)

        # 1) Quick ignore
        if target in self.ignored_domains:
            return {"is_suspicious": False, "reasons": [], "similar_brands": [], "target_domain": target}

        # 2) Exact‐match safe
        if target in self.known_domains:
            return {"is_suspicious": False, "reasons": [], "similar_brands": [], "target_domain": target}

        # 3) Work only on the label
        target_label = target.split(".", 1)[0]

        # 4) Fuzzy‐match against labels with length filter
        candidates: List[tuple[str,int]] = []
        tlen = len(target_label)
        for label in self.known_labels:
            if abs(len(label) - tlen) > self.threshold:
                continue
            dist = Levenshtein.distance(target_label, label)
            if 0 < dist <= self.threshold:
                candidates.append((label, dist))

        # 5) Sort and take top-N
        candidates.sort(key=lambda x: x[1])
        suggestions = candidates[: self.max_suggestions]

        # 6) Build return structure
        reasons = [
            f"Label similar to “{label}” (distance={dist})"
            for label, dist in suggestions
        ]
        similar_brands = [
            {"label": label, "distance": dist}
            for label, dist in suggestions
        ]

        result = {
            "is_suspicious": bool(similar_brands),
            "reasons": reasons,
            "similar_brands": similar_brands,
            "target_domain": target
        }
        print("brand data: ", result)
        print("--------------------------------")
        return result
