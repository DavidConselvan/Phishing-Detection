from transformers import pipeline

class MLModelService:
    def __init__(self):
        self.model = pipeline("text-classification", model="ealvaradob/bert-finetuned-phishing")

    def classify_url(self, url: str):
        try:
            result = self.model(url)[0]
            label = result["label"].lower()
            score = round(result["score"] * 100, 2)
            return {
                "label": label,
                "score": score,
                "is_suspicious": label == "phishing"
            }
        except Exception as e:
            return {
                "label": "error",
                "score": 0,
                "is_suspicious": False,
                "error": str(e)
            }
