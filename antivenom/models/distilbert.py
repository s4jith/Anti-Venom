from __future__ import annotations

import importlib.util
import os
import threading
from typing import Any


class DistilBertClassifier:
    def __init__(self, model_name_or_path: str = "distilbert-base-uncased") -> None:
        self._model_name_or_path = model_name_or_path
        self._tokenizer: Any = None
        self._model: Any = None
        self._load_lock = threading.Lock()

    @classmethod
    def is_available(cls) -> bool:
        return (
            importlib.util.find_spec("transformers") is not None
            and importlib.util.find_spec("torch") is not None
        )

    def lazy_load(self) -> None:
        if self._model is not None:
            return
        with self._load_lock:
            if self._model is not None:
                return
            if importlib.util.find_spec("transformers") is None:
                raise ImportError(
                    "transformers is required for ClassifierLayer. "
                    "Install with: pip install antivenom[classifier]"
                )
            if importlib.util.find_spec("torch") is None:
                raise ImportError(
                    "torch is required for ClassifierLayer. "
                    "Install with: pip install antivenom[classifier]"
                )
            from transformers import (  # type: ignore[import]
                AutoModelForSequenceClassification,
                AutoTokenizer,
            )
            # Env var override allows pointing at a fine-tuned checkpoint
            checkpoint = os.environ.get("ANTIVENOM_CLASSIFIER_MODEL", self._model_name_or_path)
            tokenizer = AutoTokenizer.from_pretrained(checkpoint)
            model = AutoModelForSequenceClassification.from_pretrained(checkpoint)
            model.eval()
            self._tokenizer = tokenizer
            self._model = model

    def predict(self, text: str) -> tuple[bool, float]:
        import torch  # type: ignore[import]
        self.lazy_load()
        inputs = self._tokenizer(
            text[:512],
            return_tensors="pt",
            truncation=True,
            max_length=512,
            padding=True,
        )
        # Run inference on the model's own device (GPU if available).
        inputs = {k: v.to(self._model.device) for k, v in inputs.items()}
        with torch.no_grad():
            logits = self._model(**inputs).logits
        if logits.shape[-1] == 1:
            # Single-output (regression-style) head: sigmoid on the lone logit.
            prob = float(torch.sigmoid(logits[0, 0]).item())
        else:
            # Multi-class head: softmax, take P(class 1 = injection). Using
            # softmax (not sigmoid on one logit) is what makes the probability
            # calibrated against the other class.
            probs = torch.softmax(logits[0], dim=-1)
            prob = float(probs[1].item())
        return prob >= 0.5, prob
