from __future__ import annotations
import importlib.util
import numpy as np
from typing import Any


class EmbeddingModel:
    """Lazy-loading sentence-transformers wrapper. Requires [semantic] extra."""

    def __init__(self, model_name: str = "all-MiniLM-L6-v2") -> None:
        self._model_name = model_name
        self._model: Any = None

    def _load(self) -> None:
        if self._model is not None:
            return
        if importlib.util.find_spec("sentence_transformers") is None:
            raise ImportError(
                "sentence-transformers is required for the semantic layer. "
                "Install with: pip install antivenom[semantic]"
            )
        from sentence_transformers import SentenceTransformer  # type: ignore[import]
        self._model = SentenceTransformer(self._model_name)

    def embed(self, text: str) -> np.ndarray:
        self._load()
        vec = self._model.encode(text, normalize_embeddings=True, show_progress_bar=False)
        return np.asarray(vec, dtype=np.float32)

    def embed_batch(self, texts: list[str]) -> np.ndarray:
        self._load()
        vecs = self._model.encode(texts, normalize_embeddings=True, show_progress_bar=False, batch_size=32)
        return np.asarray(vecs, dtype=np.float32)

    @property
    def dim(self) -> int:
        self._load()
        return self._model.get_sentence_embedding_dimension()
