class AntiVenomError(Exception):
    pass

class ConfigError(AntiVenomError):
    pass

class LayerError(AntiVenomError):
    pass

class CacheError(AntiVenomError):
    pass

class QuarantineError(AntiVenomError):
    pass

class DetectionError(AntiVenomError):
    """Raised when on_detection='raise' and a poisoned chunk is found."""
    def __init__(self, message: str, confidence: float, evidence: list[str]) -> None:
        super().__init__(message)
        self.confidence = confidence
        self.evidence = evidence
