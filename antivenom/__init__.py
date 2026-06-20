"""antivenom — RAG Corpus Poisoning Detector."""
from antivenom.core.chunk import Chunk
from antivenom.core.config import ScannerConfig
from antivenom.core.exceptions import AntiVenomError, ConfigError, DetectionError, LayerError
from antivenom.core.result import LayerResult, ScanResult, Severity
from antivenom.core.scanner import AntiVenomScanner
from antivenom.audit.quarantine import QuarantineStore
from antivenom.rules.registry import RuleRegistry

__version__ = "0.2.0"

__all__ = [
    "__version__",
    "AntiVenomScanner",
    "Chunk",
    "ScannerConfig",
    "ScanResult",
    "LayerResult",
    "Severity",
    "AntiVenomError",
    "ConfigError",
    "DetectionError",
    "LayerError",
    "QuarantineStore",
    "RuleRegistry",
]
