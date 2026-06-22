"""antivenom — LLM input security engine (prompt injection / corpus poisoning)."""
from antivenom.audit.quarantine import QuarantineStore
from antivenom.core.chunk import Chunk
from antivenom.core.config import ScannerConfig
from antivenom.core.exceptions import AntiVenomError, ConfigError, DetectionError, LayerError
from antivenom.core.finding import Finding, Technique
from antivenom.core.report import RiskReport
from antivenom.core.result import LayerResult, ScanResult, Severity
from antivenom.core.scanner import AntiVenomScanner
from antivenom.rules.registry import RuleRegistry

__version__ = "0.5.0"

__all__ = [
    "__version__",
    "AntiVenomScanner",
    "Chunk",
    "ScannerConfig",
    "ScanResult",
    "LayerResult",
    "Severity",
    "Finding",
    "Technique",
    "RiskReport",
    "AntiVenomError",
    "ConfigError",
    "DetectionError",
    "LayerError",
    "QuarantineStore",
    "RuleRegistry",
]
