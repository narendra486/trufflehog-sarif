"""TruffleHog JSON to SARIF converter."""

from .converter import convert_to_sarif, parse_trufflehog_output

__all__ = ["convert_to_sarif", "parse_trufflehog_output"]
__version__ = "0.1.0"
