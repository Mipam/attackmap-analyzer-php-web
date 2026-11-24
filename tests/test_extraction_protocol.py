"""Extraction-protocol declaration (AR082 / AC-403).

The analyzer pins ``EXTRACTION_PROTOCOL_VERSION = "2.0"`` explicitly so core's
``declared_extraction_protocol()`` reports "2.0" rather than the SDK default.
Plugins written against protocol 1.0 keep loading indefinitely: core lifts
their ``ScanResult`` into the v2 ``ExtractionResult`` container through
``attackmap.extraction.adapters`` (v1 -> v2 -> v1 round trip is lossless).
"""

from pathlib import Path

from attackmap.extraction.adapters import to_extraction_result, to_scan_result
from attackmap.sdk.analyzer_contracts import declared_extraction_protocol

from attackmap_analyzer_php_web import EXTRACTION_PROTOCOL_VERSION, PhpWebAnalyzer

FIXTURES = Path(__file__).parent / "fixtures"


def test_declares_extraction_protocol_2() -> None:
    analyzer = PhpWebAnalyzer()
    assert EXTRACTION_PROTOCOL_VERSION == "2.0"
    assert analyzer.EXTRACTION_PROTOCOL_VERSION == "2.0"
    assert declared_extraction_protocol(analyzer) == "2.0"


def test_v1_payload_still_loads_via_core_adapter() -> None:
    analyzer = PhpWebAnalyzer()
    fixture = FIXTURES / "laravel_like_repo"
    assert analyzer.detect(fixture)
    v1 = analyzer.analyze(fixture)
    lifted = to_extraction_result(v1)
    assert lifted.source_protocol_version == "1.0"
    round_tripped = to_scan_result(lifted)
    assert round_tripped.model_dump() == v1.model_dump()
