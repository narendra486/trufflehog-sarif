from __future__ import annotations

import argparse
import json
import hashlib
import sys
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional

SARIF_SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"


def _normalize_key(value: str) -> str:
    """Normalize keys for loose matching (case-insensitive, ignore separators)."""
    return "".join(ch for ch in value.lower() if ch not in {"_", "-", " "})


def _case_insensitive_get(mapping: Mapping[str, Any], key: str) -> Any:
    """Return a value from a mapping matching the key (case-insensitive, separator-insensitive)."""
    target = _normalize_key(key)
    for actual_key, value in mapping.items():
        if _normalize_key(str(actual_key)) == target:
            return value
    return None


def _find_in_mapping(mapping: Mapping[str, Any], candidates: Iterable[Iterable[str] | str]) -> Any:
    """Search for the first matching key path in the mapping."""
    for candidate in candidates:
        if isinstance(candidate, str):
            candidate = (candidate,)

        value: Any = mapping
        for key in candidate:
            if not isinstance(value, Mapping):
                value = None
                break
            value = _case_insensitive_get(value, key)
            if value is None:
                break
        if value is not None:
            return value
    return None


def parse_trufflehog_output(raw: str) -> List[Dict[str, Any]]:
    """Parse TruffleHog JSON or NDJSON output into a list of findings."""
    cleaned = raw.strip()
    if not cleaned:
        return []

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        findings: List[Dict[str, Any]] = []
        for idx, line in enumerate(raw.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:  # pragma: no cover - error path tested elsewhere
                raise ValueError(f"Invalid JSON on line {idx}: {exc}") from exc
            if not isinstance(obj, MutableMapping):
                raise ValueError(f"Unexpected JSON object on line {idx}: {type(obj)!r}")
            findings.append(dict(obj))
        if not findings:
            raise ValueError("No JSON objects found in input")
        return findings

    if isinstance(parsed, list):
        return [dict(item) for item in parsed]  # ensure mutable copies
    if isinstance(parsed, dict):
        return [dict(parsed)]
    raise ValueError(f"Unexpected JSON root type: {type(parsed)!r}")


def _extract_path_and_line(finding: Mapping[str, Any]) -> tuple[Optional[str], Optional[int]]:
    """Extract file path and line number from various TruffleHog schemas."""
    path_candidates: tuple[Iterable[str] | str, ...] = (
        "path",
        "file",
        "filename",
        ("source_metadata", "data", "git", "file"),
        ("source_metadata", "data", "git", "path"),
        ("source_metadata", "path"),
        ("source", "path"),
        ("extra_data", "file"),
        ("extra", "file"),
    )
    line_candidates: tuple[Iterable[str] | str, ...] = (
        "line",
        "line_number",
        "startline",
        ("region", "startLine"),
        ("extra_data", "line"),
        ("source_metadata", "data", "git", "line"),
    )

    path = _find_in_mapping(finding, path_candidates)
    line = _find_in_mapping(finding, line_candidates)
    try:
        line_number = int(line) if line is not None else None
    except (TypeError, ValueError):
        line_number = None

    return path, line_number


def _extract_detector(finding: Mapping[str, Any]) -> str:
    detector = _find_in_mapping(
        finding,
        (
            "detector",
            "detector_name",
            "detectorname",
            "rule",
            "rule_id",
            "ruleid",
            "type",
            "category",
        ),
    )
    return str(detector or "TruffleHog Finding")


def _extract_commit_info(finding: Mapping[str, Any]) -> Dict[str, Any]:
    commit_info = _find_in_mapping(
        finding,
        (
            ("commit",),
            ("extra_data", "commit"),
            ("source_metadata", "data", "git", "commit"),
        ),
    )

    if not isinstance(commit_info, Mapping):
        return {}

    return {
        key: _case_insensitive_get(commit_info, key)
        for key in ("hash", "message", "date", "author", "email")
        if _case_insensitive_get(commit_info, key) is not None
    }


def _build_message(detector: str, finding: Mapping[str, Any]) -> str:
    redacted = _find_in_mapping(finding, ("redacted", "Redacted"))
    if redacted:
        return f"Potential secret detected by {detector}: {redacted}"
    raw = _find_in_mapping(finding, ("raw", "Raw"))
    if raw:
        snippet = str(raw)[:80]
        if len(str(raw)) > 80:
            snippet = f"{snippet}..."
        return f"Potential secret detected by {detector}: {snippet}"
    return f"Potential secret detected by {detector}"


def convert_to_sarif(
    findings: Iterable[Mapping[str, Any]],
    tool_name: str = "TruffleHog",
    tool_version: Optional[str] = None,
) -> Dict[str, Any]:
    """Convert TruffleHog findings into SARIF 2.1.0 format."""
    results: List[Dict[str, Any]] = []
    rules: Dict[str, Dict[str, Any]] = {}

    for finding in findings:
        detector = _extract_detector(finding)
        path, line = _extract_path_and_line(finding)

        properties: Dict[str, Any] = {}
        redacted = _find_in_mapping(finding, ("redacted", "Redacted"))
        raw = _find_in_mapping(finding, ("raw", "Raw"))
        if redacted is not None:
            properties["redacted"] = redacted
        if raw is not None:
            properties["raw"] = raw

        verified = _find_in_mapping(finding, ("verified", "is_verified"))
        if verified is not None:
            properties["verified"] = bool(verified)

        source_id = _find_in_mapping(finding, ("source_id", "sourceid"))
        source_type = _find_in_mapping(finding, ("source_type", "sourcetype"))
        if source_id or source_type:
            properties["source"] = {
                "id": source_id,
                "type": source_type,
            }

        commit_info = _extract_commit_info(finding)
        if commit_info:
            properties["commit"] = commit_info

        message_text = _build_message(detector, finding)

        result: Dict[str, Any] = {
            "ruleId": detector,
            "message": {"text": message_text},
        }

        if properties:
            result["properties"] = properties

        if path:
            physical_location: Dict[str, Any] = {
                "artifactLocation": {"uri": str(path)},
            }
            if line:
                physical_location["region"] = {"startLine": line}
            result["locations"] = [{"physicalLocation": physical_location}]

        # Stable fingerprints help code scanning platforms track or re-surface alerts.
        base_fingerprint = "|".join(
            str(part)
            for part in (
                detector,
                path or "",
                line or "",
                redacted or raw or "",
                commit_info.get("hash", ""),
            )
        )
        digest = hashlib.sha256(base_fingerprint.encode()).hexdigest()
        result["fingerprints"] = {"trufflehogHash": digest}
        result["partialFingerprints"] = {"uniqueId": digest}

        results.append(result)

        if detector not in rules:
            rules[detector] = {
                "id": detector,
                "name": detector,
                "shortDescription": {"text": f"Findings reported by {detector}"},
            }

    sarif: Dict[str, Any] = {
        "$schema": SARIF_SCHEMA_URL,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        **({"version": tool_version} if tool_version else {}),
                        **({"rules": list(rules.values())} if rules else {}),
                    }
                },
                "results": results,
            }
        ],
    }
    return sarif


def _read_input(path: Optional[str]) -> str:
    if not path or path == "-":
        return sys.stdin.read()
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"Input file not found: {path}") from exc


def _write_output(path: Optional[str], sarif_obj: Mapping[str, Any]) -> None:
    serialized = json.dumps(sarif_obj, indent=2)
    if not path or path == "-":
        sys.stdout.write(serialized + "\n")
        return
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(serialized)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trufflehog-sarif",
        description="Convert TruffleHog JSON output into SARIF 2.1.0.",
    )
    parser.add_argument(
        "-i",
        "--input",
        default="-",
        help="Path to TruffleHog JSON output (use '-' or omit to read stdin).",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="-",
        help="Path to write SARIF (use '-' or omit to write to stdout).",
    )
    parser.add_argument(
        "--tool-name",
        default="TruffleHog",
        help="Override SARIF tool.driver.name (default: TruffleHog).",
    )
    parser.add_argument(
        "--tool-version",
        default=None,
        help="Optional SARIF tool.driver.version value.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> None:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        raw_input = _read_input(args.input)
        findings = parse_trufflehog_output(raw_input)
        sarif = convert_to_sarif(
            findings=findings,
            tool_name=args.tool_name,
            tool_version=args.tool_version,
        )
        _write_output(args.output, sarif)
    except Exception as exc:  # pragma: no cover - CLI error handling
        parser.exit(status=1, message=f"Error: {exc}\n")


if __name__ == "__main__":  # pragma: no cover
    main()
