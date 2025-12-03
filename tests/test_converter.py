import json

import pytest

from trufflehog_sarif.converter import convert_to_sarif, parse_trufflehog_output


def test_parse_ndjson_multiple_objects():
    finding_one = {"DetectorName": "AWS", "File": "one.py", "Line": 10}
    finding_two = {"detector_name": "Slack", "file": "two.py", "line": 20}
    raw = "\n".join(json.dumps(item) for item in (finding_one, finding_two))

    parsed = parse_trufflehog_output(raw)

    assert len(parsed) == 2
    assert parsed[0]["DetectorName"] == "AWS"
    assert parsed[1]["file"] == "two.py"


def test_convert_to_sarif_maps_fields():
    findings = [
        {
            "DetectorName": "Slack Detector",
            "File": "src/app.py",
            "Line": 42,
            "Redacted": "xoxb-***",
            "Raw": "xoxb-real-token",
            "Verified": False,
            "SourceID": "git",
            "SourceType": "repository",
            "SourceMetadata": {
                "Data": {
                    "Git": {
                        "Commit": {
                            "Hash": "abc123",
                            "Message": "add token",
                            "Date": "2024-01-01",
                        }
                    }
                }
            },
        }
    ]

    sarif = convert_to_sarif(findings, tool_name="TH", tool_version="3.0.0")
    run = sarif["runs"][0]

    assert sarif["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "TH"
    assert run["tool"]["driver"]["version"] == "3.0.0"

    result = run["results"][0]
    assert result["ruleId"] == "Slack Detector"
    assert result["message"]["text"].startswith("Potential secret detected by Slack Detector")

    location = result["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "src/app.py"
    assert location["region"]["startLine"] == 42

    properties = result["properties"]
    assert properties["redacted"] == "xoxb-***"
    assert properties["raw"] == "xoxb-real-token"
    assert properties["source"]["id"] == "git"
    assert properties["commit"]["hash"] == "abc123"


def test_parse_invalid_json_raises():
    with pytest.raises(ValueError):
        parse_trufflehog_output("not-json")
