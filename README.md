# TruffleHog-SARIF

Convert TruffleHog `--json` output into SARIF 2.1.0 so findings can be pushed into GitHub Code Scanning or any SARIF-compatible platform.

## Features
- Reads TruffleHog JSON (array or NDJSON) and produces valid SARIF 2.1.0.
- CLI works locally or inside Docker with `trufflehog-sarif`.
- Accepts stdin/stdout for piping or file paths for batch jobs; CI-friendly.
- Adds contextual properties (redacted secret, commit metadata, verification flag) to SARIF results.
- Bundles the SARIF 2.1.0 schema (`src/trufflehog_sarif/sarif-2.1.0.json`) for offline validation; update from schema store when a new SARIF version is released.

## Install & Run (local)
```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

Run the converter:
```bash
# Read TruffleHog JSON from a file
trufflehog-sarif --input trufflehog.json --output trufflehog.sarif

# Or pipe directly from a scan
trufflehog --json --no-update . | trufflehog-sarif --output trufflehog.sarif
```

CLI options:
- `-i, --input` path to TruffleHog JSON (use `-` or omit for stdin)
- `-o, --output` path for SARIF output (use `-` or omit for stdout)
- `--tool-name` and `--tool-version` override SARIF tool metadata

## Docker
Build locally:
```bash
docker build -t trufflehog-sarif .
```

Convert a report:
```bash
docker run --rm -v "$(pwd)":/data trufflehog-sarif \
  --input /data/trufflehog.json \
  --output /data/trufflehog.sarif
```

Pipe directly:
```bash
trufflehog --json --no-update . | docker run --rm -i trufflehog-sarif > trufflehog.sarif
```

If a newer SARIF schema is published, refresh the bundled copy:
```bash
curl -L https://json.schemastore.org/sarif-2.1.0.json -o src/trufflehog_sarif/sarif-2.1.0.json
```

## Example GitHub Code Scanning upload
```bash
gh code-scanning upload --sarif=trufflehog.sarif --category="trufflehog-secrets"
```

## Testing
```bash
pytest
```

## How it maps TruffleHog → SARIF
- `ruleId`: TruffleHog detector/rule name.
- `message.text`: human-friendly message (prefers redacted secret).
- `locations[].physicalLocation.artifactLocation.uri`: file path when present.
- `locations[].physicalLocation.region.startLine`: line number when present.
- `properties`: commit hash/message/date (if available), redacted/raw secret, verification flag, and source metadata.

## References
- TruffleHog: https://github.com/trufflesecurity/trufflehog
- SARIF 2.1.0 spec: https://github.com/oasis-tcs/sarif-spec
- Project repo: https://github.com/narendra486/trufflehog-sarif

## License
MIT
