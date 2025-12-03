# TruffleHog-SARIF

TruffleHog-SARIF is a lightweight CLI tool that converts TruffleHog secret-scan results into **SARIF** (Static Analysis Results Interchange Format).  
This allows you to integrate TruffleHog findings directly into platforms like **GitHub Code Scanning**, Azure DevOps, and other security dashboards.

---

## Features

- Converts TruffleHog JSON output to SARIF
- Distributed as a lightweight Docker image
- CI/CD friendly (GitHub Actions, GitLab CI, Jenkins, etc.)
- Simple and easy-to-use CLI interface
- Generates SARIF 2.1.0 compliant output

---

## Usage

### 1. Run TruffleHog and save output as JSON

```
trufflehog git https://github.com/your-org/your-repo --json > trufflehog.json
```

### 2. Convert JSON → SARIF

#### Using Docker (recommended)

```
docker run --rm   -v $(pwd):/data   youruser/trufflehog-sarif:latest   --input /data/trufflehog.json   --output /data/trufflehog.sarif
```

#### Local Python execution

```
trufflehog-sarif --input trufflehog.json --output trufflehog.sarif
```

---

##  Example GitHub Code Scanning Upload

```
gh code-scanning upload --sarif=trufflehog.sarif --category="trufflehog-secrets"
```

---

##  Docker Image

```
docker pull youruser/trufflehog-sarif:latest
```

Replace **youruser** with your Docker Hub username.
