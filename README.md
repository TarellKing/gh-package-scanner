# gh-package-scanner

Lightweight CLI tool for searching GitHub to find repositories that depend on a specific package — and optionally a specific version. Built for supply chain attack defense.

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

cp .env.example .env
# edit .env and set GITHUB_TOKEN=ghp_...
```

A GitHub token is strongly recommended — unauthenticated requests hit GitHub's rate limit almost immediately (10 req/min vs 30/min authenticated, and content verification makes extra calls per result).

Generate one at: **GitHub → Settings → Developer Settings → Personal access tokens → Fine-grained** with `Public Repositories (read-only)` scope.

---

## Usage

```
python scanner.py <package> [--version VERSION] [--output table|json] [--limit N] [--files ...]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--version` / `-v` | any | Pin to a specific version |
| `--output` / `-o` | `table` | `table` or `json` |
| `--limit` / `-l` | `50` | Max results per file type |
| `--files` / `-f` | `requirements.txt package.json` | Manifest files to search |

---

## Common Queries

### Find all repos using a package (any version)
```bash
python scanner.py litellm
python scanner.py requests
python scanner.py express
```

### Find repos pinned to a specific vulnerable version
```bash
python scanner.py litellm --version 1.35.2
python scanner.py requests --version 2.28.0
python scanner.py lodash --version 4.17.15
```
> For `package.json` results, this matches exact pins (`"1.35.2"`) and range declarations that include the version (`"^1.35.2"`, `"~1.35.2"`).

### Search only Python manifests
```bash
python scanner.py litellm --files requirements.txt pyproject.toml Pipfile
```

### Search only JavaScript/Node manifests
```bash
python scanner.py axios --files package.json
python scanner.py lodash --version 4.17.20 --files package.json
```

### Cross-ecosystem search (Python + JS + PHP)
```bash
python scanner.py litellm --files requirements.txt package.json pyproject.toml composer.json
```

### Export to JSON for scripting / SIEM ingestion
```bash
python scanner.py litellm --version 1.35.2 --output json > litellm-exposure.json
python scanner.py litellm --output json | jq '.[].repo_url'
```

### Cast a wide net (more results)
```bash
python scanner.py litellm --limit 200
```

### Investigate a typosquatted or malicious package name
```bash
python scanner.py litelm          # one letter off
python scanner.py litellm-dev
python scanner.py litellm-core
```

---

## How It Works

1. Queries the **GitHub Code Search API** for the package name in manifest files
2. Fetches each matched file's content and verifies the package is actually a **dependency** (not just mentioned in comments or the file's own `"name"` field)
3. If a version is specified, confirms the declared version matches after stripping semver operators (`^`, `~`, `>=`)
4. Fetches the full repo metadata for accurate star counts and last-push dates
5. Deduplicates and renders a sorted table (or JSON)

### Supported manifest files

| File | Ecosystem |
|------|-----------|
| `requirements.txt` | Python (pip) |
| `package.json` | JavaScript / Node (npm, yarn) |
| `pyproject.toml` | Python (Poetry, Hatch, PEP 517) |
| `Pipfile` | Python (Pipenv) |
| `setup.py` | Python (legacy) |
| `setup.cfg` | Python (legacy) |
| `composer.json` | PHP (Composer) |

---

## Notes

- GitHub's code search index can lag by hours. A deleted or privatized repo may still appear in results — always verify the link resolves.
- GitHub caps code search at **1,000 results** per query. For very popular packages, narrow the scope with `--version`.
- Content verification makes one extra API call per result to confirm the match. With 50 results across 2 file types, expect ~100+ API calls total.
