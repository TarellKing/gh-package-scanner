#!/usr/bin/env python3
"""
gh-package-scanner — Search GitHub for repos using a specific package.
Supply chain defense tool: find who's using a package (and which version).

Usage:
  python scanner.py litellm
  python scanner.py litellm --version 1.35.2
  python scanner.py litellm --version 1.35.2 --output json
  python scanner.py litellm --limit 100
  python scanner.py litellm --files requirements.txt package.json pyproject.toml
"""

import argparse
import base64
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.spinner import Spinner
from rich.text import Text

load_dotenv()

GITHUB_API = "https://api.github.com"

# All supported manifest types — defaults are requirements.txt + package.json
MANIFEST_FILES = [
    "requirements.txt",
    "package.json",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "Pipfile",
    "composer.json",
]
DEFAULT_FILES = ["requirements.txt", "package.json"]

console = Console()


def get_headers() -> dict:
    token = os.getenv("GITHUB_TOKEN")
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    else:
        console.print("[yellow]Warning: GITHUB_TOKEN not set. Rate limit: 10 req/min.[/yellow]")
    return headers


def search_code(query: str, page: int = 1, per_page: int = 30) -> dict | None:
    """Call GitHub Code Search API with retry on rate limit."""
    url = f"{GITHUB_API}/search/code"
    params = {"q": query, "per_page": per_page, "page": page}
    headers = get_headers()

    for attempt in range(4):
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=15)
        except requests.RequestException as e:
            console.print(f"[red]Request error: {e}[/red]")
            return None

        if resp.status_code == 200:
            return resp.json()

        if resp.status_code in (403, 429):
            retry_after = int(resp.headers.get("Retry-After", 60))
            console.print(
                f"[yellow]Rate limited. Waiting {retry_after}s (attempt {attempt+1}/4)...[/yellow]"
            )
            time.sleep(retry_after)
            continue

        if resp.status_code == 422:
            console.print(f"[red]Invalid query: {query}[/red]")
            return None

        console.print(f"[red]API error {resp.status_code}: {resp.text[:200]}[/red]")
        return None

    console.print("[red]Exceeded retry limit.[/red]")
    return None


def fetch_file_content(url: str) -> str | None:
    """Fetch raw file content from GitHub contents API."""
    headers = get_headers()
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("encoding") == "base64":
                return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
    except Exception:
        pass
    return None


def version_in_content(content: str, package: str, version: str) -> bool:
    """Check if package==version appears in a requirements-style file."""
    pkg_pattern = re.escape(package).replace(r"\-", r"[-_]").replace(r"\_", r"[-_]")
    patterns = [
        rf'(?i)^{pkg_pattern}\s*[=~>!<]{{1,2}}\s*{re.escape(version)}',
        rf'(?i)^{pkg_pattern}\s*==\s*{re.escape(version)}',
    ]
    for pat in patterns:
        if re.search(pat, content, re.MULTILINE):
            return True
    return False


def package_in_json_deps(content: str, package: str, version: str | None) -> bool:
    """
    Verify that `package` appears as a dependency key in a JSON manifest
    (package.json, composer.json, etc.) — NOT just as the file's "name" field.
    If version is given, also check that the declared version includes it
    (handles ^, ~, >=, = prefixes common in npm/composer).
    """
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return False

    dep_sections = [
        "dependencies", "devDependencies", "peerDependencies",
        "optionalDependencies", "bundledDependencies", "require", "require-dev",
    ]

    for section in dep_sections:
        deps = data.get(section, {})
        if not isinstance(deps, dict):
            continue
        if package not in deps:
            continue
        # Package is a dependency key — now check version if requested
        if version is None:
            return True
        declared: str = str(deps[package])
        # Strip leading semver range operators to get the base version
        base = re.sub(r'^[\^~>=<! ]+', '', declared).strip()
        # Match if the base version starts with the requested version
        # e.g. declared "^1.35.2" → base "1.35.2" matches requested "1.35.2"
        # e.g. declared "^1.35.0" → base "1.35.0" does NOT match "1.35.2" (different patch)
        if base == version or base.startswith(version + ".") or base.startswith(version + "-"):
            return True
    return False


def _verify_item(entry: dict, package: str, version: str | None, is_json: bool) -> dict | None:
    """Fetch file content and confirm the package is a real dependency. Returns entry or None."""
    contents_url = entry.get("contents_url", "")
    if not contents_url:
        return entry  # can't verify, include as-is
    content = fetch_file_content(contents_url)
    if content is None:
        return entry  # fetch failed, include as-is
    if is_json:
        return entry if package_in_json_deps(content, package, version) else None
    if version:
        return entry if version_in_content(content, package, version) else None
    return entry


def search_manifest(
    package: str,
    version: str | None,
    filename: str,
    limit: int,
    fast: bool = False,
) -> list[dict]:
    """
    Search one manifest file type and return verified matching repo entries.

    Phase 1 — paginate the GitHub Code Search API to collect raw candidates (fast).
    Phase 2 — verify file content in parallel to filter false positives (skipped with fast=True).
    """
    is_json = filename.endswith(".json")
    needs_verify = not fast and (is_json or version is not None)

    if is_json:
        query = f'"{package}" filename:{filename}'
    elif version:
        query = f'"{package}=={version}" filename:{filename}'
    else:
        query = f'"{package}" filename:{filename}'

    # Phase 1: collect raw candidates (no extra API calls per item)
    # Over-fetch when we'll be verifying, since some results will be filtered out
    fetch_limit = min(limit * 4, 200) if needs_verify else limit
    candidates: list[dict] = []
    page = 1
    per_page = 30

    while len(candidates) < fetch_limit:
        data = search_code(query, page=page, per_page=per_page)
        if not data or not data.get("items"):
            break
        for item in data["items"]:
            repo = item["repository"]
            candidates.append({
                "repo":         repo["full_name"],
                "file":         filename,
                "stars":        repo.get("stargazers_count", 0),
                "pushed_at":    repo.get("pushed_at", ""),
                "repo_url":     repo["html_url"],
                "file_url":     item.get("html_url", ""),
                "contents_url": item.get("url", ""),
            })
            if len(candidates) >= fetch_limit:
                break
        total = data.get("total_count", 0)
        if page * per_page >= min(total, 1000):
            break
        page += 1
        time.sleep(0.5)

    if not needs_verify:
        return candidates[:limit]

    # Phase 2: verify content in parallel (8 workers)
    verified: list[dict] = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {
            pool.submit(_verify_item, c, package, version, is_json): c
            for c in candidates
        }
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                verified.append(result)
            if len(verified) >= limit:
                # Cancel remaining futures
                for f in futures:
                    f.cancel()
                break

    return verified[:limit]


def deduplicate(entries: list[dict]) -> list[dict]:
    """Keep one entry per repo+file combo (same repo can appear for multiple file types)."""
    seen: set[tuple] = set()
    result = []
    for entry in entries:
        key = (entry["repo"], entry["file"])
        if key not in seen:
            seen.add(key)
            result.append(entry)
    return result


def format_date(iso: str) -> str:
    if not iso:
        return "—"
    try:
        dt = datetime.fromisoformat(iso.rstrip("Z"))
        return dt.strftime("%Y-%m-%d")
    except Exception:
        return iso[:10]


def print_table(entries: list[dict], package: str, version: str | None) -> None:
    title = f"Repos using [bold cyan]{package}[/bold cyan]"
    if version:
        title += f" [bold yellow]=={version}[/bold yellow]"
    title += f"  ([green]{len(entries)} results[/green])"

    table = Table(title=title, show_lines=True, header_style="bold magenta")
    table.add_column("#", style="dim", justify="right", width=4)
    table.add_column("Repository", style="bold cyan", no_wrap=True)
    table.add_column("File", style="dim", no_wrap=True)
    table.add_column("Stars", justify="right")
    table.add_column("Last Push")
    table.add_column("Link to File")

    for i, e in enumerate(
        sorted(entries, key=lambda x: x.get("stars", 0), reverse=True), 1
    ):
        file_url = e.get("file_url", "")
        repo_url = e.get("repo_url", "")
        # Clickable link: label shows short path, clicking opens the file
        if file_url:
            link_cell = f"[link={file_url}]{file_url}[/link]"
        elif repo_url:
            link_cell = f"[link={repo_url}]{repo_url}[/link]"
        else:
            link_cell = "—"

        table.add_row(
            str(i),
            f"[link={repo_url}]{e['repo']}[/link]" if repo_url else e["repo"],
            e["file"],
            str(e.get("stars", 0)),
            format_date(e.get("pushed_at", "")),
            link_cell,
        )

    console.print(table)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Search GitHub for repos using a Python package (supply chain scanner).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("package", help="Package name to search for (e.g. litellm)")
    parser.add_argument("--version", "-v", help="Exact version to match (e.g. 1.35.2)")
    parser.add_argument(
        "--output", "-o",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument(
        "--limit", "-l",
        type=int,
        default=50,
        help="Max results per manifest file type (default: 50)",
    )
    parser.add_argument(
        "--files", "-f",
        nargs="+",
        choices=MANIFEST_FILES,
        default=DEFAULT_FILES,
        help=f"Manifest files to search (default: {DEFAULT_FILES})",
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Skip content verification (faster, may include false positives)",
    )
    args = parser.parse_args()

    if not os.getenv("GITHUB_TOKEN"):
        console.print(
            "[yellow]Tip: Set GITHUB_TOKEN in .env for 30x higher rate limits.[/yellow]\n"
        )

    console.print(
        f"Scanning GitHub for [bold cyan]{args.package}[/bold cyan]"
        + (f" version [bold yellow]{args.version}[/bold yellow]" if args.version else "")
        + f" across: {', '.join(args.files)}\n"
    )

    all_results: list[dict] = []
    status: dict[str, str] = {f: "searching..." for f in args.files}

    def render_status() -> Text:
        t = Text()
        for fname, state in status.items():
            t.append(f"  {fname}: ", style="dim")
            t.append(state + "\n", style="yellow" if state.endswith("...") else "green")
        return t

    with Live(render_status(), console=console, refresh_per_second=4) as live:
        with ThreadPoolExecutor(max_workers=len(args.files)) as executor:
            futures = {
                executor.submit(
                    search_manifest, args.package, args.version, fname, args.limit, args.fast
                ): fname
                for fname in args.files
            }
            for future in as_completed(futures):
                fname = futures[future]
                try:
                    hits = future.result()
                    status[fname] = f"{len(hits)} hits"
                    all_results.extend(hits)
                except Exception as e:
                    status[fname] = f"error — {e}"
                live.update(render_status())

    deduped = deduplicate(all_results)
    console.print(f"\nTotal unique repos: [bold]{len(deduped)}[/bold]\n")

    if args.output == "json":
        clean = [
            {k: v for k, v in e.items() if k != "contents_url"}
            for e in deduped
        ]
        print(json.dumps(clean, indent=2))
    else:
        print_table(deduped, args.package, args.version)


if __name__ == "__main__":
    main()
