#!/usr/bin/env python3
"""Build sing-box rule-sets from RoscomVPN whitelist sources.

The script downloads only whitelist-related files, converts them to the
sing-box source rule-set format, compiles them to .srs with a pinned
sing-box binary and validates the result by decompiling it again.

Outputs:
    dist/geosite.srs   domains  (domain / domain_suffix / domain_keyword / domain_regex)
    dist/geoip.srs     subnets  (ip_cidr)
    dist/manifest.json provenance, counts and SHA-256 checksums
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GEOSITE_REPO = "hydraponique/roscomvpn-geosite"
GEOSITE_REF = "master"
GEOSITE_PATH = "data/whitelist"

GEOIP_REPO = "hydraponique/roscomvpn-geoip"
GEOIP_REF = "release"
GEOIP_PATH = "text/whitelist.txt"

DOMAIN_KEYS = ("domain", "domain_suffix", "domain_keyword", "domain_regex")
SRS_MAGIC = b"SRS"
SRS_VERSION = 3

# Conservative sanity limits: a temporarily broken upstream file must not
# replace a working release with an empty or truncated rule-set.
MIN_DOMAINS = 50
MIN_CIDRS = 500

USER_AGENT = "rkn-whitelist-srs/1.0 (+https://github.com/BranchSeeker/rkn-whitelist-srs)"
DOMAIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$")


class BuildError(RuntimeError):
    """A recoverable build failure with a human-readable message."""


def log(message: str) -> None:
    print(f"[build] {message}", flush=True)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    log("run: " + " ".join(command))
    process = subprocess.run(
        command,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
    )
    if check and process.returncode != 0:
        raise BuildError(
            "command failed with exit code "
            f"{process.returncode}: {' '.join(command)}\n"
            f"stdout:\n{process.stdout}\n"
            f"stderr:\n{process.stderr}"
        )
    return process


def http_get(url: str, *, token: str | None = None, attempts: int = 4) -> bytes:
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if token and url.startswith("https://api.github.com/"):
        headers["Authorization"] = f"Bearer {token}"

    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            request = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(request, timeout=60) as response:
                data = response.read()
            if not data:
                raise BuildError(f"empty response from {url}")
            return data
        except urllib.error.HTTPError as error:
            # Do not waste retries on a definitive client error.
            if error.code in (400, 401, 403, 404, 410):
                raise BuildError(f"HTTP {error.code} for {url}") from error
            last_error = error
        except Exception as error:  # noqa: BLE001 - retried below
            last_error = error

        if attempt < attempts:
            delay = 2 ** (attempt - 1)
            log(f"request failed ({last_error}); retry in {delay}s: {url}")
            time.sleep(delay)

    raise BuildError(f"cannot download {url}: {last_error}")


def resolve_commit(repo: str, ref: str, token: str | None) -> str:
    """Resolve a branch/tag to a full commit SHA.

    GitHub API is preferred because it works on runners without a configured
    git credential helper; git ls-remote is a fallback for rate-limited runs.
    """
    api_error: Exception | None = None
    try:
        payload = json.loads(
            http_get(f"https://api.github.com/repos/{repo}/commits/{ref}", token=token).decode("utf-8")
        )
        sha = payload.get("sha", "")
        if re.fullmatch(r"[0-9a-f]{40}", sha):
            return sha
        api_error = BuildError(f"unexpected commit response for {repo}@{ref}")
    except Exception as error:  # noqa: BLE001 - fallback below
        api_error = error
        log(f"GitHub API failed for {repo}@{ref}: {error}")

    try:
        environment = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="echo")
        process = subprocess.run(
            ["git", "ls-remote", "--exit-code", f"https://github.com/{repo}.git", f"refs/heads/{ref}"],
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            env=environment,
        )
        if process.returncode == 0 and process.stdout.strip():
            sha = process.stdout.split()[0]
            if re.fullmatch(r"[0-9a-f]{40}", sha):
                return sha
        raise BuildError(process.stderr.strip() or f"git ls-remote failed for {repo}@{ref}")
    except Exception as error:  # noqa: BLE001 - report both failures
        raise BuildError(f"cannot resolve {repo}@{ref}: API={api_error}; git={error}") from error


def looks_like_html(data: bytes) -> bool:
    head = data[:4096].lstrip().lower()
    return head.startswith(b"<!doctype html") or head.startswith(b"<html") or b"<html" in head[:512]


def fetch_source(
    repo: str,
    ref: str,
    path: str,
    *,
    token: str | None,
    expected_kind: str,
) -> dict[str, Any]:
    commit = resolve_commit(repo, ref, token)
    url = f"https://raw.githubusercontent.com/{repo}/{commit}/{path}"
    log(f"download {repo}@{ref} ({commit[:12]}) {path}")
    data = http_get(url)
    if looks_like_html(data):
        raise BuildError(f"{url} returned HTML instead of a plain-text list")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise BuildError(f"{url} is not valid UTF-8: {error}") from error

    lines = sum(1 for line in text.splitlines() if line.strip())
    log(f"downloaded {len(data)} bytes, {lines} non-empty lines ({expected_kind})")

    return {
        "repo": repo,
        "ref": ref,
        "commit": commit,
        "path": path,
        "url": url,
        "sha256": sha256_bytes(data),
        "bytes": len(data),
        "text": text,
    }


def clean_line(raw: str) -> str:
    """Strip BOM, comments and v2fly attributes from one list line."""
    line = raw.strip().lstrip("\ufeff")
    if not line:
        return ""
    if line.startswith("#") or line.startswith("//"):
        return ""

    # Inline comments only when preceded by whitespace; this keeps regexes
    # such as "regexp:^https?://" intact.
    for marker in (" #", "\t#", " //", "\t//"):
        index = line.find(marker)
        if index != -1:
            line = line[:index]

    # v2fly attributes, e.g. "domain:example.com @cn".
    line = re.sub(r"\s+@.*$", "", line)
    return line.strip()


def normalize_domain(value: str, *, allow_wildcard: bool = False) -> str | None:
    value = value.strip().lower().rstrip(".")
    if value.startswith("*."):
        if not allow_wildcard:
            return None
        value = value[2:]
    elif "*" in value:
        return None

    value = value.lstrip(".")
    if not value:
        return None

    if any(ord(character) > 127 for character in value):
        try:
            value = value.encode("idna").decode("ascii")
        except UnicodeError:
            return None

    if len(value) > 253 or not DOMAIN_RE.fullmatch(value):
        return None

    labels = value.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        for label in labels
    ):
        return None
    return value


def normalize_keyword(value: str) -> str | None:
    value = value.strip().lower().lstrip(".").rstrip(".")
    if not value or any(character.isspace() for character in value):
        return None
    return value


def normalize_regex(value: str) -> str | None:
    value = value.strip()
    if not value:
        return None
    try:
        re.compile(value)
    except re.error:
        return None
    return value


def parse_geosite(
    text: str, *, min_domains: int = MIN_DOMAINS
) -> tuple[dict[str, list[str]], dict[str, Any], dict[str, int]]:
    buckets: dict[str, set[str]] = {key: set() for key in DOMAIN_KEYS}
    stats: Counter[str] = Counter()
    unknown: Counter[str] = Counter()

    for raw in text.splitlines():
        stats["lines"] += 1
        line = clean_line(raw)
        if not line:
            stats["blank_or_comment"] += 1
            continue

        lowered = line.lower()
        if lowered.startswith("include:"):
            stats["include_skipped"] += 1
            continue

        if lowered.startswith("full:"):
            stats["full"] += 1
            domain = normalize_domain(line[5:])
            key = "domain"
        elif lowered.startswith("domain:"):
            stats["domain"] += 1
            domain = normalize_domain(line[7:], allow_wildcard=True)
            key = "domain_suffix"
        elif lowered.startswith("keyword:"):
            stats["keyword"] += 1
            domain = normalize_keyword(line[8:])
            key = "domain_keyword"
        elif lowered.startswith("regexp:"):
            stats["regexp"] += 1
            domain = normalize_regex(line[7:])
            key = "domain_regex"
        elif re.match(r"^[a-z0-9_-]+:", lowered):
            prefix = lowered.split(":", 1)[0]
            unknown[prefix] += 1
            stats["unknown_directive"] += 1
            continue
        else:
            stats["plain"] += 1
            domain = normalize_domain(line, allow_wildcard=True)
            key = "domain_suffix"

        if domain is None:
            stats["invalid"] += 1
            if stats["invalid"] <= 10:
                log(f"skip invalid domain line: {line!r}")
            continue

        buckets[key].add(domain)
        stats["accepted"] += 1

    total = sum(len(values) for values in buckets.values())
    if total < min_domains:
        raise BuildError(
            f"only {total} domains parsed (minimum {min_domains}); "
            "upstream format may have changed"
        )
    if unknown:
        log(f"ignored unknown directives: {dict(unknown)}")

    rules = {key: sorted(values) for key, values in buckets.items() if values}
    summary = {
        "lines": stats["lines"],
        "accepted": stats["accepted"],
        "skipped": stats["lines"] - stats["accepted"],
        "invalid": stats["invalid"],
        "blank_or_comment": stats["blank_or_comment"],
        "include_skipped": stats["include_skipped"],
        "unknown_directives": dict(unknown),
        "by_prefix": {
            "full": stats["full"],
            "domain": stats["domain"],
            "keyword": stats["keyword"],
            "regexp": stats["regexp"],
            "plain": stats["plain"],
        },
    }
    return rules, summary, dict(unknown)


def parse_cidr(
    text: str, *, min_cidrs: int = MIN_CIDRS
) -> tuple[list[str], dict[str, Any]]:
    networks: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
    stats: Counter[str] = Counter()

    for raw in text.splitlines():
        stats["lines"] += 1
        line = clean_line(raw)
        if not line:
            stats["blank_or_comment"] += 1
            continue
        try:
            network = ipaddress.ip_network(line, strict=False)
        except ValueError:
            stats["invalid"] += 1
            if stats["invalid"] <= 10:
                log(f"skip invalid CIDR line: {line!r}")
            continue
        networks.add(network)
        stats["accepted"] += 1

    if len(networks) < min_cidrs:
        raise BuildError(
            f"only {len(networks)} CIDRs parsed (minimum {min_cidrs}); "
            "upstream format may have changed"
        )

    ordered = sorted(
        networks,
        key=lambda network: (network.version, int(network.network_address), network.prefixlen),
    )
    summary = {
        "lines": stats["lines"],
        "accepted": stats["accepted"],
        "skipped": stats["lines"] - stats["accepted"],
        "invalid": stats["invalid"],
        "blank_or_comment": stats["blank_or_comment"],
        "unique": len(networks),
        "ipv4": sum(1 for network in networks if network.version == 4),
        "ipv6": sum(1 for network in networks if network.version == 6),
    }
    return [str(network) for network in ordered], summary


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def make_domain_source(rules: dict[str, list[str]]) -> dict[str, Any]:
    rule = {key: rules[key] for key in DOMAIN_KEYS if rules.get(key)}
    return {"version": SRS_VERSION, "rules": [rule] if rule else []}


def make_ip_source(cidrs: list[str]) -> dict[str, Any]:
    return {"version": SRS_VERSION, "rules": [{"ip_cidr": cidrs}] if cidrs else []}


def compile_rule_set(sing_box: str, source: Path, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    run([sing_box, "rule-set", "compile", "--output", str(output), str(source)])
    if not output.is_file() or output.stat().st_size < 16:
        raise BuildError(f"sing-box did not create a valid rule-set: {output}")


def read_srs_version(path: Path) -> int:
    header = path.read_bytes()[:4]
    if len(header) < 4 or header[:3] != SRS_MAGIC:
        raise BuildError(f"{path} is not a sing-box SRS file")
    return header[3]


def count_rule_items(payload: dict[str, Any]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for rule in payload.get("rules", []):
        if not isinstance(rule, dict):
            continue
        for key in (*DOMAIN_KEYS, "ip_cidr"):
            value = rule.get(key)
            if isinstance(value, list):
                counts[key] += len(value)
    return counts


def decompile(sing_box: str, srs: Path, output: Path) -> dict[str, Any]:
    if output.exists():
        output.unlink()
    run([sing_box, "rule-set", "decompile", str(srs), "-o", str(output)])
    try:
        return json.loads(output.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BuildError(f"cannot read decompiled rule-set {output}: {error}") from error


def validate_domain_srs(
    sing_box: str,
    srs: Path,
    work: Path,
    expected: dict[str, list[str]],
) -> Counter[str]:
    version = read_srs_version(srs)
    if version != SRS_VERSION:
        raise BuildError(f"{srs.name}: SRS version {version}, expected {SRS_VERSION}")

    payload = decompile(sing_box, srs, work / "geosite.decompiled.json")
    counts = count_rule_items(payload)
    if counts.get("ip_cidr"):
        raise BuildError(f"{srs.name}: domain rule-set contains ip_cidr items")
    actual = sum(counts.get(key, 0) for key in DOMAIN_KEYS)
    wanted = sum(len(values) for values in expected.values())
    if actual == 0:
        raise BuildError(f"{srs.name}: decompiled rule-set has no domain items")
    if actual < wanted * 0.90:
        raise BuildError(
            f"{srs.name}: decompiled {actual} domain items, expected about {wanted}"
        )
    if actual != wanted:
        log(f"note: {srs.name}: {actual} items after compilation, {wanted} before")
    return counts


def validate_ip_srs(
    sing_box: str,
    srs: Path,
    work: Path,
    expected: list[str],
) -> Counter[str]:
    version = read_srs_version(srs)
    if version != SRS_VERSION:
        raise BuildError(f"{srs.name}: SRS version {version}, expected {SRS_VERSION}")

    payload = decompile(sing_box, srs, work / "geoip.decompiled.json")
    counts = count_rule_items(payload)
    domain_items = sum(counts.get(key, 0) for key in DOMAIN_KEYS)
    if domain_items:
        raise BuildError(f"{srs.name}: subnet rule-set contains domain items")

    actual = counts.get("ip_cidr", 0)
    if actual == 0:
        raise BuildError(f"{srs.name}: decompiled rule-set has no ip_cidr items")
    if actual > len(expected):
        raise BuildError(
            f"{srs.name}: decompiled {actual} CIDRs, more than the {len(expected)} inputs"
        )

    compiled_networks = [
        ipaddress.ip_network(value, strict=False)
        for value in _collect_values(payload, "ip_cidr")
    ]
    sample = expected[:: max(1, len(expected) // 10)][:10]
    for value in sample:
        network = ipaddress.ip_network(value, strict=False)
        if not any(
            network.version == candidate.version and network.subnet_of(candidate)
            for candidate in compiled_networks
        ):
            raise BuildError(f"{srs.name}: {value} is not covered by the compiled rule-set")

    if actual < len(expected) * 0.25:
        raise BuildError(
            f"{srs.name}: suspiciously few CIDRs after compilation: {actual} of {len(expected)}"
        )
    if actual != len(expected):
        log(f"note: {srs.name}: {actual} CIDRs after compilation, {len(expected)} before")
    return counts


def _collect_values(payload: dict[str, Any], key: str) -> list[str]:
    values: list[str] = []
    for rule in payload.get("rules", []):
        if isinstance(rule, dict) and isinstance(rule.get(key), list):
            values.extend(str(item) for item in rule[key])
    return values


def sing_box_version(sing_box: str) -> str:
    process = run([sing_box, "version"])
    first_line = process.stdout.splitlines()[0].strip() if process.stdout.strip() else ""
    return first_line or "unknown"


def sidecar(path: Path) -> None:
    path.with_name(path.name + ".sha256").write_text(
        f"{sha256_file(path)}  {path.name}\n", encoding="utf-8"
    )


def build(args: argparse.Namespace) -> int:
    token = args.github_token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    out_dir = Path(args.out)
    work_dir = Path(args.work)
    work_dir.mkdir(parents=True, exist_ok=True)

    geosite = fetch_source(
        args.geosite_repo,
        args.geosite_ref,
        args.geosite_path,
        token=token,
        expected_kind="domains",
    )
    geoip = fetch_source(
        args.geoip_repo,
        args.geoip_ref,
        args.geoip_path,
        token=token,
        expected_kind="CIDRs",
    )

    (work_dir / "geosite.whitelist").write_text(geosite["text"], encoding="utf-8")
    (work_dir / "geoip.whitelist").write_text(geoip["text"], encoding="utf-8")

    rules, domain_stats, _unknown = parse_geosite(geosite["text"])
    cidrs, cidr_stats = parse_cidr(geoip["text"])
    log(f"domains: {sum(len(values) for values in rules.values())} unique items")
    log(f"CIDRs:   {len(cidrs)} unique items")

    domain_source = work_dir / "geosite.source.json"
    ip_source = work_dir / "geoip.source.json"
    write_json(domain_source, make_domain_source(rules))
    write_json(ip_source, make_ip_source(cidrs))

    if args.parse_only:
        log("parse-only mode: source JSON files written, compilation skipped")
        return 0

    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    sing_box = args.sing_box
    if not (Path(sing_box).is_file() or shutil.which(sing_box)):
        raise BuildError(f"sing-box binary not found: {sing_box}")

    geosite_srs = out_dir / "geosite.srs"
    geoip_srs = out_dir / "geoip.srs"
    compile_rule_set(sing_box, domain_source, geosite_srs)
    compile_rule_set(sing_box, ip_source, geoip_srs)

    domain_counts = validate_domain_srs(sing_box, geosite_srs, work_dir, rules)
    ip_counts = validate_ip_srs(sing_box, geoip_srs, work_dir, cidrs)

    sidecar(geosite_srs)
    sidecar(geoip_srs)

    manifest: dict[str, Any] = {
        "schema": 1,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "builder": {
            "name": "rkn-whitelist-srs",
            "sing_box": sing_box_version(sing_box),
        },
        "sources": {
            "geosite": {
                key: geosite[key]
                for key in ("repo", "ref", "commit", "path", "url", "sha256", "bytes")
            }
            | {"stats": domain_stats},
            "geoip": {
                key: geoip[key]
                for key in ("repo", "ref", "commit", "path", "url", "sha256", "bytes")
            }
            | {"stats": cidr_stats},
        },
        "outputs": {
            "geosite.srs": {
                "sha256": sha256_file(geosite_srs),
                "bytes": geosite_srs.stat().st_size,
                "counts": {key: domain_counts.get(key, 0) for key in DOMAIN_KEYS},
                "description": "Whitelisted domains for Podkop / sing-box",
            },
            "geoip.srs": {
                "sha256": sha256_file(geoip_srs),
                "bytes": geoip_srs.stat().st_size,
                "counts": {"ip_cidr": ip_counts.get("ip_cidr", 0)},
                "description": "Whitelisted IPv4/IPv6 subnets for Podkop / sing-box",
            },
        },
    }
    if args.repo:
        manifest["stable_urls"] = {
            "geosite": f"https://github.com/{args.repo}/releases/latest/download/geosite.srs",
            "geoip": f"https://github.com/{args.repo}/releases/latest/download/geoip.srs",
            "manifest": f"https://github.com/{args.repo}/releases/latest/download/manifest.json",
        }

    write_json(out_dir / "manifest.json", manifest)
    log(f"built {geosite_srs} ({geosite_srs.stat().st_size} bytes)")
    log(f"built {geoip_srs} ({geoip_srs.stat().st_size} bytes)")
    log(f"manifest: {out_dir / 'manifest.json'}")
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sing-box", default="sing-box", help="path to the sing-box binary")
    parser.add_argument("--out", default="dist", help="output directory (default: dist)")
    parser.add_argument("--work", default="build", help="intermediate directory (default: build)")
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY") or None,
                        help="owner/repo used to print stable release URLs")
    parser.add_argument("--github-token", default=os.environ.get("GITHUB_TOKEN") or None,
                        help="GitHub token for API calls (optional)")
    parser.add_argument("--geosite-repo", default=GEOSITE_REPO)
    parser.add_argument("--geosite-ref", default=GEOSITE_REF)
    parser.add_argument("--geosite-path", default=GEOSITE_PATH)
    parser.add_argument("--geoip-repo", default=GEOIP_REPO)
    parser.add_argument("--geoip-ref", default=GEOIP_REF)
    parser.add_argument("--geoip-path", default=GEOIP_PATH)
    parser.add_argument("--parse-only", action="store_true",
                        help="download and parse lists, write source JSON, do not compile")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        return build(parse_args(argv))
    except BuildError as error:
        print(f"[build] ERROR: {error}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
