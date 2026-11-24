#!/usr/bin/env python3
"""
Machine-First PyPI CLI (pypi)
Created by Antigravity & Q.S@RDOR

Zero-dependency, token-efficient PyPI registry & packaging CLI:
- Key-Value and TSV outputs (no JSON bloat, strict single-line scalars)
- HTTPS-only redirects, gzip/deflate decompression with memory caps
- Concurrent zero-body HEAD checks with PEP 508 & PEP 440 validation
- Non-destructive ~/.pypirc credential manager (POSIX 0600 atomic create)
- Ephemeral in-memory token forwarding to uv build/publish or python -m build/twine
"""

import configparser
import gzip
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
import zlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

try:
    from . import __version__
except ImportError:
    __version__ = "0.0.1"

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

USER_AGENT = f"pypi-cli/{__version__} ({platform.system()} {platform.machine()}; Python {sys.version.split()[0]})"
PEP508_NAME_RE = re.compile(r"^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$", re.IGNORECASE)
PEP440_VER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._!+-]*$")
EXTRA_MARKER_RE = re.compile(r"\bextra\s*==", re.IGNORECASE)
PRE_RELEASE_RE = re.compile(r"(?:\.|[0-9])(a|b|rc|dev|alpha|beta|pre|preview)[0-9]*", re.IGNORECASE)

MAX_WIRE_BYTES = 20 * 1024 * 1024         # 20 MiB network read cap
MAX_DECOMPRESSED_BYTES = 50 * 1024 * 1024 # 50 MiB decompression bomb guard


class _HttpsOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Blocks redirects to non-HTTPS targets to prevent downgrade attacks."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not str(newurl).lower().startswith("https://"):
            raise urllib.error.URLError(f"blocked insecure redirect target: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_HttpsOnlyRedirectHandler())


def normalize_name(name: str) -> str:
    """PEP 503 package name normalization."""
    return re.sub(r"[-_.]+", "-", name).lower()


def clean_scalar(value) -> str:
    """Normalizes metadata values to a safe single line for key: value output."""
    if value is None:
        return "None"
    collapsed = " ".join(str(value).split())
    return collapsed if collapsed else "None"


def resolve_license(info: dict) -> str:
    """Resolves concise single-line license from PEP 639, license field, or classifiers."""
    expr = clean_scalar(info.get("license_expression"))
    if expr != "None":
        return expr

    raw_lic = info.get("license") or ""
    if raw_lic and "\n" not in raw_lic.strip() and len(raw_lic.strip()) <= 80:
        return clean_scalar(raw_lic)

    classifiers = info.get("classifiers") or []
    lic_tags = [c.split("::")[-1].strip() for c in classifiers if isinstance(c, str) and c.startswith("License ::")]
    if lic_tags:
        # Prefer OSI-approved descriptive tag over generic top-level bucket
        return clean_scalar(lic_tags[-1])

    if raw_lic:
        first_line = next((line.strip() for line in raw_lic.splitlines() if line.strip()), "")
        if len(first_line) > 80:
            return first_line[:77] + "..."
        return first_line or "None"

    return "None"


def parse_target(raw: str):
    """Parses package and optional version specifier (pkg==ver, pkg@ver) with strict validation."""
    raw = raw.strip()
    m = re.match(r"^([^=@]+?)(?:==|@)(.+)$", raw)
    if m:
        name, ver = m.group(1).strip(), m.group(2).strip()
    else:
        name, ver = raw, None

    if not PEP508_NAME_RE.match(name):
        return None, None, f"invalid package name '{name}' (PEP 508 naming syntax violation)"

    if ver is not None and not PEP440_VER_RE.match(ver):
        return None, None, f"invalid version specifier '{ver}'"

    return normalize_name(name), ver, None


def _read_bounded(stream, enc: str) -> bytes:
    """Reads up to MAX_WIRE_BYTES and safely decompresses up to MAX_DECOMPRESSED_BYTES."""
    raw = stream.read(MAX_WIRE_BYTES + 1)
    if len(raw) > MAX_WIRE_BYTES:
        raise ValueError(f"response exceeded {MAX_WIRE_BYTES // (1024 * 1024)} MiB wire limit")

    enc = (enc or "").lower()
    if "gzip" in enc:
        decomp = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out = decomp.decompress(raw, MAX_DECOMPRESSED_BYTES + 1)
    elif "deflate" in enc:
        decomp = zlib.decompressobj()
        out = decomp.decompress(raw, MAX_DECOMPRESSED_BYTES + 1)
    else:
        return raw

    if len(out) > MAX_DECOMPRESSED_BYTES or decomp.unconsumed_tail:
        raise ValueError(f"decompressed payload exceeded {MAX_DECOMPRESSED_BYTES // (1024 * 1024)} MiB limit")
    return out


def make_request(url: str, headers=None, method: str = "GET"):
    """Performs HTTPS requests with redirect safety, compression, and byte caps. Returns (code, bytes)."""
    if not url.startswith("https://"):
        return 0, b"HTTPS protocol is required"

    req_headers = {
        "User-Agent": USER_AGENT,
        "Accept-Encoding": "gzip, deflate",
    }
    if headers:
        req_headers.update(headers)

    req = urllib.request.Request(url, headers=req_headers, method=method)
    try:
        with _OPENER.open(req, timeout=10) as resp:
            code = resp.getcode()
            if method == "HEAD":
                return code, b""
            data = _read_bounded(resp, resp.headers.get("Content-Encoding", ""))
            return code, data
    except urllib.error.HTTPError as e:
        if method == "HEAD":
            return e.code, b""
        try:
            enc = e.headers.get("Content-Encoding", "") if hasattr(e, "headers") and e.headers else ""
            data = _read_bounded(e, enc)
        except Exception:
            data = b""
        return e.code, data
    except Exception as e:
        return 0, str(e).encode("utf-8", errors="replace")


def _parse_pkg_and_ver(args, usage: str):
    """Parses positional package and optional trailing version argument."""
    if not args:
        print(f"error: package name required. Usage: {usage}", file=sys.stderr)
        sys.exit(1)

    pkg, ver, err = parse_target(args[0])
    if err:
        print(f"error: {err}", file=sys.stderr)
        sys.exit(1)

    if len(args) > 1 and not ver and not args[1].startswith("-"):
        ver = args[1].strip()
        if not PEP440_VER_RE.match(ver):
            print(f"error: invalid version specifier '{ver}'", file=sys.stderr)
            sys.exit(1)

    return pkg, ver


def _fetch_json(url: str, not_found_msg: str, extra_headers=None) -> dict:
    """Fetches and decodes JSON payload with unified HTTP status error handling."""
    code, body = make_request(url, headers=extra_headers)
    if code == 404:
        print(f"error: {not_found_msg}", file=sys.stderr)
        sys.exit(1)
    if code == 429:
        print("error: API rate limit reached (HTTP 429). Please retry shortly.", file=sys.stderr)
        sys.exit(1)
    if code == 0:
        msg = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body)
        print(f"error: network connection failed: {msg}", file=sys.stderr)
        sys.exit(1)
    if code != 200:
        print(f"error: PyPI API returned HTTP {code}", file=sys.stderr)
        sys.exit(1)

    try:
        return json.loads(body)
    except Exception as e:
        print(f"error: failed to parse response JSON: {e}", file=sys.stderr)
        sys.exit(1)


def _format_size(num_bytes) -> str:
    if not isinstance(num_bytes, (int, float)) or num_bytes < 0:
        return "-"
    if num_bytes < 1024:
        return f"{int(num_bytes)}B"
    if num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f}KB"
    return f"{num_bytes / (1024 * 1024):.1f}MB"


def _extract_token_arg(args):
    """Parses --token <val> or --token=<val> safely while stripping from pass-through args."""
    token = None
    cleaned = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--token":
            if i + 1 >= len(args) or args[i + 1].startswith("-"):
                print("error: --token requires a valid token value", file=sys.stderr)
                sys.exit(1)
            token = args[i + 1]
            i += 2
            continue
        if a.startswith("--token="):
            token = a.split("=", 1)[1]
            if not token:
                print("error: --token= value cannot be empty", file=sys.stderr)
                sys.exit(1)
            i += 1
            continue
        cleaned.append(a)
        i += 1

    if token is not None:
        if "\n" in token or "\r" in token:
            print("error: token must not contain newline characters", file=sys.stderr)
            sys.exit(1)
        token = token.strip()
        if not token:
            print("error: token cannot be empty or whitespace", file=sys.stderr)
            sys.exit(1)

    return token, cleaned


def _write_pypirc_secure(pypirc_path: Path, cfg: configparser.RawConfigParser):
    """Writes ~/.pypirc with atomic 0600 permissions on POSIX to eliminate TOCTOU exposure."""
    if os.name == "posix":
        fd = os.open(pypirc_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            f = os.fdopen(fd, "w", encoding="utf-8")
        except Exception:
            os.close(fd)
            raise
        with f:
            cfg.write(f)
        try:
            os.chmod(pypirc_path, 0o600)
        except Exception:
            pass
    else:
        with open(pypirc_path, "w", encoding="utf-8") as f:
            cfg.write(f)


def cmd_info(args):
    """Outputs single-line Key-Value metadata for a package or exact version."""
    pkg, ver = _parse_pkg_and_ver(args, "pypi info <package>[==version]")
    url = f"https://pypi.org/pypi/{pkg}/{ver}/json" if ver else f"https://pypi.org/pypi/{pkg}/json"
    target_str = f"'{pkg}=={ver}'" if ver else f"'{pkg}'"
    data = _fetch_json(url, f"package {target_str} not found on PyPI (404)")

    info = data.get("info", {})
    releases = data.get("releases", {})

    print(f"name: {clean_scalar(info.get('name'))}")
    print(f"version: {clean_scalar(info.get('version'))}")
    if info.get("yanked"):
        reason = clean_scalar(info.get("yanked_reason") or "No reason provided")
        print(f"yanked: True (reason: {reason})")
    print(f"summary: {clean_scalar(info.get('summary'))}")
    print(f"author: {clean_scalar(info.get('author') or info.get('author_email'))}")
    print(f"license: {resolve_license(info)}")
    print(f"requires_python: {clean_scalar(info.get('requires_python'))}")
    print(f"homepage: {clean_scalar(info.get('home_page') or info.get('project_url'))}")

    urls = info.get("project_urls") or {}
    if urls:
        url_list = [f"{clean_scalar(k)}={clean_scalar(v)}" for k, v in urls.items()]
        print(f"urls: {'; '.join(url_list)}")

    if not ver:
        print(f"total_releases: {len(releases)}")


def cmd_check(args):
    """Batch checks package availability on PyPI via concurrent zero-body HEAD requests."""
    if not args:
        print("error: package name required. Usage: pypi check <package_name...>", file=sys.stderr)
        sys.exit(1)

    ordered_results = [None] * len(args)
    valid_slots = []

    for idx, raw in enumerate(args):
        raw_name = raw.strip()
        if not PEP508_NAME_RE.match(raw_name):
            ordered_results[idx] = (raw_name, "INVALID_NAME (PEP 508 syntax error)")
        else:
            valid_slots.append((idx, normalize_name(raw_name)))

    def probe(slot):
        idx, pkg = slot
        code, _ = make_request(f"https://pypi.org/pypi/{pkg}/json", method="HEAD")
        status = "AVAILABLE" if code == 404 else ("TAKEN" if code == 200 else f"UNKNOWN (HTTP {code})")
        return idx, pkg, status

    if len(valid_slots) > 1:
        with ThreadPoolExecutor(max_workers=min(10, len(valid_slots))) as executor:
            for idx, pkg, status in executor.map(probe, valid_slots):
                ordered_results[idx] = (pkg, status)
    elif valid_slots:
        idx, pkg, status = probe(valid_slots[0])
        ordered_results[idx] = (pkg, status)

    for pkg, status in ordered_results:
        print(f"name: {pkg}\tstatus: {status}")


def cmd_deps(args):
    """Outputs package dependencies line-by-line. Supports --core and --extra <name>."""
    if not args:
        print("error: package name required. Usage: pypi deps <package>[==ver] [--core | --extra <name>]", file=sys.stderr)
        sys.exit(1)

    core_only = False
    target_extra = None
    clean_args = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("--core", "--no-extras"):
            core_only = True
        elif a == "--extra":
            if i + 1 >= len(args):
                print("error: --extra requires an extra name", file=sys.stderr)
                sys.exit(1)
            target_extra = args[i + 1].strip().lower()
            i += 1
        elif a.startswith("--extra="):
            target_extra = a.split("=", 1)[1].strip().lower()
        else:
            clean_args.append(a)
        i += 1

    pkg, ver = _parse_pkg_and_ver(clean_args, "pypi deps <package>[==ver] [--core | --extra <name>]")
    url = f"https://pypi.org/pypi/{pkg}/{ver}/json" if ver else f"https://pypi.org/pypi/{pkg}/json"
    target_str = f"'{pkg}=={ver}'" if ver else f"'{pkg}'"
    data = _fetch_json(url, f"package {target_str} not found")

    deps = data.get("info", {}).get("requires_dist") or []
    if not deps:
        print(f"Package {target_str} has no declared dependencies.")
        return

    extra_exact_re = (
        re.compile(rf"\bextra\s*==\s*['\"]{re.escape(target_extra)}['\"]", re.IGNORECASE)
        if target_extra
        else None
    )

    emitted = 0
    for dep in deps:
        if core_only and EXTRA_MARKER_RE.search(dep):
            continue
        if extra_exact_re and not extra_exact_re.search(dep):
            continue
        print(clean_scalar(dep))
        emitted += 1

    if emitted == 0:
        if core_only:
            print(f"Package {target_str} has no core runtime dependencies (all dependencies are optional extras).")
        elif target_extra:
            print(f"Package {target_str} has no dependencies for extra '{target_extra}'.")


def cmd_versions(args):
    """Outputs recent versions using PEP 691 Simple API in dense TSV. Supports --stable."""
    if not args:
        print("error: package name required. Usage: pypi versions <package> [-n N] [--stable]", file=sys.stderr)
        sys.exit(1)

    limit = 15
    stable_only = False
    positional = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("--stable", "--no-pre"):
            stable_only = True
        elif a in ("-n", "-l", "--limit"):
            if i + 1 >= len(args):
                print(f"error: {a} requires an integer value", file=sys.stderr)
                sys.exit(1)
            try:
                limit = int(args[i + 1])
            except ValueError:
                print(f"error: invalid integer for {a}: '{args[i + 1]}'", file=sys.stderr)
                sys.exit(1)
            i += 1
        elif a.startswith(("-n=", "-l=", "--limit=")):
            val = a.split("=", 1)[1]
            try:
                limit = int(val)
            except ValueError:
                print(f"error: invalid integer for limit: '{val}'", file=sys.stderr)
                sys.exit(1)
        else:
            positional.append(a)
        i += 1

    if limit <= 0:
        print("error: limit must be greater than 0", file=sys.stderr)
        sys.exit(1)

    if not positional:
        print("error: package name required", file=sys.stderr)
        sys.exit(1)

    raw_name = positional[0].strip()
    if not PEP508_NAME_RE.match(raw_name):
        print(f"error: invalid package name '{raw_name}' (PEP 508 naming syntax violation)", file=sys.stderr)
        sys.exit(1)
    pkg = normalize_name(raw_name)

    data = _fetch_json(
        f"https://pypi.org/simple/{pkg}/",
        f"package '{pkg}' not found on PyPI",
        extra_headers={"Accept": "application/vnd.pypi.simple.v1+json"},
    )

    versions = data.get("versions", [])
    if stable_only:
        versions = [v for v in versions if not PRE_RELEASE_RE.search(v)]

    if not versions:
        print(f"No matching versions found for '{pkg}'.")
        return

    recent = versions[-limit:]
    recent.reverse()
    print(f"name: {pkg}\ttotal_versions: {len(versions)}")
    print("version\tindex")
    for idx, ver in enumerate(recent, 1):
        print(f"{ver}\t{idx}")


def cmd_files(args):
    """Lists distribution wheels and sdists for a package/version in dense TSV."""
    pkg, ver = _parse_pkg_and_ver(args, "pypi files <package>[==version]")
    url = f"https://pypi.org/pypi/{pkg}/{ver}/json" if ver else f"https://pypi.org/pypi/{pkg}/json"
    target_str = f"'{pkg}=={ver}'" if ver else f"'{pkg}'"
    data = _fetch_json(url, f"package {target_str} not found on PyPI (404)")

    resolved_ver = data.get("info", {}).get("version") or ver or "-"
    files = data.get("urls") or []
    print(f"name: {pkg}\tversion: {resolved_ver}\ttotal_files: {len(files)}")
    if not files:
        return

    print("filename\ttype\tsize\trequires_python\tyanked")
    for f in files:
        fname = clean_scalar(f.get("filename"))
        ptype = clean_scalar(f.get("packagetype"))
        size = _format_size(f.get("size"))
        req_py = clean_scalar(f.get("requires_python"))
        yanked = "True" if f.get("yanked") else "False"
        print(f"{fname}\t{ptype}\t{size}\t{req_py}\t{yanked}")


def cmd_stats(args):
    """Outputs download statistics from pypistats.org in dense Key-Value."""
    if not args:
        print("error: package name required. Usage: pypi stats <package>", file=sys.stderr)
        sys.exit(1)

    raw_name = args[0].strip()
    if not PEP508_NAME_RE.match(raw_name):
        print(f"error: invalid package name '{raw_name}' (PEP 508 naming syntax violation)", file=sys.stderr)
        sys.exit(1)
    pkg = normalize_name(raw_name)

    data = _fetch_json(
        f"https://pypistats.org/api/packages/{pkg}/recent",
        f"statistics not found for '{pkg}' on pypistats.org",
    ).get("data", {})

    print(f"name: {pkg}")
    print(f"last_day: {data.get('last_day', 0):,}")
    print(f"last_week: {data.get('last_week', 0):,}")
    print(f"last_month: {data.get('last_month', 0):,}")


def cmd_build(args):
    """Builds sdist and wheel using uv (preferred) or python -m build."""
    target_dir = "."
    extra_flags = []
    for a in args:
        if target_dir == "." and not a.startswith("-"):
            target_dir = a
        else:
            extra_flags.append(a)

    if not Path(target_dir).exists():
        print(f"error: build target directory '{target_dir}' does not exist", file=sys.stderr)
        sys.exit(1)

    uv_path = shutil.which("uv")
    if uv_path:
        cmd = [uv_path, "build"]
        if target_dir != ".":
            cmd += ["--directory", target_dir]
        cmd += extra_flags
        print(f"Building package with uv in: {target_dir}")
        res = subprocess.run(cmd)
        if res.returncode != 0:
            sys.exit(res.returncode)
        return

    cmd = [sys.executable, "-m", "build", target_dir] + extra_flags
    print(f"Building package with python -m build in: {target_dir}")
    res = subprocess.run(cmd)
    if res.returncode != 0:
        sys.exit(res.returncode)


def cmd_publish(args):
    """Uploads distributions using uv publish or twine with secure in-memory token forwarding."""
    pypirc_path = Path.home() / ".pypirc"
    env = os.environ.copy()

    token, no_tok_args = _extract_token_arg(args)
    test_mode = "--test" in no_tok_args or any("test.pypi.org" in a for a in no_tok_args)
    target_section = "testpypi" if test_mode else "pypi"
    cleaned_args = [a for a in no_tok_args if a != "--test"]

    if not token:
        token = env.get("UV_PUBLISH_TOKEN") or env.get("TWINE_PASSWORD")

    if not token and pypirc_path.exists():
        cfg = configparser.RawConfigParser()
        try:
            cfg.read(pypirc_path, encoding="utf-8")
            tok = cfg.get(target_section, "password", fallback="").strip()
            if tok.startswith("pypi-"):
                token = tok
        except Exception:
            pass

    if token:
        env["UV_PUBLISH_TOKEN"] = token
        env["TWINE_USERNAME"] = "__token__"
        env["TWINE_PASSWORD"] = token

    uv_path = shutil.which("uv")
    if uv_path:
        cmd = [uv_path, "publish"]
        check_url = "https://test.pypi.org/simple/" if test_mode else "https://pypi.org/simple/"
        if "--check-url" not in cleaned_args:
            cmd += ["--check-url", check_url]
        cmd += cleaned_args
        if test_mode and "--publish-url" not in cleaned_args:
            cmd += ["--publish-url", "https://test.pypi.org/legacy/"]

        print("Publishing package distributions via uv...")
        res = subprocess.run(cmd, env=env)
        if res.returncode != 0:
            sys.exit(res.returncode)
        return

    twine_path = shutil.which("twine")
    if twine_path:
        cmd = [twine_path, "upload"]
        if test_mode and "--repository-url" not in cleaned_args:
            cmd += ["--repository-url", "https://test.pypi.org/legacy/"]
        cmd += cleaned_args if cleaned_args else ["dist/*"]
        print("Publishing package distributions via twine...")
        res = subprocess.run(cmd, env=env)
        if res.returncode != 0:
            sys.exit(res.returncode)
        return

    print("error: Neither 'uv' nor 'twine' was found in PATH. Please install uv or twine to publish.", file=sys.stderr)
    sys.exit(1)


def cmd_auth(args):
    """Safely inspects or updates PyPI token in ~/.pypirc without destroying other sections."""
    pypirc_path = Path.home() / ".pypirc"
    token, rest = _extract_token_arg(args)
    test_mode = "--test" in rest

    if token:
        section = "testpypi" if test_mode else "pypi"
        cfg = configparser.RawConfigParser()

        if pypirc_path.exists():
            try:
                cfg.read(pypirc_path, encoding="utf-8")
            except Exception:
                pass

        if not cfg.has_section("distutils"):
            cfg.add_section("distutils")

        servers = cfg.get("distutils", "index-servers", fallback="").split()
        if section not in servers:
            servers.append(section)
        cfg.set("distutils", "index-servers", "\n" + "\n".join(servers))

        if not cfg.has_section(section):
            cfg.add_section(section)

        if test_mode:
            cfg.set(section, "repository", "https://test.pypi.org/legacy/")

        cfg.set(section, "username", "__token__")
        cfg.set(section, "password", token)

        _write_pypirc_secure(pypirc_path, cfg)
        print(f"status: OK\tsection: {section}\tfile: {pypirc_path}")
        return

    if pypirc_path.exists():
        cfg = configparser.RawConfigParser()
        try:
            cfg.read(pypirc_path, encoding="utf-8")
            has_pypi = cfg.has_section("pypi") and cfg.get("pypi", "password", fallback="").startswith("pypi-")
            has_test = cfg.has_section("testpypi") and cfg.get("testpypi", "password", fallback="").startswith("pypi-")
            sections = [s for s in cfg.sections() if s != "distutils"]
            print(f"pypirc_file: {pypirc_path}")
            print(f"pypi_token_configured: {has_pypi}")
            print(f"testpypi_token_configured: {has_test}")
            print(f"configured_sections: {', '.join(sections)}")
        except Exception as e:
            print(f"pypirc_file: {pypirc_path} (error reading config: {e})")
    else:
        print(f"pypirc_file: None (file does not exist: {pypirc_path})")
        print("hint: configure token via 'pypi auth --token <your-pypi-token>'")


HELP_TOPICS = {
    "info": """
PYPI INFO: INSPECT PACKAGE METADATA
Fetches single-line Key-Value metadata (including PEP 639 license_expression) for a package or pinned version.

EXAMPLES:
  $ pypi info fastapi
  $ pypi info requests==2.31.0
  $ pypi info pydantic@1.10.12
  $ pypi info torch 2.1.0
""",
    "check": """
PYPI CHECK: CONCURRENT NAME AVAILABILITY VERIFIER
Checks multiple package names concurrently via zero-body HEAD requests and PEP 508 validation.

EXAMPLES:
  $ pypi check my-cool-project
  $ pypi check fastapi requests candidate-pkg "invalid/name"
""",
    "deps": """
PYPI DEPS: EXTRACT DECLARED DEPENDENCIES
Prints requires_dist dependencies line-by-line without downloading wheels. Supports --core and --extra filtering.

EXAMPLES:
  $ pypi deps fastapi
  $ pypi deps fastapi --core
  $ pypi deps pytest --extra dev
  $ pypi deps pydantic@1.10.12 --core
""",
    "versions": """
PYPI VERSIONS: RECENT VERSION LIST
Queries PEP 691 Simple JSON endpoint for recent releases in dense TSV. Supports --stable to hide pre-releases.

EXAMPLES:
  $ pypi versions fastapi
  $ pypi versions requests -n 5
  $ pypi versions urllib3 --limit 5 --stable
""",
    "files": """
PYPI FILES: DISTRIBUTION & WHEEL INSPECTOR
Lists wheels and sdists for a release (ABI, size, requires_python, yanked status) in dense TSV.

EXAMPLES:
  $ pypi files numpy
  $ pypi files requests==2.31.0
""",
    "stats": """
PYPI STATS: DOWNLOAD METRICS
Fetches daily, weekly, and monthly download numbers from pypistats.org.

EXAMPLES:
  $ pypi stats numpy
  $ pypi stats uv
""",
    "build": """
PYPI BUILD: PACKAGE DISTRIBUTION COMPILER
Invokes 'uv build' (or python -m build fallback) to compile sdist and wheel binaries into dist/.

EXAMPLES:
  $ pypi build
  $ pypi build ./my-package --wheel
""",
    "publish": """
PYPI PUBLISH: SECURE DISTRIBUTION UPLOADER
Invokes 'uv publish' (or twine fallback). Tokens are stripped from argv and passed strictly via memory env vars.

EXAMPLES:
  $ pypi publish
  $ pypi publish --token <your-pypi-token>
  $ pypi publish --test
  $ pypi publish --dry-run
""",
    "auth": """
PYPI AUTH: TOKEN AND CONFIGURATION MANAGER
Safely inspects or updates API tokens inside ~/.pypirc (enforcing POSIX 0600 permissions) while preserving other sections.

EXAMPLES:
  $ pypi auth
  $ pypi auth --token <your-pypi-token>
  $ pypi auth --token <your-testpypi-token> --test
""",
}


def show_topic_help(topic: str):
    key = (topic or "").lower().strip("-")
    if key in HELP_TOPICS:
        print(HELP_TOPICS[key].strip())
    else:
        topics = ", ".join(HELP_TOPICS.keys())
        print(f"error: unknown help topic '{topic}'. Available: {topics}", file=sys.stderr)
        sys.exit(1)


def show_help():
    print(f"""
pypi-cli v{__version__}
Created by Antigravity & Q.S@RDOR

Usage:
  pypi info <package>[==ver]          Inspect summary, PEP 639 license, and python constraints
  pypi check <pkg1> [pkg2...]         Concurrent batch availability & PEP 508 check
  pypi deps <package> [--core|--extra] Print dependencies line-by-line
  pypi versions <pkg> [-n N] [--stable] List recent versions via PEP 691 API
  pypi files <package>[==ver]         List wheels/sdists, sizes, and yanked status
  pypi stats <package>                Print download counts from pypistats.org
  pypi build [path] [flags]           Compile wheel/sdist via uv or python -m build
  pypi publish [flags]                Upload distributions securely via uv or twine
  pypi auth [--token <tok>] [--test]  Inspect or update ~/.pypirc without data loss
  pypi help [topic]                   Show topic-specific examples
  pypi --version                      Show CLI version

Topics:
  pypi --help info | check | deps | versions | files | stats | build | publish | auth
""".strip())


def main():
    if len(sys.argv) < 2:
        show_help()
        return

    first = sys.argv[1].lower()
    if first in ("--version", "-v", "version") and len(sys.argv) == 2:
        print(f"pypi-cli {__version__}")
        return

    if first in ("help", "--help", "-h"):
        if len(sys.argv) > 2:
            show_topic_help(sys.argv[2])
        else:
            show_help()
        return

    if "--help" in sys.argv or "-h" in sys.argv:
        topic = next((a for a in sys.argv[1:] if not a.startswith("-") and a != "help"), None)
        if topic and topic.lower() in HELP_TOPICS:
            show_topic_help(topic)
            return

    dispatch = {
        "info": cmd_info,
        "check": cmd_check,
        "deps": cmd_deps,
        "versions": cmd_versions,
        "files": cmd_files,
        "stats": cmd_stats,
        "build": cmd_build,
        "publish": cmd_publish,
        "auth": cmd_auth,
    }

    fn = dispatch.get(first)
    if fn:
        fn(sys.argv[2:])
    else:
        print(f"error: unknown command '{first}'. Run 'pypi help' for usage.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
