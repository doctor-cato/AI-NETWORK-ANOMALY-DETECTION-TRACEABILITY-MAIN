"""Verify and synchronize NetFlow Sentinel M6 desktop version across Tauri, Cargo, and npm.

Ensures version consistency across:
- desktop/src-tauri/Cargo.toml
- desktop/src-tauri/Cargo.lock
- desktop/package.json
- desktop/package-lock.json
- desktop/src-tauri/tauri.conf.json

While preserving the independent Python package / FastAPI contract version (0.1.0).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent

CARGO_TOML_PATH = PROJECT_ROOT / "desktop" / "src-tauri" / "Cargo.toml"
CARGO_LOCK_PATH = PROJECT_ROOT / "desktop" / "src-tauri" / "Cargo.lock"
PACKAGE_JSON_PATH = PROJECT_ROOT / "desktop" / "package.json"
PACKAGE_LOCK_PATH = PROJECT_ROOT / "desktop" / "package-lock.json"
TAURI_CONF_PATH = PROJECT_ROOT / "desktop" / "src-tauri" / "tauri.conf.json"

PYPROJECT_PATH = PROJECT_ROOT / "pyproject.toml"
PY_INIT_PATH = PROJECT_ROOT / "src" / "network_anomaly" / "__init__.py"
API_MAIN_PATH = PROJECT_ROOT / "src" / "network_anomaly" / "api" / "main.py"

SEMVER_RE = re.compile(
    r"^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<prerelease>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


def validate_semver(version: str) -> re.Match[str]:
    """Validate SemVer string (e.g. '0.6.0' or '0.6.0-beta.1')."""
    match = SEMVER_RE.match(version.strip())
    if not match:
        raise ValueError(
            f"Invalid SemVer version {version!r}. Expected 'MAJOR.MINOR.PATCH' or "
            "'MAJOR.MINOR.PATCH-prerelease' (e.g., '0.6.0' or '0.6.0-beta.1')."
        )
    return match


def read_cargo_toml_version(path: Path = CARGO_TOML_PATH) -> str:
    content = path.read_text(encoding="utf-8")
    match = re.search(
        r'(?ms)^\[package\]\s+.*?^version\s*=\s*"([^"]+)"',
        content,
    )
    if not match:
        raise ValueError(f"Could not find [package] version in {path}")
    return match.group(1)


def read_cargo_lock_version(
    path: Path = CARGO_LOCK_PATH,
    package_name: str = "netflow-sentinel-desktop",
) -> str:
    content = path.read_text(encoding="utf-8")
    pattern = re.compile(
        r'\[\[package\]\]\r?\nname\s*=\s*"'
        + re.escape(package_name)
        + r'"\r?\nversion\s*=\s*"([^"]+)"'
    )
    match = pattern.search(content)
    if not match:
        raise ValueError(f"Could not find package {package_name!r} version in {path}")
    return match.group(1)


def read_package_json_version(path: Path = PACKAGE_JSON_PATH) -> str:
    data = json.loads(path.read_text(encoding="utf-8"))
    version = data.get("version")
    if not isinstance(version, str) or not version:
        raise ValueError(f"Missing 'version' in {path}")
    return version


def read_package_lock_versions(path: Path = PACKAGE_LOCK_PATH) -> Tuple[str, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    top_version = data.get("version")
    packages = data.get("packages")
    root_pkg_version = packages.get("", {}).get("version") if isinstance(packages, dict) else None
    if not isinstance(top_version, str) or not top_version:
        raise ValueError(f"Missing top-level 'version' in {path}")
    if not isinstance(root_pkg_version, str) or not root_pkg_version:
        raise ValueError(f"Missing packages['']['version'] in {path}")
    return top_version, root_pkg_version


def read_tauri_conf_version(path: Path = TAURI_CONF_PATH) -> str:
    data = json.loads(path.read_text(encoding="utf-8"))
    version = data.get("version")
    if not isinstance(version, str) or not version:
        raise ValueError(f"Missing 'version' in {path}")
    return version


def collect_desktop_versions(root: Path = PROJECT_ROOT) -> Dict[str, str]:
    """Read desktop versions from all 5 canonical configuration and lock files."""
    cargo_toml = root / "desktop" / "src-tauri" / "Cargo.toml"
    cargo_lock = root / "desktop" / "src-tauri" / "Cargo.lock"
    pkg_json = root / "desktop" / "package.json"
    pkg_lock = root / "desktop" / "package-lock.json"
    tauri_conf = root / "desktop" / "src-tauri" / "tauri.conf.json"

    lock_top, lock_root = read_package_lock_versions(pkg_lock)
    return {
        "desktop/src-tauri/Cargo.toml": read_cargo_toml_version(cargo_toml),
        "desktop/src-tauri/Cargo.lock": read_cargo_lock_version(cargo_lock),
        "desktop/package.json": read_package_json_version(pkg_json),
        "desktop/package-lock.json (root)": lock_top,
        "desktop/package-lock.json (packages[''])": lock_root,
        "desktop/src-tauri/tauri.conf.json": read_tauri_conf_version(tauri_conf),
    }


def collect_backend_api_versions(root: Path = PROJECT_ROOT) -> Dict[str, str]:
    """Read Python package and FastAPI contract versions to ensure they stay independent."""
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    py_init = (root / "src" / "network_anomaly" / "__init__.py").read_text(encoding="utf-8")
    api_main = (root / "src" / "network_anomaly" / "api" / "main.py").read_text(encoding="utf-8")

    m_py = re.search(r'(?m)^version\s*=\s*"([^"]+)"', pyproject)
    m_init = re.search(r'__version__\s*=\s*"([^"]+)"', py_init)
    m_api = re.search(r'version\s*=\s*"([^"]+)"', api_main)

    if not (m_py and m_init and m_api):
        raise ValueError("Could not parse Python/FastAPI version identifiers.")

    return {
        "pyproject.toml": m_py.group(1),
        "src/network_anomaly/__init__.py": m_init.group(1),
        "src/network_anomaly/api/main.py": m_api.group(1),
    }


def set_desktop_version(new_version: str, root: Path = PROJECT_ROOT) -> Dict[str, str]:
    """Update all 5 desktop configuration/lock files to `new_version`."""
    validate_semver(new_version)

    cargo_toml = root / "desktop" / "src-tauri" / "Cargo.toml"
    cargo_lock = root / "desktop" / "src-tauri" / "Cargo.lock"
    pkg_json = root / "desktop" / "package.json"
    pkg_lock = root / "desktop" / "package-lock.json"
    tauri_conf = root / "desktop" / "src-tauri" / "tauri.conf.json"

    # 1. Cargo.toml
    toml_text = cargo_toml.read_text(encoding="utf-8")
    toml_updated, n_toml = re.subn(
        r'(?ms)(^\[package\]\s+.*?^version\s*=\s*")([^"]+)(")',
        rf"\g<1>{new_version}\g<3>",
        toml_text,
        count=1,
    )
    if n_toml != 1:
        raise ValueError(f"Failed to update [package] version in {cargo_toml}")
    cargo_toml.write_text(toml_updated, encoding="utf-8", newline="\n")

    # 2. Cargo.lock
    lock_text = cargo_lock.read_text(encoding="utf-8")
    lock_updated, n_lock = re.subn(
        r'(\[\[package\]\]\r?\nname\s*=\s*"netflow-sentinel-desktop"\r?\nversion\s*=\s*")([^"]+)(")',
        rf"\g<1>{new_version}\g<3>",
        lock_text,
        count=1,
    )
    if n_lock != 1:
        raise ValueError(f"Failed to update netflow-sentinel-desktop version in {cargo_lock}")
    cargo_lock.write_text(lock_updated, encoding="utf-8", newline="\n")

    # 3. package.json
    pkg_data = json.loads(pkg_json.read_text(encoding="utf-8"))
    pkg_data["version"] = new_version
    pkg_json.write_text(json.dumps(pkg_data, indent=2) + "\n", encoding="utf-8", newline="\n")

    # 4. package-lock.json
    plock_data = json.loads(pkg_lock.read_text(encoding="utf-8"))
    plock_data["version"] = new_version
    if isinstance(plock_data.get("packages"), dict) and isinstance(
        plock_data["packages"].get(""), dict
    ):
        plock_data["packages"][""]["version"] = new_version
    pkg_lock.write_text(json.dumps(plock_data, indent=2) + "\n", encoding="utf-8", newline="\n")

    # 5. tauri.conf.json
    tauri_data = json.loads(tauri_conf.read_text(encoding="utf-8"))
    tauri_data["version"] = new_version
    tauri_conf.write_text(json.dumps(tauri_data, indent=2) + "\n", encoding="utf-8", newline="\n")

    return collect_desktop_versions(root)


def verify_desktop_version(
    *,
    root: Path = PROJECT_ROOT,
    expected_version: Optional[str] = None,
    expected_tag: Optional[str] = None,
) -> Tuple[bool, str]:
    """Verify desktop version consistency and optional tag/version match."""
    try:
        versions = collect_desktop_versions(root)
        backend_versions = collect_backend_api_versions(root)
    except Exception as exc:
        return False, f"Version read failure: {exc}"

    unique_desktop = sorted(set(versions.values()))
    if len(unique_desktop) != 1:
        details = ", ".join(f"{k}={v}" for k, v in versions.items())
        return False, f"Desktop version mismatch across files: {details}"

    desktop_ver = unique_desktop[0]
    try:
        m_desk = validate_semver(desktop_ver)
    except ValueError as exc:
        return False, str(exc)

    if (int(m_desk.group("major")), int(m_desk.group("minor"))) < (0, 6):
        return (
            False,
            f"Desktop version {desktop_ver!r} is older than M6 target '0.6.0'.",
        )

    # Ensure backend API contract version (0.1.0) was not accidentally overwritten
    unique_backend = sorted(set(backend_versions.values()))
    if len(unique_backend) != 1 or unique_backend[0] != "0.1.0":
        details = ", ".join(f"{k}={v}" for k, v in backend_versions.items())
        return (
            False,
            f"Backend/API contract version must remain '0.1.0' across Python files, got: {details}",
        )

    if expected_version is not None:
        validate_semver(expected_version)
        if desktop_ver != expected_version.strip():
            return (
                False,
                f"Desktop version {desktop_ver!r} does not match expected version {expected_version!r}.",
            )

    if expected_tag is not None:
        tag_clean = expected_tag.strip()
        if tag_clean.startswith("refs/tags/"):
            tag_clean = tag_clean[len("refs/tags/") :]
        if not tag_clean.startswith("v"):
            return False, f"Git tag {tag_clean!r} must start with 'v' (e.g. 'v0.6.0')."
        tag_ver = tag_clean[1:]
        try:
            validate_semver(tag_ver)
        except ValueError as exc:
            return False, f"Invalid SemVer in Git tag {tag_clean!r}: {exc}"

        if desktop_ver != tag_ver:
            return (
                False,
                (
                    f"Desktop version {desktop_ver!r} does not match Git tag {tag_clean!r} "
                    f"(expected {tag_ver!r}). Run "
                    f"'python scripts/check_desktop_version.py --set-version {tag_ver}' "
                    "before tagging so app metadata, NSIS installer, and Git tag agree."
                ),
            )

    return (
        True,
        f"Desktop version verified consistent: {desktop_ver} "
        f"(Python/FastAPI contract version: {unique_backend[0]})",
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify or synchronize NetFlow Sentinel M6 desktop versions."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check that all desktop version files are synchronized (default action).",
    )
    parser.add_argument(
        "--set-version",
        type=str,
        default=None,
        help="Synchronize all 5 desktop version files to the specified SemVer (e.g. 0.6.0 or 0.6.0-beta.1).",
    )
    parser.add_argument(
        "--expect-version",
        type=str,
        default=None,
        help="Require desktop version to equal this exact SemVer string.",
    )
    parser.add_argument(
        "--expect-tag",
        type=str,
        default=None,
        help="Require desktop version to match the given Git tag (e.g. v0.6.0 or v0.6.0-beta.1).",
    )
    args = parser.parse_args()

    if args.set_version:
        updated = set_desktop_version(args.set_version.strip())
        print(f"Synchronized desktop version to {args.set_version.strip()}:")
        for k, v in updated.items():
            print(f"  - {k}: {v}")

    ok, message = verify_desktop_version(
        expected_version=args.expect_version,
        expected_tag=args.expect_tag,
    )
    if not ok:
        print(f"ERROR: {message}", file=sys.stderr)
        return 1
    print(f"OK: {message}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
