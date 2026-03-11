#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[2]
TARGETS_DIR = REPO_ROOT / "packaging" / "targets"
SCHEMA_PATH = REPO_ROOT / "packaging" / "target.schema.json"


def repo_root() -> Path:
    return REPO_ROOT


def schema_path() -> Path:
    return SCHEMA_PATH


def target_path(target: str) -> Path:
    return TARGETS_DIR / f"{target}.json"


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_target(path: Path | None = None, target: str | None = None) -> tuple[Path, dict[str, Any]]:
    if path is None:
        if not target:
            raise ValueError("target or path is required")
        path = target_path(target)
    data = load_json(path)
    return path, data


def required_string(data: dict[str, Any], key: str, context: str, errors: list[str]) -> None:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{context}.{key} must be a non-empty string")


def required_list(data: dict[str, Any], key: str, context: str, errors: list[str]) -> None:
    value = data.get(key)
    if not isinstance(value, list) or not value:
        errors.append(f"{context}.{key} must be a non-empty list")


def validate_target(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    if data.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    required_string(data, "id", "target", errors)

    os_data = data.get("os")
    if not isinstance(os_data, dict):
        errors.append("os must be an object")
    else:
        for key in ("family", "version", "arch"):
            required_string(os_data, key, "os", errors)

    packages = data.get("packages")
    if not isinstance(packages, dict):
        errors.append("packages must be an object")
    else:
        for key in ("build", "runtime"):
            required_list(packages, key, "packages", errors)

    dpdk = data.get("dpdk")
    if not isinstance(dpdk, dict):
        errors.append("dpdk must be an object")
    else:
        for key in ("version", "profile", "abi"):
            required_string(dpdk, key, "dpdk", errors)
        for key in ("disable_drivers", "enable_pmd_sets"):
            required_list(dpdk, key, "dpdk", errors)

    runtime = data.get("runtime")
    if not isinstance(runtime, dict):
        errors.append("runtime must be an object")
    else:
        for key in (
            "prefix",
            "binary_dir",
            "ui_dir",
            "env_file",
            "appliance_env_file",
            "bootstrap_path",
            "service_file",
            "launcher_path",
            "link_name",
        ):
            required_string(runtime, key, "runtime", errors)
        for key in ("dpdk_library_globs", "dpdk_pmd_globs"):
            required_list(runtime, key, "runtime", errors)

    hardening = data.get("hardening")
    if not isinstance(hardening, dict):
        errors.append("hardening must be an object")
    else:
        for key in ("profile", "waiver_file"):
            required_string(hardening, key, "hardening", errors)

    sbom = data.get("sbom")
    if not isinstance(sbom, dict):
        errors.append("sbom must be an object")
    else:
        required_list(sbom, "formats", "sbom", errors)

    base_images = data.get("base_images")
    if not isinstance(base_images, dict):
        errors.append("base_images must be an object")
    else:
        for provider in ("aws", "azure", "gcp", "qemu"):
            if not isinstance(base_images.get(provider), dict):
                errors.append(f"base_images.{provider} must be an object")

    return errors


def flatten(prefix: str, value: Any) -> Iterable[tuple[str, str]]:
    key = prefix.upper().replace("-", "_").replace(".", "_")
    if isinstance(value, dict):
        for child_key, child_value in value.items():
            yield from flatten(f"{prefix}_{child_key}", child_value)
    elif isinstance(value, list):
        encoded = json.dumps(value, separators=(",", ":"))
        yield key, encoded
    elif isinstance(value, bool):
        yield key, "true" if value else "false"
    elif value is None:
        yield key, ""
    else:
        yield key, str(value)
