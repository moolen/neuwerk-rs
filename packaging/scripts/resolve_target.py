#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path

from common import flatten, load_target, validate_target


def main() -> int:
    parser = argparse.ArgumentParser(description="Resolve a target manifest into JSON or shell env output.")
    parser.add_argument("--target", required=True, help="Target ID, for example ubuntu-24.04-minimal-amd64")
    parser.add_argument(
        "--format",
        choices=("json", "env"),
        default="json",
        help="Output format",
    )
    parser.add_argument(
        "--provider",
        choices=("aws", "azure", "gcp", "qemu"),
        help="Restrict output to a provider-specific base image block in env format",
    )
    args = parser.parse_args()

    manifest_path, data = load_target(target=args.target)
    errors = validate_target(data)
    if errors:
        for entry in errors:
            print(f"error: {entry}", file=sys.stderr)
        return 1

    if args.format == "json":
        print(json.dumps(data, indent=2, sort_keys=True))
        return 0

    print(f"TARGET_MANIFEST_PATH={shlex.quote(str(manifest_path))}")
    for key, value in flatten("target", data):
        print(f"{key}={shlex.quote(value)}")
    if args.provider:
        provider_data = data["base_images"][args.provider]
        for key, value in flatten(args.provider, provider_data):
            print(f"{key}={shlex.quote(value)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
