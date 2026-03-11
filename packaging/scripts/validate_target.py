#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from common import load_json, load_target, schema_path, validate_target


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate an image target manifest.")
    parser.add_argument("--target", help="Target ID, for example ubuntu-24.04-amd64")
    parser.add_argument("--path", type=Path, help="Path to a target manifest JSON file")
    parser.add_argument("--print-schema", action="store_true", help="Print the repository JSON schema path")
    args = parser.parse_args()

    if args.print_schema:
        print(schema_path())
        return 0

    try:
        manifest_path, data = load_target(path=args.path, target=args.target)
    except Exception as exc:  # pragma: no cover - operator-facing error path
        print(f"error: {exc}", file=sys.stderr)
        return 1

    errors = validate_target(data)
    if errors:
        for entry in errors:
            print(f"error: {entry}", file=sys.stderr)
        return 1

    schema = load_json(schema_path())
    summary = {
        "manifest": str(manifest_path),
        "target": data["id"],
        "schema": schema.get("$schema"),
        "status": "ok",
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
