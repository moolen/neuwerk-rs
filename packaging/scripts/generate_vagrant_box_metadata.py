#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate Vagrant box metadata.json.")
    parser.add_argument("--box-name", required=True, help="Vagrant box name, for example neuwerk/neuwerk-demo")
    parser.add_argument("--version", required=True, help="Box version")
    parser.add_argument("--provider", required=True, help="Provider name, for example virtualbox")
    parser.add_argument("--url", required=True, help="Provider box URL")
    parser.add_argument("--checksum", required=True, help="SHA256 checksum for the box")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    payload = {
        "name": args.box_name,
        "description": "Neuwerk local demo box",
        "versions": [
            {
                "version": args.version,
                "providers": [
                    {
                        "name": args.provider,
                        "url": args.url,
                        "checksum_type": "sha256",
                        "checksum": args.checksum,
                    }
                ],
            }
        ],
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
