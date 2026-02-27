# DPDK (vendored build)

This repository builds a pinned DPDK release into a local install prefix for reproducible
Linux builds. The version is controlled by `third_party/dpdk/VERSION`.

Build:
- `scripts/build-dpdk.sh`

The build installs into `third_party/dpdk/install/<VERSION>` and is used by `make build.dpdk`.
