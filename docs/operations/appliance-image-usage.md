# Appliance Image Usage

## Supported Scope

- Ubuntu 24.04 is the only supported appliance base in this phase.
- Published Ubuntu appliance artifacts target `ubuntu-24.04-minimal-amd64`.
- GitHub Releases is the canonical distribution channel for appliance artifacts.
- AWS, Azure, and GCP are supported as manual import targets.
- This guide covers operator usage of published release artifacts only (not Terraform automation or provider-native publication pipelines).

## Download And Verify Release Assets

Download the full asset set required for your selected target from the selected GitHub Release before running checksum verification. `SHA256SUMS` covers the published files in that checksum set, so partial downloads can cause `sha256sum -c SHA256SUMS` to fail with missing-file errors.

Do not rely on a partial subset. Download every asset required for the selected target and its checksum set before running checksum verification.

The release asset set typically includes:

- split appliance image parts such as `neuwerk-<target>.qcow2.zst.part-*`
- `restore-qcow2.sh`
- `SHA256SUMS`
- `manifest.json`
- `release-notes.md`
- `linkage.json`
- `packer-manifest.json`
- rootfs and source archives such as `neuwerk-<target>-rootfs.tar.zst` and `neuwerk-<target>-source.tar.gz`
- image and rootfs SBOM files in `spdx` and `cyclonedx` formats
- any release-specific extras attached for that target, such as Vagrant box assets or metadata

Run checksum verification in the artifact directory:

```bash
sha256sum -c SHA256SUMS
```

Expected result: all downloaded files report `OK`.

## Restore The qcow2 Appliance Image

Rebuild and decompress the split appliance image with the release helper script:

```bash
bash ./restore-qcow2.sh
```

Expected result: a restored `neuwerk-<target>.qcow2` image is produced in your working directory.

## AWS Import Flow

- Convert the restored `qcow2` to a raw image:
  `qemu-img convert -f qcow2 -O raw neuwerk-<target>.qcow2 neuwerk-<target>.raw`
- Upload the converted raw image (`neuwerk-<target>.raw`) to S3.
- Use the EC2 VM import path to create an EBS-backed image.
- Launch a VM from the imported image and verify networking before enabling traffic.

Example conversion command:

```bash
qemu-img convert -f qcow2 -O raw neuwerk-<target>.qcow2 neuwerk-<target>.raw
```

## Azure Import Flow

- Convert the restored `qcow2` to a fixed VHD:
  `qemu-img convert -f qcow2 -O vpc -o subformat=fixed neuwerk-<target>.qcow2 neuwerk-<target>.vhd`
- Upload the converted VHD to Azure storage.
- Create a managed image from the uploaded VHD-compatible artifact path you prepared.
- Boot a VM from that image and verify NIC placement and service health.

Example conversion command:

```bash
qemu-img convert -f qcow2 -O vpc -o subformat=fixed neuwerk-<target>.qcow2 neuwerk-<target>.vhd
```

## GCP Import Flow

- Convert the restored `qcow2` to a raw image:
  `qemu-img convert -f qcow2 -O raw neuwerk-<target>.qcow2 neuwerk-<target>.img`
- Package the raw image for import:
  `tar --format=oldgnu -Sczf neuwerk-<target>.img.tar.gz neuwerk-<target>.img`
- Upload the packaged image to Cloud Storage.
- Create a custom Compute Engine image from the uploaded artifact.
- Launch a VM from the custom image and verify service health.

Example conversion and packaging commands:

```bash
qemu-img convert -f qcow2 -O raw neuwerk-<target>.qcow2 neuwerk-<target>.img
tar --format=oldgnu -Sczf neuwerk-<target>.img.tar.gz neuwerk-<target>.img
```

## First Boot And Appliance Configuration

After first boot, apply operator-specific overrides in:

- `/etc/neuwerk/appliance.env`

Use this file for supported runtime overrides such as interface selection, environment-specific tuning, or deployment-time values required by your environment.

## Start And Verify Neuwerk

Check service state:

```bash
systemctl status neuwerk.service
```

Inspect recent logs:

```bash
journalctl -u neuwerk.service
```

Simple post-boot validation flow:

1. Confirm the VM NICs are attached to the intended networks/subnets.
2. Confirm `neuwerk.service` is active and not crash-looping.
3. Confirm logs show clean startup and no persistent backend initialization errors.
4. Validate dataplane reachability with a controlled test flow before routing production traffic.

## Troubleshooting

- If checksum verification fails, re-download artifacts from the same GitHub Release and rerun `sha256sum -c SHA256SUMS`.
- If `restore-qcow2.sh` fails, confirm all `neuwerk-<target>.qcow2.zst.part-*` files are present and unmodified.
- If cloud import fails, re-check the required conversion format for that provider (`raw` for AWS/GCP, fixed `vhd` for Azure).
- If service startup fails, inspect `journalctl -u neuwerk.service` and review `/etc/neuwerk/appliance.env` for invalid overrides.
