# Appliance Image Usage

## Supported Scope

- Ubuntu 24.04 is the only supported appliance base in this phase.
- The only supported published target is `ubuntu-24.04-minimal-amd64`.
- GitHub Releases is the canonical distribution channel for appliance artifacts.
- The published release contains a generic `qcow2` appliance bundle plus release metadata.
- AWS, Azure, and GCP are currently supported as manual import targets.
- Provider-native image publication is not automated in this phase.
- This guide covers operator usage of published release artifacts only, not Terraform automation or provider-native publication pipelines.

## Deployment Prerequisites

Before importing the image, plan for the following:

- A Linux workstation with `sha256sum`, `qemu-img`, `tar`, and `zstd`.
- The provider CLI used in the examples below:
  - `aws` for AWS
  - `az` for Azure
  - `gcloud` for GCP
- A VM layout with separate management and dataplane NICs.

Neuwerk expects distinct management and dataplane interfaces. If you boot the appliance with only one usable NIC, `neuwerk.service` can fail until you correct the interface layout and restart it.

## Download And Verify Release Assets

The minimum asset set needed to restore the published appliance image is:

- `neuwerk-ubuntu-24.04-minimal-amd64.qcow2.zst.part-*`
- `restore-qcow2.sh`
- `SHA256SUMS`
- `SHA256SUMS.sig`
- `neuwerk-release-signing-key.asc`

The full release typically also includes:

- `manifest.json`
- `release-notes.md`
- `linkage.json`
- `packer-manifest.json`
- `neuwerk-ubuntu-24.04-minimal-amd64-rootfs.tar.zst`
- `neuwerk-ubuntu-24.04-minimal-amd64-source.tar.gz`
- image and rootfs SBOM files in SPDX and CycloneDX formats
- any release-specific extras attached for that release

Download the selected release into one working directory and verify it there:

Current shared Neuwerk release-signing fingerprint:

- `DC34EB84D498D1445B68CB405E6B936CF37928C3`

```bash
gpg --import neuwerk-release-signing-key.asc
gpg --show-keys --with-fingerprint neuwerk-release-signing-key.asc
gpg --verify SHA256SUMS.sig SHA256SUMS
sha256sum -c SHA256SUMS
```

Expected result: all downloaded files report `OK`.

## Restore The Published `qcow2`

Rebuild and decompress the split appliance archive with the shipped helper script:

```bash
bash ./restore-qcow2.sh
```

Expected result: a restored `neuwerk-ubuntu-24.04-minimal-amd64.qcow2` file is produced in the current working directory.

## AWS Import Flow

Reference: [Import a VM as an image using VM Import/Export](https://docs.aws.amazon.com/vm-import/latest/userguide/import-vm-image.html)

AWS import prerequisites:

- an S3 bucket in the target AWS Region
- the `vmimport` service role required by VM Import/Export
- a plan to launch the imported image with separate management and dataplane ENIs

Convert the restored appliance image to `raw`:

```bash
qemu-img convert \
  -f qcow2 \
  -O raw \
  neuwerk-ubuntu-24.04-minimal-amd64.qcow2 \
  neuwerk-ubuntu-24.04-minimal-amd64.raw
```

Upload the converted image to S3:

```bash
aws s3 cp \
  neuwerk-ubuntu-24.04-minimal-amd64.raw \
  s3://<bucket>/neuwerk-ubuntu-24.04-minimal-amd64.raw
```

Start the import task:

```bash
aws ec2 import-image \
  --description "Neuwerk ubuntu-24.04-minimal-amd64" \
  --disk-containers "Format=raw,UserBucket={S3Bucket=<bucket>,S3Key=neuwerk-ubuntu-24.04-minimal-amd64.raw}"
```

Poll the task until AWS returns the resulting AMI:

```bash
aws ec2 describe-import-image-tasks \
  --import-task-ids <import-task-id>
```

Launch the resulting AMI with a management NIC and a separate dataplane NIC. After the instance is reachable over SSH, continue with [First Boot And Appliance Configuration](#first-boot-and-appliance-configuration).

## Azure Import Flow

Reference: [Create a VM from a specialized disk](https://learn.microsoft.com/en-us/azure/virtual-machines/linux/create-vm-specialized)

This guide documents a manual specialized-disk import path for the published appliance artifact. It does not claim that the shipped release artifact is already generalized for Azure image-gallery publication.

Convert the restored appliance image to a fixed-size VHD:

```bash
qemu-img convert \
  -f qcow2 \
  -O vpc \
  -o subformat=fixed \
  neuwerk-ubuntu-24.04-minimal-amd64.qcow2 \
  neuwerk-ubuntu-24.04-minimal-amd64.vhd
```

Upload the VHD as a page blob:

```bash
az storage blob upload \
  --account-name <storage-account> \
  --container-name <container> \
  --name neuwerk-ubuntu-24.04-minimal-amd64.vhd \
  --file neuwerk-ubuntu-24.04-minimal-amd64.vhd \
  --type page
```

Create a managed disk from the uploaded VHD:

```bash
az disk create \
  --resource-group <resource-group> \
  --name neuwerk-ubuntu-24.04-minimal-amd64 \
  --source https://<storage-account>.blob.core.windows.net/<container>/neuwerk-ubuntu-24.04-minimal-amd64.vhd
```

Create a VM from that specialized OS disk:

```bash
az vm create \
  --resource-group <resource-group> \
  --name neuwerk-appliance \
  --attach-os-disk neuwerk-ubuntu-24.04-minimal-amd64 \
  --os-type Linux \
  --specialized
```

Attach or pre-provision a second NIC for the dataplane before treating the appliance as ready. Then continue with [First Boot And Appliance Configuration](#first-boot-and-appliance-configuration).

## GCP Import Flow

Reference: [Manually import an existing virtual disk](https://docs.cloud.google.com/compute/docs/import/importing-virtual-disks)

Google's manual import path expects a compressed tarball containing a single raw disk file named `disk.raw`.

Convert the restored appliance image to `raw`:

```bash
qemu-img convert \
  -f qcow2 \
  -O raw \
  neuwerk-ubuntu-24.04-minimal-amd64.qcow2 \
  disk.raw
```

Package that raw disk with the required filename:

```bash
tar --format=oldgnu -Sczf \
  neuwerk-ubuntu-24.04-minimal-amd64-disk.raw.tar.gz \
  disk.raw
```

Upload the tarball to Cloud Storage:

```bash
gcloud storage cp \
  neuwerk-ubuntu-24.04-minimal-amd64-disk.raw.tar.gz \
  gs://<bucket>/neuwerk-ubuntu-24.04-minimal-amd64-disk.raw.tar.gz
```

Create a custom image from the uploaded tarball:

```bash
gcloud compute images create neuwerk-ubuntu-24-04-minimal-amd64 \
  --source-uri=gs://<bucket>/neuwerk-ubuntu-24.04-minimal-amd64-disk.raw.tar.gz
```

Launch an instance from the image with separate management and dataplane NICs. Google documents that manually imported images also need the guest environment installed after first boot before you rely on normal Compute Engine guest integration, metadata handling, or guest-agent behavior.

Continue with [First Boot And Appliance Configuration](#first-boot-and-appliance-configuration) after the instance is reachable.

## First Boot And Appliance Configuration

The packaged runtime contract is:

- `/etc/neuwerk/config.yaml`

Edit subsystem YAML paths directly in that file, then restart `neuwerk.service`.

For the canonical operator-facing reference for supported YAML runtime paths, defaults, and guidance, see [Runtime Configuration Reference](./runtime-knobs.md).

At minimum, verify or set:

- `bootstrap.cloud_provider` when runtime discovery needs an explicit provider hint
- `bootstrap.management_interface`
- `bootstrap.data_interface`
- `dns.upstreams` reachable from the management network

Example starter configuration:

```bash
sudo tee /etc/neuwerk/config.yaml >/dev/null <<'EOF'
version: 1
bootstrap:
  cloud_provider: aws
  management_interface: eth0
  data_interface: eth1
  data_plane_mode: dpdk
dns:
  upstreams:
    - 10.0.0.2:53
    - 10.0.0.3:53
policy:
  default: deny
dataplane:
  snat: auto
EOF
```

If the dataplane NIC comes up under a different name than expected, update `bootstrap.data_interface` to match the actual interface before restarting `neuwerk.service`.

Other operator-tunable subsystem YAML paths live in the same file, for example:

- `metrics.bind`
- `metrics.allow_public_bind`
- `integration.mode`
- `integration.aws.region`
- `tls_intercept.upstream_verify`
- `dataplane.flow_incomplete_tcp_idle_timeout_secs`
- `dataplane.flow_incomplete_tcp_syn_sent_idle_timeout_secs`
- `dpdk.service_lane.intercept_service_ip`

Useful discovery commands:

```bash
ip -br link
ip -4 -br addr
```

## Start And Verify Neuwerk

After editing `/etc/neuwerk/config.yaml`, restart the service:

```bash
sudo systemctl restart neuwerk.service
```

Check service state:

```bash
systemctl status neuwerk.service --no-pager
```

Inspect recent boot logs:

```bash
journalctl -u neuwerk.service -b --no-pager
```

Simple post-boot validation flow:

1. Confirm the VM has separate management and dataplane NICs attached to the intended networks.
2. Confirm `neuwerk.service` is active and not crash-looping.
3. Confirm `/etc/neuwerk/config.yaml` still matches your intended subsystem YAML paths after any first-boot automation.
4. Confirm logs show clean startup and no persistent backend initialization errors.
5. Validate dataplane reachability with a controlled test flow before routing production traffic.

## Troubleshooting

- If checksum verification fails, re-download artifacts from the same GitHub Release and rerun `sha256sum -c SHA256SUMS`.
- If `restore-qcow2.sh` fails, confirm all `neuwerk-ubuntu-24.04-minimal-amd64.qcow2.zst.part-*` files are present and unmodified in the current directory.
- If AWS import fails, verify the `vmimport` role exists and that you uploaded a `raw` image to S3 in the target Region.
- If Azure import fails, verify you uploaded a fixed-size VHD as a page blob and that you are following the specialized-disk flow documented above.
- If GCP import fails, verify the tarball contains a single file named `disk.raw`.
- If `neuwerk.service` fails on first boot, check for config-file issues such as:
  - invalid YAML syntax in `/etc/neuwerk/config.yaml`
  - unknown or misspelled subsystem keys
  - missing required interface, DNS, or integration fields
  - semantic validation failures for the selected dataplane or integration mode
- If GCP boots but metadata-driven integration is missing, install the documented Compute Engine guest environment packages before proceeding.
