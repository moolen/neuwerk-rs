#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  build_vagrant_box.sh \
    --target <target-id> \
    --artifact-dir <artifact-dir> \
    --release-version <version> \
    --provider <provider> \
    --box-name <box-name> \
    --box-version <box-version> \
    --output-box <path>

Optional:
  --memory <mb>                VirtualBox VM memory for the packaged appliance. Default: 4096
  --cpus <count>               VirtualBox VM CPU count for the packaged appliance. Default: 4
  --box-url <url>              If set, also generate Vagrant metadata.json for this download URL
  --metadata-output <path>     metadata.json path when --box-url is set
EOF
}

require_cmd() {
  local tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing required tool: $tool" >&2
    exit 1
  fi
}

sanitize_name() {
  printf '%s' "$1" | tr -cs 'A-Za-z0-9._-' '-'
}

set_shadow_password_hash() {
  local shadow_path="$1"
  local username="$2"
  local password_hash="$3"

  $SUDO python3 - "$shadow_path" "$username" "$password_hash" <<'PY'
import sys

shadow_path, username, password_hash = sys.argv[1:4]
lines = []
found = False

with open(shadow_path, "r", encoding="utf-8") as handle:
    for raw_line in handle:
        line = raw_line.rstrip("\n")
        fields = line.split(":")
        if fields[0] == username:
            fields[1] = password_hash
            found = True
            line = ":".join(fields)
        lines.append(line)

if not found:
    raise SystemExit(f"user not found in shadow file: {username}")

with open(shadow_path, "w", encoding="utf-8") as handle:
    handle.write("\n".join(lines) + "\n")
PY
}

ensure_sshd_setting() {
  local sshd_config_path="$1"
  local key="$2"
  local value="$3"

  $SUDO python3 - "$sshd_config_path" "$key" "$value" <<'PY'
import pathlib
import re
import sys

config_path = pathlib.Path(sys.argv[1])
key = sys.argv[2]
value = sys.argv[3]
pattern = re.compile(rf"^\s*#?\s*{re.escape(key)}\s+.*$", re.IGNORECASE)

lines = config_path.read_text(encoding="utf-8").splitlines()
replaced = False
updated = []

for line in lines:
    if pattern.match(line):
        if not replaced:
            updated.append(f"{key} {value}")
            replaced = True
        continue
    updated.append(line)

if not replaced:
    if updated and updated[-1] != "":
        updated.append("")
    updated.append(f"{key} {value}")

config_path.write_text("\n".join(updated) + "\n", encoding="utf-8")
PY
}

install_authorized_key() {
  local mount_root="$1"
  local username="$2"
  local public_key="$3"

  $SUDO python3 - "$mount_root" "$username" "$public_key" <<'PY'
import os
import pathlib
import sys

mount_root = pathlib.Path(sys.argv[1])
username = sys.argv[2]
public_key = sys.argv[3].strip()

passwd_path = mount_root / "etc/passwd"
passwd_entry = None
for raw_line in passwd_path.read_text(encoding="utf-8").splitlines():
    if not raw_line or raw_line.startswith("#"):
        continue
    fields = raw_line.split(":")
    if len(fields) < 7:
        continue
    if fields[0] == username:
        passwd_entry = {
            "uid": int(fields[2]),
            "gid": int(fields[3]),
            "home": fields[5],
        }
        break

if passwd_entry is None:
    raise SystemExit(f"user not found in passwd file: {username}")

home_dir = mount_root / passwd_entry["home"].lstrip("/")
ssh_dir = home_dir / ".ssh"
auth_keys = ssh_dir / "authorized_keys"

ssh_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

entries = []
if auth_keys.exists():
    entries = [line.strip() for line in auth_keys.read_text(encoding="utf-8").splitlines() if line.strip()]

if public_key not in entries:
    entries.append(public_key)

auth_keys.write_text("\n".join(entries) + "\n", encoding="utf-8")
os.chmod(ssh_dir, 0o700)
os.chmod(auth_keys, 0o600)
os.chown(ssh_dir, passwd_entry["uid"], passwd_entry["gid"])
os.chown(auth_keys, passwd_entry["uid"], passwd_entry["gid"])
PY
}

target=""
artifact_dir=""
release_version=""
provider=""
box_name=""
box_version=""
output_box=""
box_url=""
metadata_output=""
memory="4096"
cpus="4"
vagrant_ssh_username="ubuntu"
vagrant_ssh_password_hash='$6$neuwerksalt$BCxXfRyxQRR2Y9GyF3lV2Ot/p0DPYfDBjefpDxEbhEEcSjryi3WiFjWAcWFZ6m8LaASwS2LkJag..0/lRcuMj.'
vagrant_insecure_public_key='ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA6NF8iallvQVp22WDkTkyrtvp9eWW6A8YVr+kz4TjGYe7gHzIw+niNltGEFHzD8+v1I2YJ6oXevct1YeS0o9HZyN1Q9qgCgzUFtdOKLv6IedplqoPkcmF0aYet2PkEDo3MlTBckFXPITAMzF8dJSIFo9D8HfdOV0IAdx4O7PtixWKn5y2hMNG0zQPyUecp4pzC6kivAIhyfHilFR61RGL+GPXQ2MWZWFYbAGjyiYJnAmCP3NOTd0jMZEnDkbUvxhMmBYSdETk1rRgm+R4LOzFUGaHqHDLKLX+FIPKcF96hrucXzcWyLbIbEgE98OHlnVYCzRdK8jlqm8tehUc9c9WhQ=='

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      target="$2"
      shift 2
      ;;
    --artifact-dir)
      artifact_dir="$2"
      shift 2
      ;;
    --release-version)
      release_version="$2"
      shift 2
      ;;
    --provider)
      provider="$2"
      shift 2
      ;;
    --box-name)
      box_name="$2"
      shift 2
      ;;
    --box-version)
      box_version="$2"
      shift 2
      ;;
    --output-box)
      output_box="$2"
      shift 2
      ;;
    --memory)
      memory="$2"
      shift 2
      ;;
    --cpus)
      cpus="$2"
      shift 2
      ;;
    --box-url)
      box_url="$2"
      shift 2
      ;;
    --metadata-output)
      metadata_output="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$target" || -z "$artifact_dir" || -z "$release_version" || -z "$provider" || -z "$box_name" || -z "$box_version" || -z "$output_box" ]]; then
  usage >&2
  exit 1
fi

if [[ "$provider" != "virtualbox" ]]; then
  echo "unsupported provider: $provider (expected virtualbox)" >&2
  exit 1
fi

if [[ -n "$box_url" && -z "$metadata_output" ]]; then
  echo "--metadata-output is required when --box-url is set" >&2
  exit 1
fi

require_cmd VBoxManage
require_cmd chroot
require_cmd find
require_cmd losetup
require_cmd mount
require_cmd qemu-img
require_cmd python3
require_cmd sha256sum
require_cmd tar
require_cmd umount

if [[ "$(id -u)" -eq 0 ]]; then
  SUDO=""
else
  require_cmd sudo
  SUDO="sudo"
fi

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
qemu_dir="${artifact_dir}/qemu/${target}"
qcow2_path="$(find "$qemu_dir" -maxdepth 1 -type f -name '*.qcow2' | sort | head -n 1)"
if [[ -z "$qcow2_path" ]]; then
  echo "no qcow2 artifact found under: $qemu_dir" >&2
  exit 1
fi

output_box="$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$output_box")"
output_dir="$(dirname "$output_box")"
mkdir -p "$output_dir"

build_tmp_root="${artifact_dir}/tmp"
mkdir -p "$build_tmp_root"
work_dir="$(mktemp -d "${build_tmp_root}/vagrant-box.XXXXXX")"
sanitized_target="$(sanitize_name "$target")"
sanitized_release="$(sanitize_name "$release_version")"
vm_name="neuwerk-${sanitized_target}-${sanitized_release}-vagrant-box-$$"
vm_registered=0
loopdev=""
mount_dir=""
boot_mount_dir=""
efi_mount_dir=""

cleanup() {
  set +e
  if [[ -n "$mount_dir" ]]; then
    $SUDO umount "$mount_dir/dev/pts" >/dev/null 2>&1 || true
    $SUDO umount "$mount_dir/dev" >/dev/null 2>&1 || true
    $SUDO umount "$mount_dir/proc" >/dev/null 2>&1 || true
    $SUDO umount "$mount_dir/sys" >/dev/null 2>&1 || true
    $SUDO umount "$mount_dir/run" >/dev/null 2>&1 || true
  fi
  if [[ -n "$efi_mount_dir" ]]; then
    $SUDO umount "$efi_mount_dir" >/dev/null 2>&1 || true
  fi
  if [[ -n "$boot_mount_dir" ]]; then
    $SUDO umount "$boot_mount_dir" >/dev/null 2>&1 || true
  fi
  if [[ -n "$mount_dir" ]]; then
    $SUDO umount "$mount_dir" >/dev/null 2>&1 || true
  fi
  if [[ -n "$loopdev" ]]; then
    $SUDO losetup -d "$loopdev" >/dev/null 2>&1 || true
  fi
  if [[ $vm_registered -eq 1 ]]; then
    VBoxManage unregistervm "$vm_name" --delete >/dev/null 2>&1 || true
  fi
  rm -rf "$work_dir"
}
trap cleanup EXIT

connect_loop() {
  local image="$1"
  $SUDO losetup --show -Pf "$image"
}

prepare_guest_networking() {
  local image="$1"
  local root_partition=""
  local boot_partition=""
  local efi_partition=""
  local probe_attempt=0
  local original_resolv_target=""

  loopdev="$(connect_loop "$image")" || {
    echo "failed to connect image to a loop device" >&2
    exit 1
  }

  for probe_attempt in {1..10}; do
    if command -v udevadm >/dev/null 2>&1; then
      $SUDO udevadm settle >/dev/null 2>&1 || true
    fi
    if $SUDO test -b "${loopdev}p1"; then
      break
    fi
    sleep 1
  done

  root_partition="$($SUDO lsblk -lnpo NAME,FSTYPE,LABEL "$loopdev" | awk '$2 == "ext4" && $3 == "cloudimg-rootfs" {print $1; exit}')"
  if [[ -z "$root_partition" ]]; then
    root_partition="$($SUDO lsblk -lnpo NAME,FSTYPE "$loopdev" | awk '$2 == "ext4" {print $1; exit}')"
  fi
  if [[ -z "$root_partition" ]]; then
    echo "failed to locate root filesystem partition in $image" >&2
    exit 1
  fi
  boot_partition="$($SUDO lsblk -lnpo NAME,FSTYPE,LABEL "$loopdev" | awk '$2 == "ext4" && $3 == "BOOT" {print $1; exit}')"
  efi_partition="$($SUDO lsblk -lnpo NAME,FSTYPE,LABEL "$loopdev" | awk '$2 == "vfat" && $3 == "UEFI" {print $1; exit}')"

  mount_dir="${work_dir}/mnt"
  mkdir -p "$mount_dir"
  $SUDO mount "$root_partition" "$mount_dir"
  if [[ -n "$boot_partition" ]]; then
    boot_mount_dir="${mount_dir}/boot"
    $SUDO mkdir -p "$boot_mount_dir"
    $SUDO mount "$boot_partition" "$boot_mount_dir"
    if [[ -n "$efi_partition" ]]; then
      efi_mount_dir="${boot_mount_dir}/efi"
      $SUDO mkdir -p "$efi_mount_dir"
      $SUDO mount "$efi_partition" "$efi_mount_dir"
    fi
  fi

  $SUDO mkdir -p "$mount_dir/etc/netplan" "$mount_dir/etc/cloud/cloud.cfg.d"
  $SUDO tee "$mount_dir/etc/netplan/01-vagrant-dhcp.yaml" >/dev/null <<'EOF'
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: true
      dhcp6: true
EOF
  $SUDO chmod 0600 "$mount_dir/etc/netplan/01-vagrant-dhcp.yaml"
  $SUDO rm -f "$mount_dir/etc/netplan/50-cloud-init.yaml"
  $SUDO tee "$mount_dir/etc/cloud/cloud.cfg.d/99-neuwerk-vagrant-network.cfg" >/dev/null <<'EOF'
network:
  config: disabled
EOF
  $SUDO tee "$mount_dir/etc/cloud/cloud.cfg.d/99-neuwerk-vagrant-ssh.cfg" >/dev/null <<'EOF'
ssh_pwauth: true
EOF
  ensure_sshd_setting "$mount_dir/etc/ssh/sshd_config" "PasswordAuthentication" "yes"
  ensure_sshd_setting "$mount_dir/etc/ssh/sshd_config" "KbdInteractiveAuthentication" "no"
  ensure_sshd_setting "$mount_dir/etc/ssh/sshd_config" "PubkeyAuthentication" "yes"
  ensure_sshd_setting "$mount_dir/etc/ssh/sshd_config" "UsePAM" "yes"
  set_shadow_password_hash "$mount_dir/etc/shadow" "$vagrant_ssh_username" "$vagrant_ssh_password_hash"
  install_authorized_key "$mount_dir" "$vagrant_ssh_username" "$vagrant_insecure_public_key"
  $SUDO rm -f "$mount_dir/etc/default/grub.d/40-force-partuuid.cfg"
  $SUDO mkdir -p "$mount_dir/etc/default/grub.d"
  $SUDO tee "$mount_dir/etc/default/grub.d/99-neuwerk-vagrant.cfg" >/dev/null <<'EOF'
GRUB_DISABLE_LINUX_PARTUUID=true
EOF
  if $SUDO test -L "$mount_dir/etc/resolv.conf"; then
    original_resolv_target="$($SUDO readlink "$mount_dir/etc/resolv.conf")"
  fi
  $SUDO rm -f "$mount_dir/etc/resolv.conf"
  $SUDO cp -L /etc/resolv.conf "$mount_dir/etc/resolv.conf"
  $SUDO mkdir -p "$mount_dir/dev/pts" "$mount_dir/proc" "$mount_dir/sys" "$mount_dir/run"
  for bind_path in dev dev/pts proc sys run; do
    $SUDO mount --bind "/${bind_path}" "${mount_dir}/${bind_path}"
  done
  if ! $SUDO test -x "$mount_dir/usr/sbin/update-initramfs"; then
    $SUDO chroot "$mount_dir" /usr/bin/env \
      DEBIAN_FRONTEND=noninteractive \
      PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
      apt-get update
    $SUDO chroot "$mount_dir" /usr/bin/env \
      DEBIAN_FRONTEND=noninteractive \
      PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
      apt-get install -y initramfs-tools
  fi
  if ! $SUDO find "$mount_dir/boot" -maxdepth 1 -name 'initrd.img-*' | grep -q .; then
    $SUDO chroot "$mount_dir" /usr/bin/env \
      PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
      /usr/sbin/update-initramfs -c -k all
  else
    $SUDO chroot "$mount_dir" /usr/bin/env \
      PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
      /usr/sbin/update-initramfs -u -k all
  fi
  $SUDO chroot "$mount_dir" /usr/bin/env \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    /usr/sbin/update-grub
  for bind_path in run sys proc dev/pts dev; do
    $SUDO umount "${mount_dir}/${bind_path}" >/dev/null 2>&1 || true
  done
  if [[ -n "$original_resolv_target" ]]; then
    $SUDO rm -f "$mount_dir/etc/resolv.conf"
    $SUDO ln -s "$original_resolv_target" "$mount_dir/etc/resolv.conf"
  fi
  $SUDO rm -rf "$mount_dir/var/lib/cloud/instances" "$mount_dir/var/lib/cloud/instance" "$mount_dir/var/lib/cloud/data" "$mount_dir/var/lib/cloud/sem"
  $SUDO sync
  if [[ -n "$efi_mount_dir" ]]; then
    $SUDO umount "$efi_mount_dir"
    efi_mount_dir=""
  fi
  if [[ -n "$boot_mount_dir" ]]; then
    $SUDO umount "$boot_mount_dir"
    boot_mount_dir=""
  fi
  $SUDO umount "$mount_dir"
  mount_dir=""
  $SUDO losetup -d "$loopdev" >/dev/null
  loopdev=""
}

source_raw="${work_dir}/source-disk.raw"
source_vdi="${work_dir}/source-disk.vdi"
export_dir="${work_dir}/export"
vm_base="${work_dir}/virtualbox"
mkdir -p "$export_dir" "$vm_base"

qemu-img convert \
  -f qcow2 \
  -O raw \
  "$qcow2_path" \
  "$source_raw"

prepare_guest_networking "$source_raw"

qemu-img convert \
  -f raw \
  -O vdi \
  "$source_raw" \
  "$source_vdi"

VBoxManage createvm --name "$vm_name" --ostype Ubuntu_64 --basefolder "$vm_base" --register >/dev/null
vm_registered=1
VBoxManage modifyvm "$vm_name" \
  --memory "$memory" \
  --cpus "$cpus" \
  --ioapic on \
  --audio-enabled off \
  --usb off \
  --nic1 nat \
  --cableconnected1 on >/dev/null
VBoxManage storagectl "$vm_name" --name "SATA Controller" --add sata --controller IntelAhci --portcount 4 --bootable on >/dev/null
VBoxManage storageattach "$vm_name" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "$source_vdi" >/dev/null

VBoxManage export "$vm_name" --output "${export_dir}/box.ovf" --ovf20 >/dev/null

cat >"${export_dir}/metadata.json" <<'EOF'
{
  "provider": "virtualbox",
  "format": "ovf"
}
EOF

cat >"${export_dir}/Vagrantfile" <<'EOF'
Vagrant.configure("2") do |config|
  config.vm.synced_folder ".", "/vagrant", disabled: true
end
EOF

rm -f "$output_box"
(
  cd "$export_dir"
  tar -cf "$output_box" .
)

checksum="$(sha256sum "$output_box" | awk '{print $1}')"
printf '%s  %s\n' "$checksum" "$(basename "$output_box")" >"${output_box}.sha256"

if [[ -n "$box_url" ]]; then
  python3 "${repo_root}/packaging/scripts/generate_vagrant_box_metadata.py" \
    --box-name "$box_name" \
    --version "$box_version" \
    --provider "$provider" \
    --url "$box_url" \
    --checksum "$checksum" \
    --output "$metadata_output"
fi

echo "built Vagrant box: $output_box"
