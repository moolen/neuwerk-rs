#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  prepare_github_release.sh \
    --target <target-id> \
    --artifact-dir <artifact-dir> \
    --release-version <version> \
    --git-revision <revision> \
    --output-dir <output-dir>

Optional:
  --split-size <size>              Split size for the compressed qcow2 archive. Default: 1900m
  --qcow2-compression-level <n>    zstd level for the qcow2 archive. Default: 10
  --rootfs-compression-level <n>   zstd level for the rootfs archive. Default: 10
EOF
}

require_cmd() {
  local tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing required tool: $tool" >&2
    exit 1
  fi
}

human_size() {
  numfmt --to=iec --suffix=B "$1"
}

file_size() {
  stat -c '%s' "$1"
}

target=""
artifact_dir=""
release_version=""
git_revision=""
output_dir=""
split_size="1900m"
qcow2_compression_level="10"
rootfs_compression_level="10"

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
    --git-revision)
      git_revision="$2"
      shift 2
      ;;
    --output-dir)
      output_dir="$2"
      shift 2
      ;;
    --split-size)
      split_size="$2"
      shift 2
      ;;
    --qcow2-compression-level)
      qcow2_compression_level="$2"
      shift 2
      ;;
    --rootfs-compression-level)
      rootfs_compression_level="$2"
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

if [[ -z "$target" || -z "$artifact_dir" || -z "$release_version" || -z "$git_revision" || -z "$output_dir" ]]; then
  usage >&2
  exit 1
fi

require_cmd find
require_cmd numfmt
require_cmd python3
require_cmd sha256sum
require_cmd sort
require_cmd split
require_cmd stat
require_cmd tar
require_cmd zstd

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
release_dir="${artifact_dir}/release/${target}"
qemu_dir="${artifact_dir}/qemu/${target}"
vagrant_dir="${artifact_dir}/vagrant/${target}"
packer_manifest_path="${artifact_dir}/packer-manifest.json"
source_bundle_path="${artifact_dir}/source/${target}.tar.gz"
rootfs_dir="${release_dir}/rootfs"

if [[ ! -d "$release_dir" ]]; then
  echo "release artifact directory not found: $release_dir" >&2
  exit 1
fi

if [[ ! -d "$rootfs_dir" ]]; then
  echo "staged rootfs not found: $rootfs_dir" >&2
  exit 1
fi

if [[ ! -f "$packer_manifest_path" ]]; then
  echo "packer manifest not found: $packer_manifest_path" >&2
  exit 1
fi

qcow2_path="$(find "$qemu_dir" -maxdepth 1 -type f -name '*.qcow2' | sort | head -n 1)"
if [[ -z "$qcow2_path" ]]; then
  echo "no qcow2 artifact found under: $qemu_dir" >&2
  exit 1
fi

rm -rf "$output_dir"
mkdir -p "$output_dir"

cp "$release_dir/linkage.json" "$output_dir/"
cp "$release_dir/${target}-image.spdx.json" "$output_dir/"
cp "$release_dir/${target}-image.cyclonedx.json" "$output_dir/"
cp "$release_dir/${target}-rootfs.spdx.json" "$output_dir/"
cp "$release_dir/${target}-rootfs.cyclonedx.json" "$output_dir/"
cp "$packer_manifest_path" "$output_dir/"

if [[ -f "$source_bundle_path" ]]; then
  cp "$source_bundle_path" "$output_dir/neuwerk-${target}-source.tar.gz"
fi

if [[ -d "$vagrant_dir" ]]; then
  while IFS= read -r path; do
    cp "$path" "$output_dir/"
  done < <(find "$vagrant_dir" -maxdepth 1 -type f | sort)
fi

rootfs_archive_path="$output_dir/neuwerk-${target}-rootfs.tar.zst"
tar \
  --sort=name \
  --mtime='UTC 2026-01-01' \
  --owner=0 \
  --group=0 \
  --numeric-owner \
  -I "zstd -T0 -${rootfs_compression_level}" \
  -cf "$rootfs_archive_path" \
  -C "$release_dir" \
  rootfs

qcow2_archive_name="$(basename "$qcow2_path").zst"
qcow2_archive_path="$output_dir/$qcow2_archive_name"
zstd -T0 -"${qcow2_compression_level}" -f "$qcow2_path" -o "$qcow2_archive_path"

split --numeric-suffixes=0 --suffix-length=3 --bytes "$split_size" \
  "$qcow2_archive_path" \
  "$output_dir/${qcow2_archive_name}.part-"
rm -f "$qcow2_archive_path"

shopt -s nullglob
qcow2_part_paths=( "$output_dir/${qcow2_archive_name}.part-"* )
shopt -u nullglob

if [[ ${#qcow2_part_paths[@]} -eq 0 ]]; then
  echo "failed to split compressed qcow2 archive" >&2
  exit 1
fi

restore_script_path="$output_dir/restore-qcow2.sh"
cat >"$restore_script_path" <<EOF
#!/usr/bin/env bash
set -euo pipefail

archive="${qcow2_archive_name}"
output="$(basename "$qcow2_path")"

if [[ ! -f SHA256SUMS ]]; then
  echo "SHA256SUMS is required in the current directory" >&2
  exit 1
fi

if ! ls "\${archive}.part-"* >/dev/null 2>&1; then
  echo "missing split archive parts for \${archive}" >&2
  exit 1
fi

grep " \${archive}\\.part-" SHA256SUMS | sha256sum -c
cat "\${archive}.part-"* > "\$archive"
zstd -d -f "\$archive" -o "\$output"

echo "restored \$output"
EOF
chmod 0755 "$restore_script_path"

raw_qcow2_size_bytes="$(file_size "$qcow2_path")"
rootfs_archive_size_bytes="$(file_size "$rootfs_archive_path")"
compressed_parts_size_bytes="$(
  printf '%s\0' "${qcow2_part_paths[@]}" | xargs -0 stat -c '%s' | awk '{sum += $1} END {print sum + 0}'
)"

release_notes_path="$output_dir/release-notes.md"
{
  echo "# Neuwerk Image Release ${release_version}"
  echo
  echo "- Target: \`${target}\`"
  echo "- Git revision: \`${git_revision}\`"
  echo "- Provider artifact: \`$(basename "$qcow2_path")\`"
  echo "- Raw qcow2 size: \`$(human_size "$raw_qcow2_size_bytes")\` (${raw_qcow2_size_bytes} bytes)"
  echo "- GitHub-safe qcow2 archive: \`${qcow2_archive_name}.part-*\` across ${#qcow2_part_paths[@]} part(s), total \`$(human_size "$compressed_parts_size_bytes")\`"
  echo "- Rootfs archive: \`$(basename "$rootfs_archive_path")\` at \`$(human_size "$rootfs_archive_size_bytes")\`"
  echo
  echo "## Supported Appliance Contract"
  echo
  echo "- Ubuntu 24.04 is the supported appliance base for this release."
  echo "- GitHub Releases is the canonical distribution channel."
  echo "- AWS, Azure, and GCP are supported as manual import targets."
  echo "- The image is built with the existing vendored Neuwerk runtime contract."
  echo "- Provider-native image publication is not automated in this phase."
  echo "- See \`docs/operations/appliance-image-usage.md\` for the operator guide."
  echo
  echo "## Attached Assets"
  while IFS= read -r asset_name; do
    asset_path="$output_dir/$asset_name"
    echo "- \`${asset_name}\` (\`$(human_size "$(file_size "$asset_path")")\`)"
  done < <(find "$output_dir" -maxdepth 1 -type f ! -name 'manifest.json' ! -name 'SHA256SUMS' -printf '%f\n' | sort)
  echo
  echo "## Restore The qcow2"
  echo
  echo '```bash'
  echo 'sha256sum -c SHA256SUMS'
  echo "bash ./restore-qcow2.sh"
  echo '```'
  echo
  echo "The raw \`qcow2\` exceeds GitHub's per-file release-asset limit, so the workflow publishes a compressed multi-part archive instead."
} >"$release_notes_path"

mapfile -t artifact_names < <(find "$output_dir" -maxdepth 1 -type f ! -name 'manifest.json' ! -name 'SHA256SUMS' -printf '%f\n' | sort)

(
  cd "$output_dir"
  sha256sum "${artifact_names[@]}" > SHA256SUMS
)

artifact_names+=( "SHA256SUMS" )

manifest_cmd=(
  python3
  "$repo_root/packaging/scripts/generate_release_manifest.py"
  --target "$target"
  --provider qemu
  --release-version "$release_version"
  --git-revision "$git_revision"
  --image-reference "$(basename "$qcow2_path")"
  --output manifest.json
)

for artifact_name in "${artifact_names[@]}"; do
  manifest_cmd+=( --artifact "$artifact_name" )
done

(
  cd "$output_dir"
  "${manifest_cmd[@]}"
)

echo "prepared GitHub release assets in $output_dir"
