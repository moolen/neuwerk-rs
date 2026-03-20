GCP runtime bundles are local build artifacts and are intentionally not committed.

Pass the exact tarball you want to validate via Terraform:

`terraform apply -var 'neuwerk_dpdk_runtime_bundle_path=/absolute/path/to/dpdk-runtime.tar.gz'`

Keep the runtime bundle provenance aligned with the Neuwerk binary and the Ubuntu 24.04 / DPDK 23.11 bench assumption.
