# Local VM Demo

## Goal

Provide a low-fuss local evaluation path for Neuwerk on laptops using:

- `vagrant up`
- a provider-native VM image
- a dedicated management IP
- a client-facing gateway IP that the host can route through

## Chosen Shape

The recommended first implementation is:

- Vagrant as the user-facing workflow
- VirtualBox as the primary provider
- a separate demo box artifact per release
- software dataplane mode inside the guest for the demo path

This is intentionally separate from the production appliance packaging contract.

## Why Not Reuse The Current `qcow2` Directly

The current local image release path publishes a compressed split `qcow2`.

That artifact is appropriate for QEMU and cloud-image workflows, but a Vagrant user experience is
better when the release is already packaged as a provider-native `.box` for the selected provider.

## Guest Design

The local demo guest should boot with demo defaults:

- Neuwerk UI listening on the management adapter
- metrics on the management adapter
- a dedicated client-facing host-only adapter
- a dedicated internet uplink adapter
- `neuwerk.service` running in software `tun` mode for compatibility

This lets the user point the host default route at the VM and exercise real browser or CLI traffic
through Neuwerk.

## Checked-In Demo Workflow

The repository now includes:

- a checked-in [Vagrantfile](/home/moritz/dev/neuwerk-rs/firewall/demo/vagrant/Vagrantfile)
- a first-boot guest provisioner at [provision-demo.sh](/home/moritz/dev/neuwerk-rs/firewall/demo/vagrant/provision-demo.sh)

That provisioner turns a base appliance box into a local demo guest by:

- discovering the uplink, management, and client interfaces
- forcing the runtime into software `tun` mode
- using the file-backed local HTTP auth keyset under `/var/lib/neuwerk/http-tls`
- assigning a dedicated secondary uplink SNAT IP for Neuwerk-translated traffic
- installing policy-routing rules that steer client traffic into `dp0` and only steer return
  traffic for the dedicated SNAT IP back through `dp0`
- minting an admin token into `/var/lib/neuwerk-demo/admin.token`

This keeps the provider box close to the base appliance image while still making `vagrant up`
usable as a real gateway demo.

The checked-in Vagrant workflow should prefer the `ubuntu-24.04-minimal-amd64` target so the
demo box starts from Ubuntu Minimal rather than the larger general-purpose server cloud image.

## Release Pipeline Changes

The preferred release design is:

1. Keep the current `qcow2` appliance release for QEMU and cloud workflows.
2. Add a provider-native box build for `virtualbox`.
3. Publish that box as a versioned Vagrant artifact.
4. Publish a Vagrant `metadata.json` that references the provider box.
5. Point the checked-in demo `Vagrantfile` at the published box name or metadata URL.

The box publication should be treated as a first-class release artifact, not as a manual
post-processing step.

The repository now includes
[generate_vagrant_box_metadata.py](/home/moritz/dev/neuwerk-rs/firewall/packaging/scripts/generate_vagrant_box_metadata.py)
for generating that `metadata.json`.

## Future Expansion

Optional future work:

- add a VMware Desktop provider artifact
- add an `arm64` target for Apple Silicon hosts
- add richer host route helper tooling for Linux and macOS rollback
- add a second VM for deterministic upstream simulation if needed in addition to real internet egress

## Current Scope Recommendation

For the first iteration:

- support `amd64/x86_64` hosts
- support the `virtualbox` provider
- optimize for UI access plus real host-as-client routing
