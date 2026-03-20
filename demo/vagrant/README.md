# Neuwerk Vagrant Demo

This directory defines the local-demo shape for Neuwerk as a VM-first workflow.

The intended user experience is:

```bash
cd demo/vagrant
./launch-demo.sh
vagrant ssh
```

The VM gives the user:

- a dedicated management IP for the Neuwerk UI and API
- a shell inside the appliance with `vagrant ssh`
- a client-facing gateway IP that the host can route through
- a demo admin token written inside the guest
- a release-backed Vagrant box path so local users do not need to build the image first

## Why This Path

The repository's normal release artifact for local virtualization is a `qcow2` appliance image.
That is a good fit for QEMU and cloud image publishing, but not for a portable Vagrant experience.

For a Vagrant-based demo we standardize on:

- `vagrant` as the lifecycle tool
- `virtualbox` as the first provider
- a provider-native Vagrant box artifact published per release

This keeps the user workflow simple and avoids asking users to manually restore a `qcow2`,
import it into a hypervisor, and then discover the right networking by hand.

## Demo Topology

The gateway demo uses three appliance-facing interfaces plus the software dataplane device:

1. Uplink
A VirtualBox bridged adapter on the host uplink, by default `wlan0`. This is the VM's
internet-facing egress path and the firewall SNATs through the bridged interface's primary IP.

The default NAT adapter remains present so `vagrant up` and `vagrant ssh` keep working
reliably during boot.

2. Management
A host-only adapter with a stable management IP. The UI, API, and `vagrant ssh` use this path.

3. Client
A host-only adapter with a stable gateway IP. The host can point its default route here.

4. Software dataplane device
A `tun` interface created by the firewall inside the guest.

The firewall runs in software mode for the Vagrant demo. The production appliance remains
DPDK-oriented; the demo box is a separate packaging target with demo-oriented defaults.

## User Workflow

The intended workflow is:

1. `./launch-demo.sh`
2. Open the UI on the management IP, by default `https://192.168.57.10:8443`
3. `vagrant ssh`
4. Read the admin token from `/var/lib/neuwerk-demo/admin.token`
5. Point the host default route at the client gateway IP, by default `192.168.56.10`
6. Test browser or CLI traffic from the host through the VM

This path is meant to support real host-to-internet gateway testing.

## What Provisioning Does

The checked-in `Vagrantfile` runs `provision-demo.sh` on first boot. That provisioning step:

- discovers the bridged uplink, management, and client interfaces
- switches the firewall service into software `tun` mode
- enables a local single-node cluster on `127.0.0.1:9600`
- uses the bridged uplink's primary DHCP address as the dataplane SNAT source
- installs policy-routing rules that steer client traffic into `dp0`
- mints an admin token to `/var/lib/neuwerk-demo/admin.token`

If the host uplink is not `wlan0`, set `NEUWERK_BRIDGED_IFACE` before running `launch-demo.sh`.

For the normal path, use `launch-demo.sh` in this directory. It resolves the host uplink,
discovers the published GitHub release box metadata, checks the local prerequisites, asks for
confirmation, runs `vagrant up --provision`, and prints the UI login token from the guest.

Useful guest commands:

```bash
cat /var/lib/neuwerk-demo/admin.token
ip -4 addr show
ip rule show
ip route show table 100
```

## Recommended First Phase

Phase 1 should ship a single-VM box with:

- a stable management IP for UI and API access
- a stable client-facing gateway IP for host routing
- a dedicated uplink path for internet egress
- a permissive starting policy so the first connectivity test succeeds immediately
- clear printed instructions after `vagrant up`

## Box Publication Model

Each release should publish a provider-specific Vagrant box for the demo path.

Recommended first publication target:

- `virtualbox`

Future optional targets:

- `vmware_desktop`
- `libvirt`

Those should be separate provider entries for the same box version, not a single universal VM
artifact.

The repository also includes `packaging/scripts/generate_vagrant_box_metadata.py` so release
automation can publish a Vagrant `metadata.json` alongside a provider box artifact.

The provider-native `.box` itself is built from an existing local `qcow2` artifact with:

```bash
make package.image.build.qemu TARGET=ubuntu-24.04-minimal-amd64 RELEASE_VERSION=dev
make package.vagrant.box TARGET=ubuntu-24.04-minimal-amd64 RELEASE_VERSION=dev
```

## Architecture Constraint

The recommended demo image target in this repository is `ubuntu-24.04-minimal-amd64`.

That means the first Vagrant demo should be documented as `amd64/x86_64` only.

If Apple Silicon support is required, the clean path is a separate `arm64` image target and a
matching provider-native Vagrant box build, not emulation hidden behind the same release claim.
