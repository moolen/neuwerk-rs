**Overview**
Implement cloud integrations for Azure VMSS, AWS ASG, and GCP MIG with a shared lifecycle/route-management engine in the control plane. The integration discovers tagged subnets and instances, assigns subnets deterministically, manages default routes, and coordinates cluster bootstrap/join and drain during replacements.

**Goals**
- Support Azure VMSS as first implementation, with AWS ASG and GCP MIG following the same interface and algorithm.
- Auto-discover dataplane subnets via tags and manage a single named default route per subnet.
- Deterministic and stable subnet-to-instance assignment with fair distribution and minimal churn.
- Fully unattended cluster formation using instance tags and deterministic seed selection.
- Route cutover only after readiness; drain old instances with a bounded timeout.
- Run in CI without cloud credentials by using mockable interfaces and unit tests.

**Non-Goals (Phase 1)**
- Multi-region routing or cross-region clustering.
- Cloud LB integration or traffic steering via load balancers.
- Any dataplane changes that violate the control-plane/dataplane separation.

**Terminology**
- Integration: Provider-specific API client plus metadata discovery.
- Assignment: A mapping of subnet -> instance that owns the default route.
- Ready: `/ready` succeeds and required dataplane/control-plane conditions are met.
- Drain: Instance stops accepting new flows, waits for active flows to reach zero or a timeout.

**CLI And Naming**
- `--integration azure-vmss|aws-asg|gcp-mig|none` (default `none`).
- `--integration-route-name neuwerk-default` (overrideable).
- `--integration-drain-timeout-secs 300` (overrideable).
- `--integration-reconcile-interval-secs 15` (overrideable).
- Tag defaults (overrideable in a follow-up if needed):
- `neuwerk.io/cluster=<name>`
- `neuwerk.io/role=dataplane`
- Azure scope: `--azure-subscription-id`, `--azure-resource-group`, `--azure-vmss-name`.
- AWS scope: `--aws-region`, `--aws-vpc-id`, `--aws-asg-name`.
- GCP scope: `--gcp-project`, `--gcp-region`, `--gcp-ig-name`.

**Module Layout (Proposed)**
- `src/controlplane/cloud/mod.rs` integration manager and shared algorithm.
- `src/controlplane/cloud/types.rs` shared types and error model.
- `src/controlplane/cloud/provider.rs` trait interface.
- `src/controlplane/cloud/providers/azure.rs`
- `src/controlplane/cloud/providers/aws.rs`
- `src/controlplane/cloud/providers/gcp.rs`

**Provider Interface**
- `CloudProvider` trait (async):
- `self_identity() -> InstanceRef` (id, name, creation time, zone, mgmt IP, tags).
- `discover_instances(filters) -> Vec<InstanceRef>`.
- `discover_subnets(filters) -> Vec<SubnetRef>` (includes route table or route resource handle).
- `get_route(subnet, route_name) -> Option<RouteRef>`.
- `ensure_default_route(subnet, route_name, next_hop) -> RouteChange` (idempotent).
- `set_instance_protection(instance, enabled) -> Result<Capability>`.
- `poll_termination_notice(instance) -> Option<TerminationEvent>`.
- `complete_termination_action(event) -> Result<Capability>`.
- `capabilities() -> IntegrationCapabilities` (instance protection, termination notice, lifecycle hook).

**Shared Lifecycle Algorithm**
- Only the control-plane leader runs the integration manager to avoid conflicting route changes.
- Reconcile loop (every `integration-reconcile-interval`):
- Discover instances and subnets by tags within provider scope.
- Filter instances: `active`, `ready`, and tagged with the cluster id.
- Compute deterministic assignments using rendezvous hashing on `(subnet_id, instance_id)`.
- Enforce zone affinity: subnets may only be assigned to instances in the same AZ/zone. If no eligible instance exists in-zone, leave the route unchanged and surface a clear metric/alert.
- Persist assignments in the replicated store for observability and stability.
- For each subnet, if assigned instance differs from current route:
- Verify the new instance is `ready`.
- Update route to the new instance.
- Mark the old instance as `draining` if it has no remaining assigned subnets.
- Apply instance protection to assigned instances when supported; clear protection for unassigned or draining instances.
- If a termination event is received, force reassignment of its subnets to ready instances and begin drain.

**Drain Semantics**
- Add a control-plane drain state per instance: `active`, `draining`, `drained`.
- Dataplane behavior while draining:
- Stop accepting new flows while allowing established flows.
- Track active flow count; declare `drained` when zero or after timeout.
- Drain timeout default 300s; timeout triggers completion of termination action and clears protection.

**Cluster Formation**
- Seed selection: oldest active, tagged, ready instance by creation time; tie-breaker by instance ID.
- If the local instance is the seed and no cluster exists, bootstrap a single-node cluster.
- Otherwise, join the seed automatically using the existing join flow.
- Manual `--join` (if provided) overrides integration discovery.

**Routing Details**
- Azure: Update a single named route in each tagged subnet’s route table, next hop = instance’s dataplane IP.
- AWS: Update the route table entry (`0.0.0.0/0`) to target the instance ENI or instance ID.
- GCP: Update the route next hop to the instance or dataplane IP, using a single named route per subnet.
- Preserve all other routes in the table; only create or replace the named default route.

**Readiness Endpoint**
- Add `/ready` to the control-plane HTTP server.
- Ready requires: DHCP success on dataplane, policy store initialized, policy replication caught up, DNS allowlist sync complete, cluster membership ready, and dataplane engine running.

**Data Model (Replicated Store)**
- `integration/assignments/<subnet_id> -> instance_id`
- `integration/drain/<instance_id> -> {state, since, deadline}`
- `integration/observed/<instance_id> -> {ready, last_seen}`

**Provider-Specific Notes**
- Azure VMSS supports instance protection and termination notifications via Scheduled Events; use both where available to delay scale-in and allow drain.
- AWS ASG supports lifecycle hooks and instance protection; use lifecycle hooks to pause termination and complete after drain.
- GCP MIG does not allow VM deletion protection on managed instances; use best-effort drain with fast route reassignment and no termination delay. Deletion protection is only supported for unmanaged instance groups or standalone VMs, so the “protect on create, remove on drain” workflow is not available on MIG.
- GCP mitigations: use MIG rolling update policy with `maxSurge > 0`, `maxUnavailable = 0`, and a `minReadySec` long enough for firewall readiness to reduce churn; add a VM `shutdown-script` to trigger last-ditch drain signals (best-effort, limited time). These do not provide a lifecycle hook equivalent to ASG/VMSS.

**Azure VMSS Requirements (Phase 1)**
- VMSS terminate notifications must be enabled: `virtualMachineProfile.scheduledEventsProfile.terminateNotificationProfile.enable: true`. The control plane fails fast if this is disabled or missing.
- Each VMSS NIC must be tagged with exactly one of:
- `neuwerk.io/management`
- `neuwerk.io/dataplane`
- Missing NIC tags are treated as fatal to avoid mis-routing.
- Scheduled events are read/acknowledged via IMDS (`/metadata/scheduledevents`); no ARM permissions are required for IMDS.

**Azure Role Permissions (Minimum)**
- Compute:
- `Microsoft.Compute/virtualMachineScaleSets/read`
- `Microsoft.Compute/virtualMachineScaleSets/virtualMachines/read`
- `Microsoft.Compute/virtualMachineScaleSets/virtualMachines/write` (instance protection updates)
- Network:
- `Microsoft.Network/virtualNetworks/read`
- `Microsoft.Network/virtualNetworks/subnets/read`
- `Microsoft.Network/networkInterfaces/read`
- `Microsoft.Network/routeTables/read`
- `Microsoft.Network/routeTables/routes/read`
- `Microsoft.Network/routeTables/routes/write` (default route updates)

**Minimal VMSS Deployment Sketch**
- VMSS with two NICs per VM (mgmt + dataplane).
- Tag mgmt NIC with `neuwerk.io/management`, dataplane NIC with `neuwerk.io/dataplane`.
- Subnets tagged with `neuwerk.io/cluster=<name>` and `neuwerk.io/role=dataplane`.
- A route table per tagged subnet with a named default route (e.g. `neuwerk-default`).
- Enable terminate notifications on the VMSS with `terminateNotificationProfile.enable: true`.

**Tests**
- Unit tests for deterministic assignment and rebalancing logic.
- Unit tests for drain state machine and timeout behavior.
- Provider client tests using mocked API responses.
- Integration test harness for route reconciliation (local mock provider).
- Cloud e2e tests in a separate, opt-in suite (Terraform-backed), not in CI.

**Milestones**
1. Define `CloudProvider` trait and integration manager skeleton.
2. Add `/ready` endpoint and drain state machine.
3. Implement deterministic assignment and reconcile loop with mocks.
4. Implement Azure VMSS provider (discovery, route update, termination events, instance protection).
5. Implement AWS ASG provider (discovery, route update, lifecycle hook, instance protection).
6. Implement GCP MIG provider (discovery, route update, best-effort drain).
7. Add metrics: route changes, drain durations, assignment changes, termination events.
8. Add documentation and example deployment notes per provider.

**Open Questions**
- Do we want a CLI override for tag keys/values in Phase 1?
