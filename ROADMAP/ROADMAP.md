## TODOs

### audit / passthrough mode 
Problem: when initially setting up the firewall, or creating a new policy, i want it to run in a "audit" mode where no traffic gets dropped. Instead, the firewall monitors/captures metadata of the traffic which violates policies. This audit mode should be configured on a per-policy basis. The policy today has a enabled/disabled enum or bool. Maybe we can change it to a enum such that the mode can be disabled|audit|enabled.

As a user i want to know which source group/network tries to make what network calls. In particular i want to know:
1. the DNS names which have been requested
2. the L4 connections (DST IP, DST Port, Protocol, FQDN if available through mapping data)
3. TLS: SNI
4. ICMP: what kind of packets, what destination

The data should be stored on a per-node basis on disk. An HTTP API endpoint exposes that information. When requested, a given node aggregates the data from other nodes, deduplicates it and returns it to the user. 

This data should be available from the UI. Maybe add a "audit" sidebar and then the user can explore the data from policies which are in audit mode.

Let's further explore this topic together and write a implementation plan. Once everything is clear write the plan to ROADMAP/AUDIT-MODE.md. Ask me questions to clarify your assumptions.

---

- per-node DNS cache with respect to TTL, figure out how this interacts with the distributed storage.


## Azure Cloud integration

I want to use VMSS in Azure to deploy the firewall. By default, it should run with 3 instances.
I want to use subnet sharding, e.g. subnet-a points at instance-a, subnet-b points at instance-b etc.
I want the application to manage the default route of those subnets. The subnets should be auto discovered using tags. The instances should form a cluster automatically, completely unattended. Use instance tags, find a stable sorting (e.g. seed instance is the oldest instance) and let them form a cluster.

For the maintenance scenario of rolling out updates, replacing instances etc. i want the firewall application to take care of managing the subnet default routes appropriately. E.g. when a new instance appears, it should wait for it to become ready, then shift the traffic to the new instance. Then wait for the old instance in that subnet to be drained, and then eventually shut down the old instance. Is that approach supported with VMSS? I know this works with AWS Auto Scaling Groups. 

I want to add a integratin for AWS Auto Scaling Groups and also for GCP Instance Groups. They should follow the same approach to lifecycle management, route management, cluster formation etc. 
Please design the lifecycle management algorithm as an interface which can have multiple implementations (AWS, GCP, Azure). I may add more integrations for this. I probably want to have a flag --integration=AWS/ASG|GCP/IG|Azure/VMSS or similar. suggest a good naming scheme for this.

I want to use the cloud provider APIs for authentication, discovery and lifecycle management. 

Lets further explore this topic and write a implementation plan to ROADMAP/AZURE-INTEGRATION.md.
Ask me questions for clarification. Once everything is clear write the implementation plan.

## Azure VMSS Integration TODOs (Instance Protection + Termination Handling)
- **Instance protection API**:
  - Research the exact Azure ARM API for VMSS instance protection (protect from scale-in / scale set actions).
  - Implement provider methods to `set_instance_protection(instance, enabled)` using the VMSS VM update endpoint.
  - Ensure protection is idempotent and applied only to assigned instances; remove when draining or unassigned.
  - Decide on failure behavior (log + continue vs. fail reconcile) and add metrics for protection errors.
- **Scheduled Events (termination / maintenance)**:
  - Implement polling of the Azure IMDS scheduled events endpoint to detect scale-in/eviction, reboot, redeploy, or other termination-related events.
  - Map event types to drain behavior: start drain on any event that can terminate or move the VM.
  - Add best-effort completion/ack once drain finishes (research required: scheduled events accept/ack semantics).
  - Add metrics for event detection, drain start time, and completion/ack outcomes.
- **Readiness gating & route cutover**:
  - Ensure route changes only occur after readiness checks succeed.
  - When a termination event is detected, force reassignment of subnet routes away from the instance before completing termination.
- **NIC tagging enforcement**:
  - Require NIC tags `neuwerk.io/management` and `neuwerk.io/dataplane` and fail fast when missing.
  - Document tag requirements and add clear error logging if tags are not present.
- **Testing**:
  - Add unit tests for protection toggling logic and scheduled events flow with a mock Azure provider.
  - Add integration tests in the local harness using a mock provider for event-driven drain.
- **Documentation**:
  - Document required Azure role permissions for VMSS updates, subnet route table updates, and scheduled events access.
  - Provide a minimal Azure VMSS deployment example (tags, routes, permissions).
