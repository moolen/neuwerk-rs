Logical Next Steps

  4. Control plane APIs + replication: implement the cluster stub, distributed rule storage, and an API surface as outlined in ROADMAP/ROADMAP.md and src/controlplane/cluster.rs.

  5. DPDK dataplane: replace the no-op loop with actual RX/TX pipeline in src/dataplane/dpdk_adapter.rs while keeping unsafe isolated.


- per-node DNS cache with respect to TTL
- UI

## Single node to cluster migration path

I want to have a migration path from a single node cluster which stores the data locally to a multi-node ha cluster which stores the data in a distributed fashion. This is needed for users who upgrade their environment or want to do maintenance on a instance.

Use-Case: User runs a single node in a environment. Then he wants a proper HA setup with 3 nodes.
He needs to add two more nodes, let them form a cluster and then distribute the traffic among the nodes.

This should help for availability (less impact on AZ failure) and resilience.

Let's explore this topic. ask me questions for clarification and once everything is clear please write a implementation plan to ROADMAP/single-node-ha-migration-path.md.

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

