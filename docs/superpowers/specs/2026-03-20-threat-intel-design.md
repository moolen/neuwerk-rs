# Neuwerk Threat Intelligence Correlation Design

Date: 2026-03-20

## Summary

Neuwerk will add a control-plane threat intelligence subsystem that correlates
observed hostnames and destination IPs with freely available threat feeds.

The feature is detection-oriented, not enforcement-oriented:

- threat matches flag suspicious indicators and potential IOCs
- existing policy enforcement remains the source of allow or deny decisions
- metrics are first-class so operators can wire the feature into alerting systems
- matching covers both newly observed traffic and retained audit history
- free feed access is required, with local feed matching as the default and
  optional remote enrichment performed asynchronously

Neuwerk is a strong fit for this feature because it already observes relevant
signals at multiple layers:

- DNS queries and denied DNS activity in the control plane
- L4 destination IPs in the dataplane-to-control-plane audit path
- hostname and SNI enrichment where that information is already available

## Goals

- Flag hostnames and IPs observed by Neuwerk when they match threat
  intelligence indicators.
- Match against both streaming observations and retained audit findings.
- Keep all threat-intel parsing, feed management, and enrichment logic in the
  control plane.
- Replicate a consistent normalized feed snapshot across the cluster.
- Expose low-cardinality Prometheus-style metrics suitable for alerting.
- Add a dedicated threat findings API and UI surface.
- Cross-link threat findings to audit findings when the same observed event
  exists in both systems.
- Keep the traffic path free from synchronous third-party dependency calls.

## Non-Goals

- Automatic blocking or policy denial based on threat-intel matches.
- Threat-feed parsing or remote API calls in the dataplane.
- Payload capture, packet retention, or DPI-driven IOC extraction.
- Per-indicator metrics labels carrying raw hostnames or IPs.
- A full SIEM replacement or generalized threat-hunting platform.
- Air-gapped manual feed import in the first phase.

## Current State

Neuwerk already has the core primitives needed for this feature:

- a node-local audit store with cluster aggregation
- DNS-layer visibility in the control plane
- L4-layer visibility through dataplane audit events
- DNS map and hostname enrichment paths
- cluster replication and leader/follower HTTP behavior
- existing Prometheus-compatible metrics export

The missing capability is correlation: today Neuwerk can tell an operator what
traffic was observed or would have been denied, but it cannot tell them whether
that traffic corresponds to known malicious infrastructure.

## Decision

Neuwerk will implement a separate threat-finding pipeline in the control plane.

The design decisions agreed for this phase are:

- action on match: flag only
- matching scope: both streaming observations and retained audit history
- external data model: hybrid
  - local feed matching is the default path
  - optional remote lookups are allowed only for asynchronous enrichment
- indicator types in scope: hostnames and IPs
- metrics model: low cardinality only
- alerting behavior: severity-threshold based
- cluster feed ownership: hybrid
  - leader-managed replicated baseline snapshot
  - optional node-local remote enrichment
- operator UX: dedicated Threats view plus threat annotations in Audit
- traffic-path behavior: async only for remote enrichment
- egress assumption: leader egress only

## Architectural Principles

### Control plane only

Threat-intel feed fetch, parsing, normalization, matching orchestration,
backfill, persistence, and enrichment all live in the control plane.

The dataplane continues to do only packet processing and audit event emission.
This preserves the repository architecture rule that control-plane logic stays
out of the dataplane.

### Detection separate from enforcement

Threat matches do not change forwarding decisions in this phase.
They create persisted threat findings and increment alerting metrics.

### Snapshot consistency over distributed fetches

All nodes should match against the same normalized baseline feed dataset.
The leader owns feed refresh, normalization, and publication of a cluster
snapshot version. Followers consume the replicated snapshot.

### No synchronous third-party dependency in the hot path

Traffic handling and core observation ingestion must never wait on remote
threat-intel APIs. Optional remote lookups only enrich already-created findings.

## Feed Strategy

### Free baseline feeds

The baseline feed set should stay narrow and high-signal in the first phase:

- ThreatFox for IOC-style hostname and IP intelligence
- URLhaus for malicious hostname or domain correlation
- Spamhaus DROP for high-confidence IP or netblock matching

Optional enrichment feeds can be added later behind configuration gates if they
remain free and practical to operate.

### Feed selection criteria

- freely available for community or fair-use access
- accessible through an API or stable downloadable dataset
- usable without requiring Neuwerk to ship commercial credentials
- reasonable data freshness
- clear indicator semantics suitable for hostname or IP correlation
- acceptable false-positive profile for operator alerting

### Feed normalization contract

Every feed adapter must normalize into a common internal indicator model:

- `indicator`
- `indicator_type` as `hostname` or `ip`
- `feed`
- `severity`
- `confidence`
- `tags`
- `reference_url`
- `feed_first_seen`
- `feed_last_seen`
- `expires_at`

Severity and confidence are feed-normalized, not raw feed passthrough values.
This keeps thresholding coherent across multiple sources.

## High-Level Architecture

The recommended implementation adds five control-plane components.

### 1. Feed Manager

Runs on the cluster leader and is responsible for:

- polling configured free feeds on a schedule
- authenticating where a free auth key is required
- parsing and normalizing feed data
- building a versioned baseline snapshot
- publishing the latest good snapshot into replicated cluster state
- updating feed freshness and refresh outcome metrics

Only the leader is required to have outbound egress for the baseline dataset.

### 2. Snapshot Matcher

Runs on every node and is responsible for:

- watching the replicated snapshot version
- rebuilding in-memory match structures from the normalized snapshot
- exact hostname matching
- exact IP matching
- CIDR or netblock matching for feeds that publish prefixes

This matcher is used for low-latency local matching against streaming
observations. It never calls external services.

### 3. Observation Pipeline

Collects normalized observed indicators from Neuwerk-owned sources:

- DNS queries and DNS-deny events
- audit-derived hostnames, FQDNs, or SNIs where already available
- audit-derived destination IPs from L4 events

This pipeline creates `ThreatObservation` records and submits them to the local
matcher. It also emits records into a backfill-capable store for rescans.

### 4. Threat Finding Store

Persists matched findings separately from audit findings.

It stores:

- threat finding identity and indicator details
- feed match metadata
- source group and observation layer
- first seen, last seen, and count
- sample node ids
- alertable or non-alertable classification
- links to audit findings where applicable
- enrichment status

Threat findings remain cluster-queryable with the same partial-result semantics
used by the audit API.

### 5. Async Enrichment Worker

Consumes newly created threat findings and performs optional remote lookup or
enrichment out of band.

This worker:

- never blocks observation ingest
- enriches findings with additional tags, references, or reputation details
- records provider success, failure, and queue-depth metrics
- updates enrichment status on the finding

## Data Model

### ThreatIndicatorSnapshot

A normalized indicator inside the replicated baseline snapshot.

Fields:

- `indicator`
- `indicator_type`
- `feed`
- `severity`
- `confidence`
- `tags`
- `reference_url`
- `feed_first_seen`
- `feed_last_seen`
- `expires_at`
- `snapshot_version`

### ThreatObservation

A normalized observed value produced by Neuwerk.

Fields:

- `indicator`
- `indicator_type`
- `observation_layer` as `dns`, `tls`, or `l4`
- `source_group`
- `node_id`
- `observed_at`
- `dst_ip` when relevant
- `audit_finding_key` when the observation came from audit history or a current
  audit event

### ThreatFinding

A persisted match result created when an observation matches one or more
indicators.

Fields:

- `indicator`
- `indicator_type`
- `observation_layer`
- `match_source` as `stream` or `backfill`
- `source_group`
- `severity`
- `confidence`
- `feed_hits`
- `first_seen`
- `last_seen`
- `count`
- `sample_node_ids`
- `audit_links`
- `enrichment_status`
- `enrichment_summary`

## Matching Semantics

### Hostnames

For the first phase:

- lowercase normalization
- trim trailing dot if present
- exact match only

This avoids ambiguity and keeps false-positive behavior understandable.
Suffix or wildcard semantics can be added later as a separate decision.

### IPs

For the first phase:

- exact single-IP matching
- CIDR or netblock matching where the normalized feed adapter emits prefixes

### Multi-feed matches

If several feeds match the same observation:

- keep all contributing feeds in `feed_hits`
- compute an effective severity from the highest normalized severity
- compute an effective confidence from the strongest feed hit

### Severity threshold

Every match is persisted as a threat finding.
Only findings at or above the configured threshold count as alertable in metrics
and UI-default views.

## Streaming And Backfill Flow

### Streaming path

1. Neuwerk emits or derives a normalized observation.
2. The node-local matcher checks the in-memory baseline snapshot.
3. On match, the control plane writes or updates a threat finding.
4. Alertable counters are incremented.
5. Optional async enrichment is queued.

### Backfill path

1. Leader publishes a new baseline snapshot version.
2. Nodes detect the new version and rebuild match structures.
3. A backfill worker rescans retained audit findings against the new snapshot.
4. New matches are written as `match_source=backfill`.
5. Backfill metrics and status are updated.

Backfill must be resumable, rate-limited, and safe to pause or retry.

## Cluster Behavior

### Leader responsibilities

- fetch external free feeds
- build normalized snapshots
- publish cluster snapshot versions
- expose feed health status

### Follower responsibilities

- consume replicated snapshots
- perform local streaming matching
- participate in cluster query fanout for threat findings

### Failure semantics

- if feed refresh fails, the last good snapshot remains active
- if snapshot publication fails, nodes continue using the old version
- if a node is unavailable during query fanout, threat APIs return partial
  results rather than failing the whole request
- if async enrichment fails, findings remain valid and only enrichment status is
  degraded

## Persistence

Threat findings should have a dedicated store separate from the existing
`audit-store`.

Reasons:

- allowed traffic can generate threat findings without corresponding audit data
- retention policy and dedup semantics differ from audit semantics
- threat findings carry feed and enrichment metadata that do not belong in the
  audit record contract

Recommended shape:

- node-local persisted store under `/var/lib/neuwerk/threat-store`
- bounded storage budget
- deduplicated snapshots or segments similar in spirit to the audit store
- cluster aggregation via local query fanout rather than raw record replication

The replicated feed snapshot is distinct from the node-local threat finding
store. Raw findings remain node-local.

## Configuration Surface

The feature needs explicit control-plane configuration.

Recommended top-level settings:

- enable or disable threat-intel matching
- severity threshold for alertable findings
- baseline feed enablement per feed
- free API keys where required
- feed refresh interval
- remote enrichment enablement
- remote enrichment providers
- backfill enablement and throttle settings
- store budget settings

This should be modeled as a dedicated threat-intel settings object rather than
as policy state. Threat intelligence is an operational detection feature, not an
enforcement policy.

## API Design

### Threat findings

- `GET /api/v1/threats/findings`
- `GET /api/v1/threats/findings/local`

Suggested filters:

- `indicator_type`
- `observation_layer`
- `severity`
- `feed`
- `source_group`
- `match_source`
- `since`
- `until`
- `limit`
- `alertable_only`

Cluster semantics should mirror the audit API:

- leader fanout to node-local endpoints
- merged deduplicated results
- `partial`
- `node_errors`
- `nodes_queried`
- `nodes_responded`

### Feed status

- `GET /api/v1/threats/feeds/status`

This returns:

- configured feeds
- current snapshot version
- last refresh start and end times
- last successful refresh time
- last refresh outcome
- current indicator counts by feed and type
- feed snapshot age

### Audit integration

Audit query responses should not be structurally replaced by threat data.
Instead, Audit should optionally surface threat badges or threat-link metadata
for overlapping findings.

## UI Design

### Dedicated Threats page

Add a sidebar entry for `Threats`.

The page should provide:

- feed filters
- severity filters
- hostname or IP filters
- source group filters
- observation layer filters
- time range filters
- alertable-only toggle
- feed freshness status
- partial-result warning state

Each row should show:

- indicator
- indicator type
- effective severity
- feed hits
- first seen
- last seen
- count
- observation layer
- source group
- sample nodes
- enrichment state

### Audit page annotations

Where an audit finding is linked to one or more threat findings:

- show a threat badge
- expose the matched severity
- link to the corresponding Threats view or detail panel

## Metrics

Metrics must remain low cardinality and suitable for Prometheus-style alerting.

Recommended metrics:

- `neuwerk_threat_matches_total{indicator_type,observation_layer,severity,feed,match_source}`
- `neuwerk_threat_alertable_matches_total{indicator_type,observation_layer,severity,feed}`
- `neuwerk_threat_feed_refresh_total{feed,outcome}`
- `neuwerk_threat_feed_snapshot_age_seconds{feed}`
- `neuwerk_threat_feed_indicators{feed,indicator_type}`
- `neuwerk_threat_backfill_runs_total{outcome}`
- `neuwerk_threat_backfill_duration_seconds`
- `neuwerk_threat_enrichment_requests_total{provider,outcome}`
- `neuwerk_threat_enrichment_queue_depth`
- `neuwerk_threat_findings_active{severity}`
- `neuwerk_threat_cluster_snapshot_version`

Explicitly rejected for this phase:

- raw hostname labels
- raw IP labels
- source-group labels unless later proven necessary and safe for cardinality

## Alerting Model

The alerting contract is metric-based rather than inline action-based.

Operators can build alerts on:

- rate of alertable threat matches
- any non-zero match rate for a specific severity bucket
- stale feed age
- repeated feed refresh failures
- backfill failures
- enrichment queue growth
- large active-finding growth suggesting an outbreak or widespread scanning

## Security And Privacy

- baseline matching should use locally replicated snapshots by default
- remote lookups are optional and must be explicitly enabled
- only the leader is assumed to make baseline feed calls
- remote enrichment should be conservative about outbound submission of observed
  indicators and documented clearly for operators
- threat-intel API keys must be stored through existing secret-handling patterns

## Risks And Mitigations

### Risk: false positives create noisy alerts

Mitigations:

- narrow initial feed set
- severity-threshold alerting
- exact hostname matching in the first phase
- preserve feed provenance in findings

### Risk: cluster inconsistency if nodes fetch feeds independently

Mitigation:

- leader-managed normalized snapshot as the baseline source of truth

### Risk: remote enrichment creates latency or availability coupling

Mitigation:

- async-only enrichment
- last good finding remains visible without enrichment

### Risk: metrics cardinality explosion

Mitigation:

- low-cardinality dimensions only
- raw indicators remain in stores and APIs, not metric labels

### Risk: historical rescans are expensive

Mitigation:

- resumable backfill
- throttled scanning
- progress metrics
- bounded local stores

## Phased Implementation Plan

### Phase 0: Contracts And Settings

- define shared threat-intel types and normalized severity model
- add threat-intel settings persistence and HTTP API
- add OpenAPI and UI type definitions

### Phase 1: Feed Manager And Snapshot Replication

- implement leader-only baseline feed refresh
- normalize free feeds into a common snapshot model
- replicate snapshot version and payload through cluster state
- add feed freshness and refresh metrics

### Phase 2: Local Matcher And Streaming Path

- add node-local matcher rebuild from replicated snapshots
- derive normalized observations from DNS and audit paths
- create local streaming threat findings
- emit threat match metrics

### Phase 3: Threat Store And Cluster Query API

- implement node-local threat store
- add local and cluster-aggregated threat findings endpoints
- add partial-result semantics

### Phase 4: Backfill

- implement rescans of retained audit findings on snapshot version changes
- add backfill metrics, throttling, and resumability

### Phase 5: UI

- add Threats page
- add feed-status panel
- add Audit page threat annotations

### Phase 6: Async Enrichment

- add optional remote lookup workers
- persist enrichment status and summary
- add enrichment metrics

## Testing Plan

### Unit tests

- feed normalization
- severity and confidence normalization
- hostname normalization and exact matching
- IP and CIDR matching
- multi-feed merge behavior
- threshold classification

### Control-plane tests

- leader refresh publishes a new snapshot
- followers rebuild matcher state from replicated snapshot
- last good snapshot survives refresh failure
- threat findings local query behavior
- cluster threat aggregation and partial-result behavior

### Integration and e2e tests

- streaming DNS hostname match
- streaming L4 IP match
- backfill after feed update
- threat metrics increment correctly
- Audit page overlap surfaces threat links
- optional enrichment updates findings asynchronously

## Open Follow-Ups

These are intentionally deferred, not unresolved blockers:

- air-gapped snapshot import workflow
- source-group labels in metrics
- suffix or wildcard hostname matching
- policy recommendation generation from threat findings
- automatic blocklist synthesis

## Recommended Implementation Boundary

The first implementation pass should stay within the control plane and adjacent
UI/API layers:

- new threat-intel control-plane modules
- cluster snapshot replication glue
- threat-specific HTTP APIs
- metrics registration and render support
- UI threat view and audit annotations

No threat-feed logic should be added to dataplane packet-processing code.
