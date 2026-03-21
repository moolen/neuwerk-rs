# Threat Analysis Silencing And Disablement Design

## Goal

Extend the threat-intel feature so operators can:

- silence false-positive findings
- prevent future findings from being created for silenced indicators
- fully disable threat analysis cluster-wide so URLs and IPs are not processed

## Requirements

Approved product requirements for the first version:

- silences are cluster-global replicated state
- disablement is cluster-global replicated state
- the primary silence workflow is global exact-indicator suppression
- future matches for silenced indicators are dropped before findings are created
- existing findings remain on disk when the feature is disabled
- disabled mode hides findings from API and UI
- regex support is limited to hostname/domain matching

## Non-Goals

This version does not add:

- policy-scoped silences
- per-node silences
- time-limited silences
- generic wildcard or regex matching for IPs
- path or query-string URL suppression
- destructive purge of existing findings on disable

## Existing System Fit

Threat intelligence in this repository is an operational detection feature rather than an
enforcement policy. The current architecture already separates:

- cluster-replicated threat baseline snapshots and manager state
- node-local threat finding storage
- threat-intel settings stored separately from policy state

The new silence and disable controls should follow that same model:

- stay out of policy state
- remain control-plane only
- replicate through cluster state in clustered mode

## High-Level Approach

Use the existing `ThreatIntelSettings.enabled` flag as the cluster-wide feature gate, and add
a separate cluster-replicated silence state object for suppression rules.

Two enforcement points are required:

1. A global feature gate that stops processing when threat intel is disabled.
2. A suppression matcher that drops matched indicators before `ThreatFinding` creation.

This keeps false-positive handling operational and prevents silenced indicators from polluting
the local threat store, audit annotations, metrics, and UI.

## Data Model

### Threat Settings

`ThreatIntelSettings.enabled` remains the master cluster-wide enable/disable switch.

When `enabled=false`, threat intelligence is considered fully off:

- no stream matching
- no backfill rescans
- no feed refresh
- no enrichment
- no visible findings in API/UI

### Threat Silences

Add a new replicated state key:

- `settings/threat_intel/silences`

Proposed entry model:

- `id: String`
- `kind: ThreatSilenceKind`
- `indicator_type: Option<ThreatIndicatorType>`
- `value: String`
- `reason: Option<String>`
- `created_at: u64`
- `created_by: Option<String>`

`ThreatSilenceKind`:

- `exact`
- `hostname_regex`

Rules:

- `exact` entries support exact normalized hostname or exact IP indicator matching
- `hostname_regex` entries apply only to normalized hostname indicators
- regex entries are cluster-global and do not carry source-group or layer scoping in v1

## Matching Semantics

### Exact Silences

Exact silences match the normalized stored indicator value:

- hostnames use the same normalization already applied by the threat runtime
- IPs match their canonical string form

Exact silences can suppress:

- DNS hostname matches
- TLS SNI / hostname-derived matches
- L4 IP-derived matches
- audit backfill findings derived from those same indicators

### Regex Silences

Regex silences apply only to hostname indicators after normalization.

This is intentionally narrower than “URL regex” in the colloquial sense because the current
threat pipeline stores hostname and IP indicators, not full URL paths. In practice, this still
solves the approved requirement: suppressing domain-based false positives.

### Drop Point

Silences are enforced after a threat match is identified but before `ThreatFinding` creation
and persistence.

This means silenced indicators:

- do not produce new `ThreatFinding` records
- do not surface in the Threats UI/API
- do not create new audit threat annotations
- do not contribute new threat-match metrics

## Runtime Behavior

### Stream Matching

The stream runtime should first load the effective threat-intel settings.

If `enabled=false`:

- skip matcher lookup entirely
- drop observations immediately

If `enabled=true`:

- perform matcher lookup
- apply silence matcher to each matched indicator
- only build and persist findings that are not silenced

### Backfill

Backfill should also obey the same gate:

- if `enabled=false`, do not rescan retained audit findings
- if enabled and a backfill-produced indicator is silenced, drop it before persistence

### Feed Refresh Manager

The threat manager loop should stop operational processing while disabled:

- do not fetch feed payloads
- do not publish refreshed snapshots
- do not run enrichment-related follow-up work

Existing last-good snapshot and feed-status data remain on disk and in cluster state, but the
runtime does not continue refreshing them until re-enabled.

## API Design

### Existing Threat Settings API

Continue using:

- `GET /api/v1/settings/threat-intel`
- `PUT /api/v1/settings/threat-intel`

The `enabled` field remains the single cluster-wide control for fully disabling the feature.

### New Silence Management API

Add:

- `GET /api/v1/threats/silences`
- `POST /api/v1/threats/silences`
- `DELETE /api/v1/threats/silences/:id`

Create request shape:

- `kind`
- `indicator_type` for exact entries
- `value`
- `reason`

Server responsibilities:

- validate exact entries by indicator type
- validate hostname regex entries by compiling the regex
- normalize exact hostname entries before persistence
- reject invalid combinations such as regex silences for IP indicators

### Threat Findings API While Disabled

`GET /api/v1/threats/findings` and local fanout equivalents should return `200` with:

- `items=[]`
- `partial=false`
- `node_errors=[]`
- `nodes_queried=0`
- `nodes_responded=0`
- `disabled=true`

This preserves an operational contract without turning disablement into an error state.

### Feed Status API While Disabled

`GET /api/v1/threats/feeds/status` should still return the configured feed view, but also expose
`disabled=true`.

No refresh work should be triggered while disabled.

## UI Design

### Threats Page

Add a control/status banner at the top of the Threats page.

When enabled:

- show normal findings and feed status
- expose a `Silences` management action
- allow creating silences from finding rows

When disabled:

- show a prominent “Threat analysis disabled” state
- explain that new URLs and IPs are not processed
- hide active findings from the main table
- still allow admins to manage silences and re-enable the feature

### Finding Row Actions

For each finding:

- `Silence exact indicator`
- if hostname: `Silence hostname regex`

The create-silence modal should include:

- the candidate value
- optional reason
- a warning that future matches will be dropped before finding creation

### Silences Management Panel

Add a management panel or table to the Threats page with:

- type
- matcher value
- optional reason
- created time
- delete action

### Settings Page

The master feature toggle remains in threat-intel settings, not as a page-local Threats toggle.

The Threats page reflects state and provides workflow shortcuts, but Settings remains the source
of truth for enablement.

## Audit Integration Impact

Audit findings should continue to derive threat annotations from the threat store.

Effects of the new controls:

- silenced future matches stop creating new threat annotations
- disabled mode hides threat findings from the Threats API/UI, so audit cross-links also stop
  surfacing while disabled
- historical findings remain on disk and become visible again when re-enabled

## Operational Behavior Summary

### Enabled + Unsilenced

- observations are processed
- findings are created
- findings are visible
- feed refresh and backfill run normally

### Enabled + Silenced

- observations may still be decoded, but silenced matches are dropped before finding creation
- no new threat findings are stored for those indicators

### Disabled

- no new URLs/IPs/hostnames are matched
- no feed refresh
- no backfill
- no enrichment
- findings hidden from UI/API
- existing persisted data retained for later re-enable

## Testing Strategy

Required backend coverage:

- exact hostname silence drops stream findings before persistence
- exact IP silence drops L4 / backfill findings before persistence
- hostname regex silence drops normalized hostname matches
- invalid regex create request is rejected
- cluster replication of silence state works across follower HTTP APIs
- disabled mode returns empty threat findings and disabled status
- disabled mode prevents new stream findings
- disabled mode prevents backfill execution
- disabled mode prevents feed refresh loop execution

Required UI coverage:

- Threats page disabled banner and empty state
- silence creation actions on finding rows
- silence management list rendering
- settings-driven disable state reflected in Threats page

## Risks

### Risk: regex silences are too broad

Mitigation:

- restrict regex support to hostnames only
- require explicit operator creation
- show exact stored pattern in management UI

### Risk: hiding findings while disabled confuses operators

Mitigation:

- explicit disabled banner
- explicit explanation that findings remain on disk and return when re-enabled

### Risk: partial enforcement if disablement is only applied at query time

Mitigation:

- enforce disablement in stream runtime, backfill runtime, and feed manager loop

## Recommendation

Implement silencing and disablement as replicated control-plane state with ingest-time suppression.

This matches the repository’s current threat-intel architecture, solves the false-positive problem
at the right point in the pipeline, and gives operators a clean cluster-wide “fully off” mode
without destructive data loss.
