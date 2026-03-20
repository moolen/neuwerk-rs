# DPI Investigation Log

## Scope
- Target: improve TLS+DPI throughput (especially `tls_intercept_http_path`, `new_connection_heavy`, `32768B`).
- Platform: Azure cloud bench, firewall VMSS currently `Standard_D4as_v5` (3 instances), single consumer VM with 8 source IPs.
- Date: 2026-03-12 to 2026-03-13.

## Baseline And Recent Evidence
- Historical best reference (forced shared demux, HTTPS unpinned): `~1928.93 RPS`, status `pass`, latency p99 `~137.78ms`.
  - Artifact: `cloud-tests/azure/artifacts/http-perf-matrix-20260312T221639Z-dpi-force-demux-unpinned-r2400`
- After service-lane forwarding changes were built but before correct binary rollout:
  - `~1834.49 RPS`, status `fail` (latency gate), no generator-limit flag.
  - Artifact: `cloud-tests/azure/artifacts/http-perf-matrix-20260312T-dpi-servicelane-forward-r2400-d4`
- Found rollout issue: cloud nodes were running old binary hash; fixed by direct deploy to all firewall nodes.

## Validated Since Redeploy
- Service-lane crash symptom is fixed:
  - No `dpdk worker exiting on error ... service lane steering unavailable` in journal for focused reruns.
- New bottleneck surfaced in forced shared-demux mode:
  - Large `dpdk_shared_io_lock_contended_total` / `dpdk_shared_io_lock_wait_seconds_sum`
  - Frequent client-side `dial: i/o timeout` and `Insufficient VUs` in some runs.

## Focused Run Snapshot (RPS=2400, new_connection_heavy, 32768B)
- `pre_redeploy_w3_forced`: fail, `1834.49 RPS`, p99 `578.14ms`, generator_limited=false
- `redeploy_w3_forced`: invalid, `342.11 RPS`, p99 `46.84ms`, generator_limited=true
  - flow-steer dispatch packets `605,088`
  - service-lane forward packets `217,125`
  - shared-io lock contended `544,386,093`, wait sum `426.278s`
- `redeploy_w2_unforced`: fail, `1887.94 RPS`, p99 `1120.14ms`, generator_limited=false
- `redeploy_w2_forced`: invalid, `441.34 RPS`, p99 `44.95ms`, generator_limited=true
  - shared-io lock contended `308,082,116`, wait sum `54.452s`

## Working Hypothesis
- In shared-demux mode, once workers stay alive and flow-steer dispatch is active, workers contend heavily on shared `DpdkIo` lock.
- A likely contributor is non-RX-owner workers still hitting shared IO paths in tight loops (especially RX-finish/idle paths), which is unnecessary.

## Next Steps In Progress
1. Change runtime worker loop so only the designated shared-RX owner polls NIC in shared-demux mode.
2. Ensure `finish_rx_packet` is called only when packet actually came from NIC RX path.
3. Re-run same focused benchmark and compare:
   - effective RPS / latency gates
   - `dpdk_shared_io_lock_*`
   - generator-limit signatures
   - worker-exit logs

## 2026-03-13 Progress (Current Session)
- Implemented runtime change in `src/runtime/dpdk/run.rs`:
  - Added owner-only direct RX polling policy for shared-demux + shared-IO mode.
  - Non-owner workers now process steered packets and no longer poll shared RX directly.
  - `finish_rx_packet` is now called only when packet actually came from direct RX path.
- Added unit regression test:
  - `runtime::dpdk::run::tests::direct_rx_poll_enabled_owner_only_allows_only_worker_zero`
- Local verification:
  - `cargo fmt` clean.
  - `cargo test direct_rx_poll_enabled_owner_only_allows_only_worker_zero` passed.
- Next immediate step: build DPDK release, deploy to firewall nodes, rerun focused DPI benchmark at `RPS=2400`.

## 2026-03-13 Experiment Log (D4, 3 firewall nodes, focused TLS+DPI run)
- Common scenario:
  - `tls_intercept_http_path`
  - `new_connection_heavy`
  - payload `32768`
  - target `2400 RPS`
  - `HTTP_REPEATS=1`

### A) Owner-only RX polling (first cut)
- Artifact: `cloud-tests/azure/artifacts/http-perf-matrix-20260313T-dpi-owner-rx-r2400-d4-w3`
- Outcome:
  - `status=invalid (generator_limited)`
  - effective `~339 RPS`
  - error rate `~0.678`
  - lock contention almost gone: `dpdk_shared_io_lock_contended_total=52`
  - but severe client `dial: i/o timeout`, `Insufficient VUs`
- Interpretation:
  - Removing shared-IO contention alone was not sufficient.
  - Throughput collapsed due connection setup stalling / timeout behavior.

### B) Owner-only RX + explicit non-owner flush
- Artifact: `cloud-tests/azure/artifacts/http-perf-matrix-20260313T-dpi-owner-rx-flush-r2400-d4-w3-rerun`
- Outcome:
  - `status=invalid (generator_limited)`
  - effective `~340 RPS`
  - error rate `~0.674`
  - lock contention rose again (`116M`, wait `~25.99s`) but still far below prior `~544M`.
- Interpretation:
  - Explicit flush did not recover throughput; problem is not just missing flush cadence.

### C) Owner-only mode disabled by default (config-gated)
- Code update:
  - `NEUWERK_DPDK_SHARED_RX_OWNER_ONLY=true` now required to enable owner-only polling.
  - Default behavior returns to multi-worker polling in shared-demux mode.
- Artifact (default/off): `cloud-tests/azure/artifacts/http-perf-matrix-20260313T-dpi-sharedrxoff-r2400-d4-w3`
- Outcome:
  - `status=invalid (generator_limited)`
  - effective `~342 RPS`
  - error rate `~0.670`
  - lock contention back to high (`~552M`, wait `~434s`)

### D) Runtime config experiment: pin HTTPS demux owner
- Runtime-only change on nodes:
  - `NEUWERK_DPDK_PIN_HTTPS_OWNER=true`
- Artifact: `cloud-tests/azure/artifacts/http-perf-matrix-20260313T-dpi-pintrue-r2400-d4-w3`
- Outcome:
  - `status=fail (latency_gate)` (not generator-limited)
  - effective `~1720 RPS`
  - error rate `~0.000187`
  - p99 latency `~2213ms`
  - `dpdk_service_lane_forward_packets_total=0`
- Interpretation:
  - This is a large recovery from `~340 RPS` invalid runs.
  - It confirms current unpinned/shared service-lane-forward path is the dominant instability source.
  - Current stable tradeoff: higher throughput but high latency tail.

## Current State Of Code / Runtime
- Deployed binary hash on firewall nodes: `486336584d04a30481fbbafc9c385aadb86d01b28cb0eddd13cd3d02531f6305`.
- Runtime knob currently set for this phase:
  - `NEUWERK_DPDK_PIN_HTTPS_OWNER=true` (for stability/throughput recovery in focused test).
- Existing baseline knobs retained:
  - `NEUWERK_DPDK_WORKERS=3`
  - `NEUWERK_DPDK_ALLOW_AZURE_MULTIWORKER=true`
  - `NEUWERK_DPDK_FORCE_SHARED_RX_DEMUX=true`
  - `NEUWERK_DPDK_PERF_MODE=aggressive`

## Working Conclusions
- The original worker-exit crash symptom is fixed, but unpinned TLS+DPI under shared-demux still collapses in practice.
- Owner pinning avoids service-lane-forward pressure and restores meaningful throughput, but p95/p99 remain too high at 2400 target.
- Main architectural pressure points now:
  - shared single-queue IO lock contention
  - service-lane handling cost when TLS flow ownership is spread across workers
  - handshake/connection setup tail latency under new-connection-heavy load

## Next Candidate Fixes
1. Make service-lane multi-writer/multi-queue capable (instead of owner-forward queue), then retest unpinned mode.
2. Add deeper per-phase latency attribution for handshake path under load (`client_tls_accept` and queueing correlations).
3. Validate scaling behavior on larger instance size with the current best stable mode (`pin=true`) to quantify whether vertical scaling helps before more invasive re-architecture.

## 2026-03-13 Follow-up (D8, post-mempool scaling fix)
- Deployment recovery completed:
  - All firewall nodes now run binary hash `716c29fcc4da562577739f876eda42d51e210c078f4bbdc0c90666d08657a316`.
  - From `2026-03-13 01:00:00` onward, no `failed to allocate mbuf` / worker-exit errors observed in `journalctl -u firewall`.
- Focus scenario unchanged for comparability:
  - `tls_intercept_http_path`
  - `new_connection_heavy`
  - payload `32768`
  - target `2400 RPS`
  - `HTTP_REPEATS=1`

### E) Unforced queue-per-worker validation after mempool fix (`w=4`)
- Artifact: `cloud-tests/azure/artifacts/http-perf-matrix-20260313T011450Z-dpi-unforce-r2400-d8-w4-postmempool`
- Outcome:
  - `status=invalid (generator_limited)`
  - effective `~305.85 RPS`
  - error rate `~0.758`
  - p95/p99 `~42.16ms / ~207.46ms`
  - load generator: `insufficient_vus=1` plus many `dial: i/o timeout`/`unexpected EOF` warnings
  - metrics deltas:
    - `dpdk_shared_io_lock_contended_total=0`
    - `dpdk_shared_io_lock_wait_seconds_sum=0`
    - `dpdk_service_lane_forward_packets_total=235,472`
    - `dpdk_flow_steer_dispatch_packets_total=0`
- Interpretation:
  - The mempool fix removed the startup/crash failure mode for unforced `w=4`.
  - Throughput collapse persists and is dominated by service-lane-forward path behavior, not shared-IO lock contention.

### F) Best-known regression check after mempool fix (forced shared-demux + pin, `w=2`)
- Artifact: `cloud-tests/azure/artifacts/http-perf-matrix-20260313T011932Z-dpi-pintrue-r2400-d8-w2-postmempool`
- Outcome:
  - `status=pass`
  - effective `~1965.76 RPS`
  - error rate `~0.0001898`
  - p95/p99 `~57.65ms / ~66.54ms`
  - load generator not limited
  - metrics deltas:
    - `dpdk_shared_io_lock_contended_total=110,714,136`
    - `dpdk_shared_io_lock_wait_seconds_sum=48.613s`
    - `dpdk_service_lane_forward_packets_total=0`
    - `dpdk_flow_steer_dispatch_packets_total=6,296,530`
- Interpretation:
  - No regression from mempool scaling fix on the currently best-performing mode.
  - This remains the strongest observed configuration for throughput + latency gate at this workload.

### G) Pinning check in unforced queue-per-worker mode (`w=4`, pin=true)
- Direct run artifact: `cloud-tests/azure/artifacts/http-perf-tls_intercept_http_path-20260313T012605Z-unforce-pintrue-w4`
- Outcome:
  - `status=invalid (generator_limited)`
  - effective `~306.80 RPS` (effectively same as E)
  - error rate `~0.756`
  - `dpdk_service_lane_forward_packets_total=235,964`, `dpdk_shared_io_lock_contended_total=0`
- Interpretation:
  - `NEUWERK_DPDK_PIN_HTTPS_OWNER=true` does not rescue unforced queue-per-worker mode here.
  - Observed packet path signature is unchanged vs unforced/pin=false.

### H) Harness/observability improvement
- Updated `cloud-tests/common/http-perf-run.sh` to support these runtime knobs directly:
  - `DPDK_PIN_HTTPS_OWNER`
  - `DPDK_SHARED_RX_OWNER_ONLY`
- The runner now:
  - propagates both to service drop-in + `/etc/neuwerk/neuwerk.env`
  - verifies effective runtime environment in `/proc/<pid>/environ`
  - records both fields in `context.json.runtime_tuning`
- Smoke validation:
  - Artifact: `cloud-tests/azure/artifacts/http-perf-smoke-20260313T013405Z-pin-knobs`
  - `context.json.runtime_tuning` captured:
    - `dpdk_workers=2`
    - `dpdk_force_shared_rx_demux="1"`
    - `dpdk_pin_https_owner="true"`
    - `dpdk_shared_rx_owner_only="0"`
- This removes manual host editing for pinned/unpinned DPI experiments and reduces configuration drift.

## Current Recommended Runtime (for next cloud runs)
- `NEUWERK_DPDK_WORKERS=2`
- `NEUWERK_DPDK_FORCE_SHARED_RX_DEMUX=1`
- `NEUWERK_DPDK_PIN_HTTPS_OWNER=true`
- `NEUWERK_DPDK_ALLOW_AZURE_MULTIWORKER=true`
- `NEUWERK_DPDK_PERF_MODE=aggressive`

## Updated Conclusion
- Mempool sizing was a real blocker for multi-queue startup stability and is now addressed.
- The remaining primary throughput limiter for TLS+DPI is the service-lane-forward behavior in unforced queue-per-worker mode (not shared-IO lock contention).
- For practical throughput today, keep forced shared-demux + pin + `w=2`; for further gains, prioritize service-lane architecture changes (true multi-writer/multi-queue path) and then re-evaluate scaling with larger instances/instance count.

## 2026-03-13 Service-Lane Re-Architecture Trial (Direct Local Flush)
- Code changes applied:
  - Removed cross-worker service-lane host-frame forwarding channel in `src/runtime/dpdk/run.rs`.
  - Switched to per-worker service-lane TAP readiness checks and local `flush_host_frames()` (no owner-forward queue).
  - Changed `NEUWERK_DPDK_PIN_HTTPS_OWNER` default to `false` (`src/runtime/dpdk/worker_plan.rs`), still overrideable via env.
  - Added regression tests:
    - `flush_host_frames_writes_all_pending_frames_to_service_lane_tap`
    - `dpdk_pin_https_demux_owner_defaults_to_disabled`
    - `dpdk_pin_https_demux_owner_honors_truthy_override`
- Focused cloud rerun:
  - Artifact: `cloud-tests/azure/artifacts/http-perf-matrix-20260313T133251Z-dpi-servicelane-rearch-r2400`
  - Infra profile:
    - firewall VMSS `Standard_D4as_v5` x3
    - `NEUWERK_DPDK_WORKERS=2`
    - consumer `Standard_D16as_v5` with `32` source IPs (`consumer_secondary_private_ip_count=31`)
    - upstream `Standard_D16as_v5`
  - Scenario:
    - `tls_intercept_http_path`
    - `new_connection_heavy`
    - payload `32768`
    - target `2400 RPS`
  - Outcome:
    - `status=fail (latency_gate)`
    - effective `~1691.28 RPS`
    - error rate `~0.00112`
    - p95/p99 `~955.55ms / ~1492.97ms`
    - not generator-limited (`generator_limited=false`)
- Key evidence from this rerun:
  - Service-lane owner-forward path is fully bypassed as intended:
    - `dpdk_service_lane_forward_packets_total=0`
    - `dpdk_service_lane_forward_bytes_total=0`
  - No shared-demux software dispatch in this run:
    - `dpdk_flow_steer_dispatch_packets_total=0`
  - TLS/DPI phase counters (delta):
    - `client_tls_accept=145,418`
    - `h2_request_body_read=145,371`
    - upstream connect/tls/h2-handshake only `156` each
    - upstream H2 pool: `hit=145,402`, `miss=16`, `reconnect=140`
  - Thread-level CPU:
    - per firewall instance, `dataplane-runti` thread avg `~77%`, peak `~99%`
    - `dpdk-worker1` avg only `~0.5%`
    - host-wide firewall CPU remains low (`~29.7%` peak), indicating single-thread hot-spot behavior.
- Interpretation:
  - The service-lane forwarding bottleneck was removed functionally, but this workload remains latency-bound by a different hot path.
  - Current limit appears to be a single dataplane runtime thread in TLS/DPI handling (not DPDK queue fanout, not load-generator port exhaustion, not upstream CPU).
  - Next optimization effort should target parallelizing/splitting the TLS intercept runtime path itself, not additional service-lane queue tweaks alone.

## 2026-03-13 Config-Drift Fix + 4-vCPU DPI Recheck

### I) Runtime-tuning propagation fix in benchmark harness
- Root cause:
  - `cloud-tests/common/http-perf-matrix.sh` did not forward DPDK/TLS tuning env into each per-run invocation.
  - This allowed matrix runs to silently fall back to defaults (`perf_mode=Standard`, `requested_workers=1`) even when outer commands were tuned.
- Fixes applied:
  - `cloud-tests/common/http-perf-matrix.sh`: pass through runtime knobs explicitly (`DPDK_*`, TLS runtime knobs, VU/ramp knobs) to each run.
  - `cloud-tests/{azure,aws,gcp}/Makefile`: forward the same knobs in `http-perf.run` and `http-perf.quick` so `make ... DPDK_WORKERS=...` cannot silently drop settings.
- Verification:
  - Journal evidence after rerun on firewall nodes:
    - `dpdk perf mode selected perf_mode=Aggressive`
    - `dpdk worker configuration ... requested_workers=2`
    - no Azure single-worker guard override when `DPDK_ALLOW_AZURE_MULTIWORKER=true`.

### J) Focus rerun with intended settings actually active (`w=2`, pin=true, r2400)
- Artifact: `cloud-tests/azure/artifacts/http-perf-matrix-20260313T150206Z-dpi-config-drift-fix-r2400`
- Settings:
  - `DPDK_WORKERS=2`
  - `DPDK_ALLOW_AZURE_MULTIWORKER=true`
  - `DPDK_FORCE_SHARED_RX_DEMUX=1`
  - `DPDK_PERF_MODE=aggressive`
  - `DPDK_PIN_HTTPS_OWNER=true`
  - `CONTROLPLANE_WORKER_THREADS=8`
- Outcome:
  - `status=pass`
  - effective `~1965.13 RPS`
  - error rate `~0.000305`
  - p95/p99 `~62.96ms / ~75.01ms`
  - `dpdk_flow_steer_dispatch_packets_total=6,284,230`
  - `dpdk_service_lane_forward_packets_total=0`
- Interpretation:
  - Most of the prior regression was configuration drift.
  - With intended knobs active, throughput recovers to ~1.97k on this profile.

### K) Pinning A/B under same load (`w=2`, r2400)
- Pin true artifact: `...150206Z-dpi-config-drift-fix-r2400` (J)
- Pin false artifact: `cloud-tests/azure/artifacts/http-perf-matrix-20260313T150605Z-dpi-pinfalse-r2400`
- Pin false outcome:
  - `status=pass`
  - effective `~1965.99 RPS` (same throughput class)
  - error rate `~0.000061` (better)
  - p95/p99 `~47.16ms / ~54.45ms` (better)
  - firewall CPU peak `~56.65%` vs `~65.8%` with pin true
  - `dpdk_flow_steer_dispatch_packets_total=3,348,362` (lower than pin true)
- Interpretation:
  - On this 4-vCPU profile, `pin=false` is preferable (same throughput, materially better latency/error/CPU).

### L) Worker-count scaling check on 4-vCPU firewall
- `w=3`, pin=false, r2400:
  - Artifact: `cloud-tests/azure/artifacts/http-perf-matrix-20260313T151149Z-dpi-w3-pinfalse-r2400`
  - `status=fail`, effective `~1320.82 RPS`, error `~0.1129`
- `w=3`, pin=false, r3000:
  - Artifact: `cloud-tests/azure/artifacts/http-perf-matrix-20260313T150847Z-dpi-w3-pinfalse-r3000`
  - `status=fail`, effective `~1635.99 RPS`, error `~0.1135`
- Interpretation:
  - `w=3` is unstable/worse on D4as_v5 for this workload; likely added scheduling/queue overhead with insufficient cores.

### M) Higher offered load (`r3000`) with `w=2`, pin=false
- Without VU override:
  - Artifact: `cloud-tests/azure/artifacts/http-perf-matrix-20260313T151448Z-dpi-w2-pinfalse-r3000`
  - `status=invalid (generator_limited)`, `insufficient_vus=1`
  - effective `~1422.73 RPS`, error `~0.1687`
- With `PRE_ALLOCATED_VUS=12000 MAX_VUS=48000`:
  - Artifact: `cloud-tests/azure/artifacts/http-perf-matrix-20260313T151805Z-dpi-w2-pinfalse-r3000-vu`
  - `status=fail` (not generator-limited)
  - effective `~1699.38 RPS`, error `~0.1701`
- Interpretation:
  - At 3000 offered load this profile enters high-error collapse; sustainable path remains around ~1.9-2.0k RPS class with acceptable error/latency.

## Revised Recommendation (D4as_v5, TLS+DPI new-connection-heavy)
- Keep:
  - `NEUWERK_DPDK_WORKERS=2`
  - `NEUWERK_DPDK_FORCE_SHARED_RX_DEMUX=1`
  - `NEUWERK_DPDK_ALLOW_AZURE_MULTIWORKER=true`
  - `NEUWERK_DPDK_PERF_MODE=aggressive`
  - `NEUWERK_DPDK_PIN_HTTPS_OWNER=false` (preferred on this instance size)
- Avoid:
  - `NEUWERK_DPDK_WORKERS=3` on 4-vCPU nodes for this path.

## 2026-03-13 Binary Provenance Recovery + True D4 vs D16 Scaling Check

### N) Binary provenance incident and recovery
- We found a mixed-artifact VMSS state:
  - two firewall instances were healthy on a newer CLI (`--dns-target-ip` supported),
  - one instance was crash-looping on an older CLI (`--dns-listen` only).
- Attempting to roll forward with local `target/release/neuwerk` introduced an ABI mismatch on Azure nodes:
  - runtime error: `librte_eal.so.26: cannot open shared object file`.
  - local hash was `460cec7f...` and was not deploy-safe for this image.
- Recovery path:
  - extracted known-good running binary from healthy node (`sha256 c14d9a07229572640f5a5a5c6a58ff74a54bf138bc4dce055b97353f87acb7ad`),
  - republished that exact artifact to Terraform storage blob via `neuwerk_binary_path`,
  - forced failing node to re-download from blob and restart service.
- Post-recovery convergence:
  - all 3 firewall instances `active`,
  - all 3 running identical hash `c14d9a...`.

### O) Important correction: the earlier `...dpi-scale-d8-clean` run was still on 4-vCPU nodes
- Terraform VMSS model had been updated, but Azure VMSS `upgrade_mode=Manual` meant instance hardware was not applied until explicit update.
- Measured state during that run:
  - `nproc=4` on firewall instances (effectively D4 class),
  - artifact: `cloud-tests/azure/artifacts/http-perf-matrix-20260313T160234Z-dpi-scale-d8-clean`.
- Results from that run (true 4-vCPU):
  - `rps=2400`: pass, effective `1964.20`, error `0.000061`, p95/p99 `46.08/50.36 ms`, firewall CPU peak `55.5%`.
  - `rps=3000`: pass, effective `2452.96`, error `0.0000868`, p95/p99 `49.87/56.51 ms`, firewall CPU peak `57.37%`.

### P) True D16 rollout and focused rerun
- Required steps:
  - set VMSS model to `Standard_D16as_v5`,
  - explicitly apply model to instances via `az vmss update-instances`.
- Quota constraint encountered:
  - Azure regional core quota blocked model application (`Current Limit 65`, needed `66-70` during rollout).
  - Worked around by temporarily downsizing non-firewall nodes to free cores:
    - consumer `D16 -> D8`,
    - upstream `D16 -> D8 -> D4`.
- Verification after update:
  - all firewall instances report `Standard_D16as_v5`,
  - `nproc=16` on each,
  - service `active`, binary hash `c14d9a...`.
- True D16 focused artifact:
  - `cloud-tests/azure/artifacts/http-perf-matrix-20260313T161537Z-dpi-scale-d16-clean`
  - scenario unchanged for apples-to-apples:
    - `tls_intercept_http_path`
    - `new_connection_heavy`
    - payload `32768`
    - tiers `2400,3000`
    - `DPDK_WORKERS=2`, `DPDK_FORCE_SHARED_RX_DEMUX=1`, `DPDK_PERF_MODE=aggressive`, `DPDK_PIN_HTTPS_OWNER=false`
- Results (true D16):
  - `rps=2400`: pass, effective `1963.71`, error `0.000204`, p95/p99 `45.37/48.44 ms`, firewall CPU peak `13.68%`.
  - `rps=3000`: pass, effective `2454.12`, error `0.000223`, p95/p99 `47.48/53.29 ms`, firewall CPU peak `14.1%`.

### Q) Scaling interpretation from D4 vs D16 at identical workload
- Throughput is effectively unchanged between true D4 and true D16 at these tiers (~1.96k at 2400 target, ~2.45k at 3000 target).
- Thread-level evidence shows the same hot-thread ceiling in both runs:
  - D4 run top thread max ~`98.7%`,
  - D16 run top thread max ~`99.3%`.
- Host-level CPU drops sharply on D16 because more cores are idle, but bottleneck stays in one runtime thread.
- Conclusion:
  - Vertical scaling alone does not improve TLS+DPI throughput for this path at current architecture.
  - The current limiter is a single-thread TLS/DPI runtime hot path, not total host CPU capacity.

### R) Practical next actions
- Bench:
  - keep D16 for now and run higher offered tiers (`3600, 4200, 5000`) to identify where error/latency collapse starts on larger cores.
- Code:
  - prioritize TLS intercept runtime parallelism (shard/parallelize handshake + request-body/read path) over additional service-lane queue tuning.
- Infra hygiene:
  - enforce explicit post-apply VMSS model rollout (`az vmss update-instances`) in bench automation when `upgrade_mode=Manual`.
  - keep deploy artifact provenance pinned and hash-verified; avoid uploading host-local binaries unless ABI-compatible with target image.

## 2026-03-13 Deep-Dive (No New Tiers): Intercept Demux Lock Serialization

### S) Hot-path bug candidate confirmed in code
- `SharedInterceptDemuxState` was guarded by one global `Mutex` and used from both dataplane workers and TLS intercept runtime.
- In TLS intercept path this map is touched on the per-packet hot path:
  - outbound-to-service-lane packet: `queue_intercept_host_frame()` -> `upsert_intercept_demux_entry()`
  - service-lane return packet: `rewrite_intercept_service_lane_egress()` -> `lookup_intercept_demux_entry()`
- This means one global lock was in the packet loop for every intercepted packet.

### T) Why this matches observed scaling symptoms
- In the true D16 focused run (`...161537Z-dpi-scale-d16-clean`), fixed scenario (`new_connection_heavy`, `32768B`) shows:
  - `rps=2400`: `147,396` requests, `6,967,209` DPDK RX packets (`47.27` packets/request), `3,293,183` flow-steer packets.
  - `rps=3000`: `184,221` requests, `8,737,508` DPDK RX packets (`47.43` packets/request), `4,056,318` flow-steer packets.
- At these packet rates, a single shared demux mutex is a credible architectural serialization point and explains weak vertical scaling despite low host-wide CPU on larger SKUs.

### U) Implemented fix (code-level)
- Reworked intercept demux state from single global lock to sharded shared state:
  - `SharedInterceptDemuxState` now owns `Vec<Mutex<InterceptDemuxShard>>`.
  - shard count is configurable via `NEUWERK_DPDK_INTERCEPT_DEMUX_SHARDS` (default `64`).
  - `upsert/remove/lookup` now lock only the key’s shard.
- Removed outer `Arc<Mutex<SharedInterceptDemuxState>>` plumbing and switched call sites to `Arc<SharedInterceptDemuxState>`:
  - dataplane adapter/service-lane runtime
  - runtime DPDK startup path
  - trafficd TLS intercept lookup path
  - startup wiring + tests/e2e helpers

### V) Local verification
- `cargo check` passed.
- Focused regressions passed:
  - `cargo test shared_intercept_demux_gc_is_amortized_between_lookups`
  - `cargo test lookup_intercept_demux_original_dst_returns_stored_tuple`

### W) Next cloud validation (same fixed scenario, no new tier sweep)
- Re-run exactly:
  - `tls_intercept_http_path`
  - `new_connection_heavy`
  - payload `32768`
  - target `3000 RPS`
- Compare before/after:
  - effective RPS, error rate, p95/p99
  - dataplane worker CPU balance
  - `dpdk_flow_steer_dispatch_packets_total` and queue wait
  - (`perf`) top symbols on worker threads to verify demux lock pressure is reduced from top hotspots.

## 2026-03-13 Deep-Dive Continuation (No New Tiers, Fixed `RPS=3000`)

### X) A/B summary at constant workload
- Stable baseline (shared-demux):  
  `cloud-tests/azure/artifacts/http-perf-matrix-20260313T-dpi-multiqueue-r3000/.../repeat-1`
  - pass, `~2456.59 RPS`, error `~0.000358`
  - `dpdk_shared_io_lock_contended_total=155,984,403`
  - `dpdk_shared_io_lock_wait_seconds_sum=50.72s`
- Queue-per-worker (unforced demux):  
  `cloud-tests/azure/artifacts/http-perf-matrix-20260313T183830Z-dpi-noshared-r3000-fix-cp8`
  - fail, `~1755.53 RPS`, error `~0.2665`
  - shared lock contention disappears (`0`), but correctness/latency collapse persists

### Y) Code change tested
- Change applied in `src/runtime/dpdk/run.rs`:
  - service-lane egress draining is no longer worker-0-only; all workers drain their own egress path
  - DHCP emission remains worker-0-only
- Regression unit test added:
  - `worker_emits_dhcp_housekeeping_only_on_worker_zero`
- Result:
  - this did **not** resolve the queue-per-worker failure signature at fixed 3000 RPS.

### Z) New root-cause evidence from runtime logs
- On queue-per-worker startup (`force_shared_rx_demux=0`), logs show:
  - `dpdk starting worker threads ... mode=QueuePerWorker`
  - repeated `rss reta update failed ... reported_reta_size=0 ... last_ret=-95`
- During those runs, trafficd reports heavy TLS-intercept path failures:
  - `client tls handshake timed out`
  - `h2 request body read timed out`
  - `h2 upstream response failed`
- Interpretation:
  - this Azure path does not provide a reliable multi-queue RSS/RETA setup for this workload.
  - Queue-per-worker currently appears functionally unstable here, even though it removes shared-IO lock contention.

### AA) Shared-demux tuning experiment (`owner_only`)
- Artifact: `cloud-tests/azure/artifacts/http-perf-matrix-20260313T184359Z-dpi-shared-owneronly-r3000`
- Knobs:
  - `DPDK_FORCE_SHARED_RX_DEMUX=1`
  - `DPDK_SHARED_RX_OWNER_ONLY=1`
  - `DPDK_WORKERS=2`
- Outcome:
  - pass, `~2455.13 RPS` (roughly unchanged vs baseline)
  - lock contention reduced significantly:
    - contended `155,984,403 -> 24,038,352`
    - wait sum `50.72s -> 40.93s`
  - throughput cap remained essentially unchanged at this offered load.

### AB) Shared-demux + `DPDK_WORKERS=4` (same offered load)
- Artifact: `cloud-tests/azure/artifacts/http-perf-matrix-20260313T184645Z-dpi-shared-owneronly-w4-r3000`
- Outcome:
  - pass but throughput regressed to `~1604.16 RPS`, error `~0.0096`
  - shared lock contention worsened again (`95,933,165`, wait `181.65s`)
- Interpretation:
  - adding workers on single-queue/shared-IO path can amplify contention and reduce throughput.

### AC) Current practical conclusion
- For this Azure setup and this DPI scenario, throughput is presently bounded by single-queue/shared-IO architecture constraints, while queue-per-worker mode is not reliable due RSS/RETA behavior (`reta_size=0`, update failure).
- Best known stable operating point from these fixed-tier reruns remains:
  - `DPDK_WORKERS=2`
  - `DPDK_FORCE_SHARED_RX_DEMUX=1`
  - `CONTROLPLANE_WORKER_THREADS=8`
- Next worthwhile code task (not yet implemented):
  - auto-downgrade to single-queue/shared-demux when multi-queue RETA programming fails, instead of entering unstable QueuePerWorker mode.

## 2026-03-13 Implementation + Validation: Automatic RETA Failure Fallback

### AD) Code changes
- Added automatic fallback logic in `src/dataplane/dpdk_adapter/io/init_port.rs`:
  - if `queue_count > 1`, RSS mq is in use, and `reta_size == 0`, force single queue.
  - warning emitted with explicit override hint:
    - `NEUWERK_DPDK_ALLOW_RETALESS_MULTI_QUEUE=1`
- Added helper + test coverage in `src/dataplane/dpdk_adapter/io.rs`:
  - `should_force_single_queue_without_reta(...)`
  - test: `should_force_single_queue_without_reta_when_unavailable_and_not_overridden`
- Existing housekeeping worker-role test remains:
  - `worker_emits_dhcp_housekeeping_only_on_worker_zero`

### AE) Deploy + runtime verification
- Deployed binary hash: `2dfa157c207887d889ca3c8e72a634692d5e3211bfd83bd6301912e7502f1153` on all firewall nodes.
- Journal evidence on startup (with `DPDK_FORCE_SHARED_RX_DEMUX=0`):
  - `reta_size=0 with multi-queue RSS; forcing single queue ...`
  - runtime mode became `SharedRxDemux` (not `QueuePerWorker`).

### AF) Fixed-scenario validation (same `3000/new_connection_heavy/32768B`)
- Previous failing no-shared run (before fallback):
  - `cloud-tests/azure/artifacts/http-perf-matrix-20260313T183830Z-dpi-noshared-r3000-fix-cp8`
  - `fail`, `~1755.53 RPS`, error `~0.2665`, `shared_lock_contended=0`
- After fallback fix (still `DPDK_FORCE_SHARED_RX_DEMUX=0` in runtime knobs):
  - `cloud-tests/azure/artifacts/http-perf-matrix-20260313T185659Z-dpi-noshared-r3000-reta-fallback`
  - `pass`, `~2457.68 RPS`, error `~0.000439`
  - `shared_lock_contended=138,080,212`, flow-steer packets `~4.10M`
- This matches the stable baseline behavior and removes the `~26%` reset/error failure mode.

### AG) Updated conclusion
- Root cause of the “no-shared” collapse at fixed 3000 was not raw CPU saturation; it was entering an unstable multi-queue RSS path on this Azure environment (`reta_size=0`, RETA update failure).
- Throughput ceiling remains in the single-queue/shared-demux architecture (~2.45k effective RPS at this offered load), but the new fallback prevents accidental regression into the broken queue-per-worker mode.

## 2026-03-13 Focused Follow-up: 3k/4k Sweep + Lock/Hot-Thread Deep Check

### AH) Quick DPI sweep executed (keep-alive only)
- Artifact:
  - `cloud-tests/azure/artifacts/http-perf-matrix-20260313T210345Z-dpi-keepalive-r3k4k-lockprobe`
- Matrix:
  - scenario `tls_intercept_http_path`
  - payloads `1024`, `32768`
  - mode `keep_alive`
  - tiers `3000`, `4000`
  - repeats `1`
- Outcome:
  - `combo_count=4`, `pass_count=4`, `fail_count=0`, `invalid_count=0`
  - 3k effective around `~2458-2460 RPS`
  - 4k effective around `~3279 RPS`
  - no generator-limit flags in any combo

### AI) Important interpretation update: “effective_rps” includes ramp period
- Current benchmark reports `effective_rps` from k6 total request rate across the full run, not steady-only.
- With current defaults (`RAMP_SECONDS=30`, `STEADY_SECONDS=45`), this naturally lowers apparent RPS compared to tier target.
- This explains why `3000` tiers repeatedly show `~245x` effective without corresponding saturation/failure signatures.

### AJ) Hot thread / locking investigation (same 4k keep-alive workload)
- Baseline (`DPDK_SHARED_RX_OWNER_ONLY=0`, workers=2):
  - effective `3278.70 RPS`
  - `dpdk_shared_io_lock_contended_total=246,212,059`
  - `dpdk_shared_io_lock_wait_seconds_sum=38.52s`
  - top thread CPU `~99.8%`
- A/B (`DPDK_SHARED_RX_OWNER_ONLY=1`, workers=2):
  - Artifact: `cloud-tests/azure/artifacts/http-perf-matrix-20260313T211336Z-dpi-4k-owneronly1`
  - effective `3277.01 RPS` (no meaningful change)
  - lock contention dropped ~10x:
    - `246,212,059 -> 25,490,935`
    - wait `38.52s -> 3.43s`
  - top thread CPU remains `~99.8-100%`
- Interpretation:
  - `dpdk_shared_io_lock_*` is strongly reduced by owner-only polling, but throughput at this load is unchanged.
  - Therefore shared-IO lock contention counters here are primarily an efficiency signal, not the active throughput limiter.

### AK) Additional probe: `new_connection_heavy` at 3000 with owner-only
- Artifact:
  - `cloud-tests/azure/artifacts/http-perf-matrix-20260313T211652Z-dpi-newconn-r3k-owner1`
- Outcome:
  - pass, no generator-limit flags
  - effective `2457.74 RPS` (same ramp-normalized interpretation caveat)
  - firewall CPU peak `13.3%`
  - top thread CPU still near `99.8%`

### AL) Worker-count scaling probe at fixed 4k keep-alive
- Artifact:
  - `cloud-tests/azure/artifacts/http-perf-matrix-20260313T212006Z-dpi-4k-w3-owner1`
- Compared to workers=2 owner-only:
  - throughput essentially flat (`3278.03` vs `3277.01`)
  - lock contention increased (`25.49M -> 52.07M`)
  - firewall CPU increased (`~12.69 avg -> ~18.84 avg`)
- Interpretation:
  - adding another worker in shared-IO/demux mode increased contention/cost without throughput gain at this load.

### AM) Practical conclusion from this pass
- No evidence of hard saturation at 3k/4k in these keep-alive DPI runs.
- The persistent `~99%` DPDK worker threads are expected busy-poll behavior, not by themselves proof of throughput collapse.
- For this architecture and configuration, `owner_only=1` is a better efficiency posture (much lower shared lock pressure) but does not increase throughput in this load region.

## 2026-03-13 Reporting Fix + Breakpoint Sweep (Steady-Phase RPS)

### AN) Reporting fix implemented
- Files updated:
  - `cloud-tests/common/http-perf/k6/webhook.js`
  - `cloud-tests/common/http-perf-run.sh`
- Change:
  - Added k6 counters `steady_requests` and `steady_failures` (counted only after ramp window).
  - Result aggregation now computes:
    - `results.effective_rps` = `steady_requests_count / STEADY_SECONDS`
    - `results.effective_rps_overall` = original full-run average rate (for reference)
    - `results.requests_steady_total`
    - `results.steady_error_rate`
- Validation artifact:
  - `cloud-tests/azure/artifacts/http-perf-matrix-20260313T212656Z-dpi-reporting-smoke`
  - at target `4000`, steady `effective_rps` now reports `~4000.18` (previous overall value still available as `~3277.85`).

### AO) High-tier keep-alive sweep (fresh progression)
- Scenario shape:
  - `tls_intercept_http_path`, payload `1024`, `keep_alive`, `HTTP_REPEATS=1`
  - knobs: `DPDK_WORKERS=2`, `DPDK_FORCE_SHARED_RX_DEMUX=0` (fallback active), `DPDK_SHARED_RX_OWNER_ONLY=1`
- Artifacts and outcomes:
  - `...-dpi-breakpoint-keepalive` (`4k,6k,8k,10k,12k`): all pass
  - `...-dpi-breakpoint-keepalive-hi` (`16k,20k,24k`): all pass
  - `...-dpi-breakpoint-keepalive-extreme` (`32k,48k,64k`): all fail (`error_rate_gate`)
- First clean fail observed at `32k`; `24k` still passed in the same progression.

### AP) Knee narrowing + stability checks
- Narrow follow-ups:
  - `...-dpi-breakpoint-keepalive-narrow` (`26k,28k,30k`): all fail
  - `...-dpi-breakpoint-keepalive-fine` (`24.5k,25k,25.5k`): all fail
  - `...-dpi-breakpoint-keepalive-stabilize` (`22k,23k,24k`): all fail
  - control `...-dpi-breakpoint-control-20k` (`20k`): fail
- Failure signature across these later runs:
  - non-generator-limited (`generator_limited=false`)
  - `error_rate ~2.1%..2.6%`
  - very high tail latency (`p99` in multi-second to 10s+ range)
  - k6 errors dominated by upstream-side stream terminations:
    - `stream error ... CANCEL; received from peer`
    - `unexpected EOF`

### AQ) Saturation interpretation (current run state)
- In failing control run (`20k`), host-level CPU showed:
  - firewall avg ~12.7% (not globally CPU-saturated)
  - consumer and upstream peaks reached ~100%
- This indicates the failing mode under prolonged stress is not a simple firewall host CPU ceiling; it is a pipeline/backpressure failure (upstream/h2 stream cancel behavior + load path instability at high sustained concurrency).
- Practical breakpoint from this session:
  - fresh progression: stable up to `24k`, first fail at `32k`
  - after extended high-stress sequence: degradation observed and failures occurred even at `20k-24k`
  - therefore the sustainable limit depends on run history/soak state; further characterization should include periodic cool-down/restart checkpoints if we need a strict steady-state SLO number.

## 2026-03-14 Hot-Thread/Node + Recovery-Mode Follow-up

### AR) `20k/24k` repeat sweep with hot-thread and node distribution evidence
- Artifact:
  - `cloud-tests/azure/artifacts/http-perf-matrix-20260313T230122Z-dpi-20k24k-repeats-hotthread`
- Scenario:
  - `tls_intercept_http_path`, payload `1024`, `keep_alive`, `HTTP_REPEATS=3`
- Result:
  - `20k`: pass `3/3` (`~20008 effective RPS`, low errors)
  - `24k`: repeat-1 fail (`error_rate_gate`), repeats 2-3 invalid (`generator_limited: insufficient_vus`) after collapse
- Hot-thread finding:
  - each firewall node had a similarly hot `dataplane-runti` thread (roughly `~84-93%` max in sampled windows), without one node standing out.
- Node distribution finding:
  - at `20k` per-node RX deltas stayed near-even (`~33/33/34%`).
  - at failing `24k` repeat-1 still only mild skew (`~35.5/33.3/31.2%`), not enough to explain collapse.
- Error-path finding at failure:
  - `svc_tls_intercept_errors_total{stage="upstream_h2_ready",reason="failure"}` spikes hard.
  - pool reconnects jump from ~`1.2k` (`20k`) to tens/hundreds of thousands in failing runs.
- Interpretation:
  - failure mode is not primarily hot-thread or hot-node distribution; it is an upstream H2 ready/reconnect storm.

### AS) Recovery-mode matrix (`24k` collapse -> `20k` control)
- `24k` collapse induction:
  - `...233310Z-dpi-recoveryA-collapse24k`: fail, non-generator-limited, high `upstream_h2_ready` failures and high reconnects.
- Immediate `20k` without restart:
  - `...233602Z-dpi-recoveryA-control20k-no-restart`: invalid (`generator_limited`), very high errors.
- `20k` after **upstream-only restart**:
  - `...233848Z-dpi-recoveryA-control20k-after-upstream-restart`: still invalid (`generator_limited`), no recovery.
- `24k` collapse induction (second branch):
  - `...234140Z-dpi-recoveryB-collapse24k`: invalid (`generator_limited`) with persistent collapse signatures.
- `20k` after **firewall-only restart**:
  - `...234443Z-dpi-recoveryB-control20k-after-firewall-restart`: recovered throughput (`~19.8k` effective RPS), not generator-limited, but still latency-gate fail due high tail (`p99 ~2003ms`).
- Interpretation:
  - degraded/collapsed state appears to be sticky primarily in firewall runtime state (likely upstream H2 pool/session lifecycle behavior), not solely upstream nginx process state.

### AT) Code instrumentation added (local repo, not yet deployed to cloud run)
- Added dedicated metric:
  - `svc_tls_intercept_upstream_h2_ready_errors_total{kind=...}`
- Added classifier for `upstream_h2_ready` error kinds (timeout/cancel/protocol/etc.) and hooked it in `record_tls_intercept_connection_error`.
- Added unit test coverage:
  - `tls_intercept_runtime_records_upstream_h2_ready_error_kind_metric`
- Goal:
  - make `upstream_h2_ready` failures explorable by concrete error class instead of a single generic `reason="failure"` bucket.

## 2026-03-14 Focused DPI Throughput Follow-up (Pool/Latency)

### AU) Baseline stability check after pool fixes
- Artifact:
  - `cloud-tests/azure/http-perf-matrix-20260314T006-20k24k-repeats-postretire`
- Scenario:
  - `tls_intercept_http_path`, payload `1024`, `keep_alive`, `HTTP_REPEATS=2`, `RPS=20000,24000`
- Result:
  - `20k`: pass `2/2` with `0.0%` errors (`p95 ~30-33ms`, `p99 ~47-52ms`)
  - `24k`: fail `2/2`, but **latency gate only** (`error_rate=0.0%`)
  - `24k` p95/p99 around `~106-109ms / ~310-313ms`
- Interpretation:
  - prior error-mode (`upstream_response` failures) is mitigated at this load band.
  - new practical limiter at `24k` in this state is tail-latency, not error-rate.

### AV) Send-path lock experiment
- Code change:
  - in `send_upstream_h2_request`, avoid holding `client.send_request` mutex across `ready().await` by cloning sender under lock and awaiting `ready()` on the clone.
- Artifact:
  - `cloud-tests/azure/http-perf-matrix-20260314T007-24k-post-sendlockfix`
- Result:
  - `24k`: still fail `2/2` by latency gate (`error_rate=0.0%`).
  - median p95/p99 moved to `~120ms / ~339ms` (not improved vs `T006`).
- Interpretation:
  - this specific lock-hold reduction did not produce measurable throughput/tail improvement in the current bottleneck regime.

### AW) H2 connection retirement budget experiment
- Harness change:
  - added `TLS_H2_MAX_REQUESTS_PER_CONNECTION` as a bench/runtime-tuning knob:
    - `cloud-tests/common/http-perf-run.sh`
    - `cloud-tests/common/http-perf-matrix.sh`
    - provider Makefiles (`azure/aws/gcp`)
- A/B run with higher cap:
  - Artifact: `cloud-tests/azure/http-perf-matrix-20260314T008-24k-maxreq4000`
  - Setting: `TLS_H2_MAX_REQUESTS_PER_CONNECTION=4000`
- Result:
  - `24k`: fail `2/2` by **error-rate gate** (`~1.10-1.16%`), with much worse latency (`p95 ~365-372ms`, `p99 ~851-856ms`).
  - `upstream_response` failures rose (`~10k` per repeat), while `upstream_h2_ready` failures remained `0`.
  - Pool churn dropped (miss/connect_wait lower), but reliability regressed.
- Interpretation:
  - aggressive long-lived H2 reuse is counterproductive here; it trades connection churn for upstream response instability.
  - default request-retirement behavior (800) is currently safer.

### AX) Control sanity after experiments
- Artifact:
  - `cloud-tests/azure/http-perf-matrix-20260314T009-20k-control-postexp`
- Result:
  - `20k` keep-alive passed (`0.0%` error, `p95 ~34.8ms`, `p99 ~78.6ms`).
- Interpretation:
  - environment/runtime remained healthy after the `24k` experiments.

### AY) Current bottleneck statement (updated)
- At this point, the dominant constraint in the `24k` keep-alive DPI case is **tail-latency amplification in the upstream H2 path**, not host-level CPU saturation and not load-generator exhaustion.
- Failure mode is sensitive to upstream response behavior and pool/session lifecycle tuning; pushing for longer-lived upstream sessions (`max_requests_per_connection=4000`) worsened both latency and error-rate.
- Practical current operating point in this environment remains around `20k` for clean pass behavior under this gate profile.

## 2026-03-14 Continuation: Upstream-Response Instrumentation + H2 Tuning A/B

### AZ) Instrumentation + harness hardening added
- Added upstream response error-kind metric:
  - `svc_tls_intercept_upstream_response_errors_total{kind=...}`
  - wiring/classification in `record_tls_intercept_connection_error(...)` for `stage="upstream_response"`.
  - test added: `tls_intercept_runtime_records_upstream_response_error_kind_metric`.
- Hardened SSH helper for cloud bench:
  - `cloud-tests/common/lib.sh` now uses `BatchMode`, `ConnectTimeout`, `ServerAliveInterval`, `ServerAliveCountMax` in `ssh_jump`.
  - prevents matrix runs from hanging indefinitely on one SSH leg.
- Parameterized upstream nginx H2 knobs for controlled A/Bs:
  - `UPSTREAM_KEEPALIVE_TIMEOUT`
  - `UPSTREAM_KEEPALIVE_REQUESTS`
  - `UPSTREAM_HTTP2_MAX_CONCURRENT_STREAMS`
  - in `cloud-tests/common/http-perf-upstream-configure.sh`.

### BA) Error-mode root cause confirmation (`no_error_close`)
- Baseline at `24k` (default maxreq) still fails by latency gate with `0%` errors:
  - `T010`: `cloud-tests/azure/http-perf-matrix-20260314T010-24k-upresp-metric`
  - `p95/p99 ~121.7/329.4ms`, `error_rate=0`.
  - `svc_tls_intercept_upstream_response_errors_total{kind=*}` delta remained `0`.
- Long-lived H2 (`TLS_H2_MAX_REQUESTS_PER_CONNECTION=4000`) reproduces upstream-response error mode:
  - `T011`: `cloud-tests/azure/http-perf-matrix-20260314T011-24k-maxreq4000-upresp-metric`
  - `error_rate ~1.27%`, `p95/p99 ~371/845ms`.
  - dominant counter delta:
    - `svc_tls_intercept_upstream_response_errors_total{kind="no_error_close"} = 11640`
    - `svc_tls_intercept_errors_total{stage="upstream_response",reason="failure"} = 11640`
- Conclusion:
  - this failure mode is a concrete upstream-response close behavior (`no_error_close`), not generic CPU overload.

### BB) Upstream nginx H2 tuning at `24k` (default maxreq)
- First attempt (`T012`) partially stalled in post-collection (now mitigated by SSH timeout/keepalive changes):
  - `cloud-tests/azure/http-perf-matrix-20260314T012-24k-upstream-h2-tuned`
- Clean rerun:
  - `T014`: `cloud-tests/azure/http-perf-matrix-20260314T014-24k-upstream-h2-tuned-rerun-clean`
  - result: fail by latency gate only, `error_rate=0`, `effective_rps~24009`.
  - latency improved vs `T010`:
    - `p95: 121.7 -> 99.1ms`
    - `p99: 329.4 -> 302.9ms`
  - `no_error_close` stayed `0`.
- Node/hot-thread evidence at `T014`:
  - per-node request/body-read distribution remained near-even (~`302k-309k` each).
  - per-node top thread is consistently `dataplane-runti` (no single-node outlier).

### BC) Focused H2 lifecycle/multiplexing A/B at `24k`
- `T015` (`maxreq=4000`, tuned upstream defaults):
  - `cloud-tests/azure/http-perf-matrix-20260314T015-24k-upstream-h2-tuned-maxreq4000`
  - no errors (`no_error_close=0`), but latency worsened vs `T014` (`p99 318.2ms`).
  - churn dropped strongly (`conn_closed 4300 -> 1608`, `miss 1146 -> 230`), but send-lock wait rose:
    - `upstream_h2_send_lock_wait` avg `0.092 -> 0.144ms`.
- `T016` (`maxreq=4000`, `UPSTREAM_HTTP2_MAX_CONCURRENT_STREAMS=256`):
  - `cloud-tests/azure/http-perf-matrix-20260314T016-24k-upstream-h2streams256-maxreq4000`
  - partial improvement vs `T015` (`p99 318.2 -> 313.3ms`), send-lock avg `0.144 -> 0.102ms`.
  - still worse than `T014` baseline.
- `T017` (`default maxreq`, `UPSTREAM_HTTP2_MAX_CONCURRENT_STREAMS=256`):
  - `cloud-tests/azure/http-perf-matrix-20260314T017-24k-upstream-h2streams256-defaultmaxreq`
  - regressed tails (`p99 322.6ms`) and higher lock-wait cost than `T014`.
- Conclusion:
  - reducing churn alone does not improve 24k tails; trade-off shifts into per-connection contention/HOL behavior.
  - best tested `24k` profile remains default maxreq with tuned upstream keepalive (`T014`), but still above latency gate.

### BD) Updated bottleneck statement (current best evidence)
- At `24k` keep-alive, the active limiter is latency tail amplification inside the firewall DPI path, strongly coupled to upstream H2 session/send-path behavior.
- Not the primary limiter in current runs:
  - load generator (no generator-limit flags in these keep-alive A/Bs),
  - upstream host CPU saturation,
  - single hot firewall node (distribution stays balanced).
- Likely limiter pattern:
  - serialized/contended path around upstream H2 send readiness (observable via higher `upstream_h2_send_lock_wait` and hot `dataplane-runti` thread even when host CPU is low).
- Practical operating guidance:
  - `20k` remains stable/pass.
  - `24k` currently misses latency SLO despite near-zero error rates under best-known config.

## 2026-03-14 Re-Architecture Attempt: Sharded Upstream H2 Session Set + Extra Observability

### BE) Code changes implemented
- Runtime/pool:
  - Added pool sharding knob `NEUWERK_TLS_H2_POOL_SHARDS` (default `1`, clamp `1..64`).
  - Added round-robin shard key selection per upstream origin (`host@addr#sN`) when shards > 1.
- New metrics:
  - `svc_tls_intercept_upstream_h2_shard_select_total{shard}`
  - `svc_tls_intercept_upstream_h2_send_wait_seconds{phase=sender_clone_lock_wait|ready_wait}`
  - `svc_tls_intercept_upstream_h2_selected_inflight`
  - `svc_tls_intercept_upstream_h2_pool_width`
  - `svc_tls_intercept_upstream_h2_conn_termination_total{kind,reason}`
- Harness knobs added and plumbed through matrix/provider Makefiles:
  - `TLS_H2_POOL_SHARDS`
  - `TLS_H2_DETAILED_METRICS`

### BF) 24k focused results with sharded session set
- `T018` (`TLS_H2_POOL_SHARDS=4`):
  - `cloud-tests/azure/http-perf-matrix-20260314T018-24k-poolshards4`
  - `p95/p99 ~116.2/324.3ms`, `error=0`, fail by latency gate.
  - shard distribution was even (`~229k` selects each shard).
  - handshakes/churn dropped strongly vs baseline (`~4.7 -> ~1.55 per 1k req`).
- `T019` (`TLS_H2_POOL_SHARDS=2`):
  - `cloud-tests/azure/http-perf-matrix-20260314T019-24k-poolshards2`
  - `p95/p99 ~122.9/331.2ms`, `error=0`, fail by latency gate.
  - handshakes/churn reduced (to `~2.84 per 1k req`) but tails were worse than baseline.
- Conclusion:
  - sharding reduced upstream reconnect/churn but did **not** improve tail latency; it regressed p95/p99 in these runs.
  - this indicates churn is not the dominant limiter at 24k under current architecture.

### BG) Observability overhead check + gating
- First implementation had detailed per-request histograms always on and showed higher tail numbers in baseline controls.
- Added runtime gate `NEUWERK_TLS_H2_DETAILED_METRICS` (default off):
  - detailed metrics (`send_wait`, `selected_inflight`, `pool_width`) now only record when enabled.
  - low-cost termination classification counter remains on.
- Validation:
  - `T023` (`500 RPS`, `TLS_H2_DETAILED_METRICS=1`) shows non-zero detailed metrics, confirming debug mode works:
    - `svc_tls_intercept_upstream_h2_send_wait_seconds_count{phase="sender_clone_lock_wait"} > 0`
    - `svc_tls_intercept_upstream_h2_send_wait_seconds_count{phase="ready_wait"} > 0`
    - `svc_tls_intercept_upstream_h2_pool_width_count > 0`
    - `svc_tls_intercept_upstream_h2_selected_inflight_count > 0`
- Baseline controls after gating:
  - `T021`, `T022` (`24k`, default knobs) stayed latency-gate fail with `~323ms` and `~315ms` p99 respectively (same qualitative regime as prior 24k fails; no new error-mode).

### BH) Current take-away from this pass
- The sharded session-set re-architecture is **not** a win for 24k p99 in current form, despite reducing handshake churn.
- The strongest remaining signal continues to be send-path contention/queuing effects rather than connection churn or raw CPU.
- Keep sharding knob as an experiment (default off behavior via `POOL_SHARDS=1`), keep detailed metrics opt-in for debugging (`TLS_H2_DETAILED_METRICS=1`), and avoid enabling sharding in production profile until a better dispatch policy is proven.

## 2026-03-14 Continuation: Adaptive Least-Loaded Selector + Weight Sweep

### BI) Selector implementation completed and deployed
- Selection policy in `select_upstream_h2_client(...)` now scores candidates by:
  - `(in_flight * selection_weight + send_wait_ewma_us, in_flight)`
  - where `send_wait_ewma_us` is updated from `upstream_h2_send_lock_wait` per send attempt.
- Added low-cost observability:
  - `svc_tls_intercept_upstream_h2_selected_inflight_peak`
  - `svc_tls_intercept_upstream_h2_retry_total{cause=...}` on reconnect path.
- Added unit regression tests:
  - `upstream_h2_selection_score_prefers_lower_send_wait_at_same_inflight`
  - `upstream_h2_selection_score_prefers_lower_inflight_when_send_wait_equal`
- Build/deploy:
  - new `--release --features dpdk` binary deployed to firewall nodes `10.20.1.4/5/6` and `neuwerk.service` restarted.

### BJ) Post-deploy control run at 24k
- `T024`:
  - `cloud-tests/azure/http-perf-matrix-20260314T024-24k-adaptive-selector`
  - (`POOL_SHARDS=1`, `DETAILED_METRICS=0`, default selector weight `128`)
- Result:
  - fail by latency gate only, `error_rate=0`
  - median `p95/p99 ~112.4/319.9ms`
  - send-lock wait avg (repeat-1): `~0.125ms` (`915419` samples)
- Comparison vs prior baseline `T022` (`p99 ~314.9ms`):
  - no clear improvement from selector logic alone at this load tier.

### BK) Bench harness knob for selector weight + focused sweep
- Added runtime knob pass-through end-to-end:
  - `TLS_H2_SELECTION_INFLIGHT_WEIGHT`
  - wired through:
    - `cloud-tests/common/http-perf-run.sh`
    - `cloud-tests/common/http-perf-matrix.sh`
    - `cloud-tests/{azure,aws,gcp}/Makefile`
  - runtime tuning context now records `tls_h2_selection_inflight_weight`.
- Focused runs at `24k`, keep-alive, payload `1024`, `HTTP_REPEATS=1`:
  - `T025` (`weight=32`): `http-perf-matrix-20260314T025-24k-selectw32`
    - severe outlier fail (`error_rate ~1.64%`, `p99 ~7390ms`, effective ~`20.4k`).
    - k6 error signature was client-side `dial: i/o timeout`; firewall retry/error counters did not spike.
  - `T026` (`weight=8`): `http-perf-matrix-20260314T026-24k-selectw8`
    - latency-gate fail, `p99 ~325.1ms` (worse than baseline/control).
  - `T027` (`weight=32` repeat): `http-perf-matrix-20260314T027-24k-selectw32-repeat`
    - normal latency-gate fail, `p99 ~324.0ms` (no error-rate collapse reproduced).
  - `T028` (`weight=128` control): `http-perf-matrix-20260314T028-24k-selectw128-control`
    - latency-gate fail, `p99 ~317.1ms` (best in this mini-sweep, still above gate).
- Conclusion from sweep:
  - non-default selector weights did not produce a consistent p99 improvement at `24k`.
  - keep default `NEUWERK_TLS_H2_SELECTION_INFLIGHT_WEIGHT=128`; treat lower weights as experiment-only.
  - current bottleneck remains tail-latency in DPI/upstream-H2 send path, not a simple dispatch-weight miss.

### BL) Added max-streams tuning knob to harness
- Added pass-through for:
  - `TLS_H2_MAX_CONCURRENT_STREAMS` -> `NEUWERK_TLS_H2_MAX_CONCURRENT_STREAMS`
- Wired through:
  - `cloud-tests/common/http-perf-run.sh`
  - `cloud-tests/common/http-perf-matrix.sh`
  - `cloud-tests/{azure,aws,gcp}/Makefile`
- Runtime tuning context now captures:
  - `tls_h2_max_concurrent_streams`

### BM) `NEUWERK_TLS_H2_MAX_CONCURRENT_STREAMS` sweep (`24k`, keep-alive, payload `1024`)
- Control (`64`, selector weight `128`):
  - `T028`: `http-perf-matrix-20260314T028-24k-selectw128-control`
  - `p95/p99 ~113.6/317.1ms`, error `0`.
- Lower stream cap (`32`):
  - `T029`: `http-perf-matrix-20260314T029-24k-h2streams32`
  - worsened tails (`p95/p99 ~131.2/339.3ms`), slight error (`~1e-6`).
  - churn/queue indicators increased sharply (`connect_wait ~398k`, `conn_closed ~6544`).
- Higher stream cap (`96`):
  - `T030`: `http-perf-matrix-20260314T030-24k-h2streams96`
  - improved to `p95/p99 ~110.3/313.3ms`.
  - confirmation:
    - `T031`: `http-perf-matrix-20260314T031-24k-h2streams96-repeat2`
    - median `p95/p99 ~102.2/307.7ms` (stable across both repeats).
- Higher stream cap (`128`):
  - `T033`: `http-perf-matrix-20260314T033-24k-h2streams128`
  - `p95/p99 ~97.5/297.6ms` (single run).
  - confirmation:
    - `T034`: `http-perf-matrix-20260314T034-24k-h2streams128-repeat2`
    - median `p95/p99 ~90.2/292.9ms`, error `0`, effective RPS `~24005.7`.
- Key mechanism signal (64 -> 128):
  - `connect_wait` dropped roughly `~243k -> ~101-109k` per repeat.
  - `conn_closed` dropped roughly `~4324 -> ~2160-2240`.
  - `connect_raced` dropped roughly `~3183 -> ~1016-1103`.
- Interpretation:
  - the default stream cap (`64`) is conservative for this load profile and drives avoidable pool churn.
  - raising the cap to `128` gives the largest and most repeatable 24k tail-latency improvement found in this pass.

### BN) Lower-bound sanity with improved cap
- `T032` (`20k`, `max_streams=96`):
  - `http-perf-matrix-20260314T032-20k-h2streams96-sanity` *(run label retained from command tag)*
  - pass with `error=0`, `p95/p99 ~30.9/47.1ms`, effective `~20.0k RPS`.
- Interpretation:
  - no regression observed at the stable 20k operating point with higher stream cap.

### BO) Tuned keep-alive matrix with `max_streams=128`
- `T035`:
  - `cloud-tests/azure/http-perf-matrix-20260314T035-dpi-keepalive-max128`
  - settings:
    - `TLS_H2_MAX_CONCURRENT_STREAMS=128`
    - `TLS_H2_SELECTION_INFLIGHT_WEIGHT=128`
    - `TLS_H2_POOL_SHARDS=1`
    - `TLS_H2_DETAILED_METRICS=0`
  - scenario scope:
    - `tls_intercept_http_path`, `keep_alive`
    - payloads `1024`, `32768`
    - tiers `500,3000,20000,24000`
    - `HTTP_REPEATS=1`
- Result summary:
  - combo_count `8`, pass `5`, fail `3`, invalid `0`.
  - payload `1024`:
    - `500`: pass (`p99 ~41.7ms`)
    - `3000`: pass (`p99 ~41.7ms`)
    - `20000`: pass (`p99 ~68.7ms`)
    - `24000`: fail by latency gate only (`error=0`, `p95/p99 ~84.1/287.1ms`)
  - payload `32768`:
    - `500`: pass (`p99 ~6.1ms`)
    - `3000`: pass (`p99 ~8.7ms`)
    - `20000`: fail by error-rate gate (`effective ~5299 RPS`, `error_rate ~8.79%`, very high tail)
    - `24000`: fail by error-rate gate (`effective ~5439 RPS`, `error_rate ~10.78%`, very high tail)
- High-tier (`24k`, payload `1024`) metric snapshot:
  - `upstream_h2_send_lock_wait` avg `~0.159ms`
  - `pool conn_closed ~2240`
  - `pool connect_wait ~104860`
  - `pool connect_raced ~1093`
  - `pool hit ~911944`, `miss ~1142`
  - `upstream_h2_ready` and `upstream_response` failure counters remained `0`.
- Interpretation:
  - for the critical small-payload high-RPS case, `max_streams=128` is the strongest improvement observed so far (`24k p99` now consistently below `300ms` in repeated runs and `~287ms` in matrix).
  - large payload (`32768`) at very high tiers is a different bottleneck regime (data-volume/timeout dominated), not the same limiter as the small-payload DPI path.

## 2026-03-14 Scaling Experiment: D16 vs D4 vs D2 (3-node firewall cluster)

### BP) Experiment design and scope
- Objective: characterize scaling behavior for `http_l34_allow`, `https_l34_allow`, and `tls_intercept_http_path` across smaller firewall instance sizes.
- Fixed topology:
  - firewall VMSS count: `3`
  - consumer: `Standard_D8as_v5` with `32` source IPs (`10.20.3.4..35`)
  - upstream: `Standard_D4as_v5`
- Shapes tested (firewall only):
  - `Standard_D16as_v5` (baseline current shape)
  - `Standard_D4as_v5`
  - `Standard_D2as_v5`
- Matrix parameters (identical across shapes):
  - scenarios: `tls_intercept_http_path,http_l34_allow,https_l34_allow`
  - payload: `1024`
  - mode: `keep_alive`
  - targets: `6000,12000,18000`
  - repeats: `1`, ramp/steady: `10s/20s`
- CPU-aware runtime knobs:
  - D16: `DPDK_WORKERS=2`, `CONTROLPLANE_WORKER_THREADS=4`
  - D4: `DPDK_WORKERS=2`, `CONTROLPLANE_WORKER_THREADS=2`
  - D2: `DPDK_WORKERS=1`, `CONTROLPLANE_WORKER_THREADS=2`
  - all shapes: `TLS_H2_MAX_CONCURRENT_STREAMS=128`, `TLS_H2_POOL_SHARDS=1`, `TLS_H2_SELECTION_INFLIGHT_WEIGHT=128`.
- Artifacts:
  - root: `cloud-tests/azure/cloud-tests/azure/artifacts/scaling-http-https-dpi-20260314T075202Z/`
  - per shape: `<shape>/{throughput,http-matrix}`.

### BQ) Core results
- Raw throughput (`throughput/result.json`):
  - D16: `max_tcp ~11.856 Gbps`, `max_udp ~3.524 Gbps`
  - D4: `max_tcp ~11.844 Gbps`, `max_udp ~3.476 Gbps`
  - D2: `max_tcp ~11.849 Gbps`, `max_udp ~3.490 Gbps`
  - observation: raw throughput is effectively flat across firewall core counts in this setup.
- HTTP matrix summary:
  - D16: `combo_count=9`, `pass=8`, `fail=1`
  - D4: `combo_count=9`, `pass=8`, `fail=1`
  - D2: `combo_count=9`, `pass=8`, `fail=1`
  - shared fail point: `http_l34_allow@18000` (error-rate gate at D4/D2; D16 run artifact missing due harness/run interruption on that combo).
- Effective RPS (representative):
  - `tls_intercept_http_path@18000`:
    - D16 `~18003.35`
    - D4 `~18003.9`
    - D2 `~17967.25`
  - `https_l34_allow@18000`:
    - D16 `~16391.05`
    - D4 `~16360.7`
    - D2 `~16353.2`
  - `http_l34_allow@12000`:
    - D16 `~12038.2`
    - D4 `~12043.3`
    - D2 `~12075.6`

### BR) Scaling interpretation
- Across these tested loads, throughput is near-constant from D2 to D16 for HTTP/HTTPS/DPI keep-alive.
- Firewall CPU rises on smaller SKUs (as expected), but remains below saturation at tested high tiers:
  - D16 high-tier peaks roughly `~7-8%`
  - D4 high-tier peaks roughly `~28-30%`
  - D2 high-tier peaks roughly `~56-61%`
- Empirical scaling rule for this regime (fixed 3-node cluster, keep-alive, 1KB payload):
  - throughput is **not core-limited** in the tested range.
  - practical approximation: `RPS(protocol) ≈ constant (for 2..16 vCPU per firewall node)` under current traffic pattern.
- Operational implication:
  - vertical scaling firewall cores alone is low-yield for these paths at this load envelope.
  - to increase throughput meaningfully, prioritize removing non-CPU bottlenecks (generator/upstream constraints, serialization points, or queueing hotspots) before buying larger firewall SKUs.

## 2026-03-14 D8 Horizontal Scaling Investigation (TLS+DPI)

### BS) Bootstrap blocker and fix
- Initial scale-out attempts showed unhealthy new nodes with:
  - `unknown flag: --dns-target-ip` in `neuwerk.service` logs.
- Root cause:
  - binary drift + bootstrap behavior.
  - VM bootstrap exits early when `/var/lib/neuwerk/bootstrap.complete` exists, so blob path updates alone do not refresh `/usr/local/bin/neuwerk` on already-bootstrapped instances.
- Fix applied:
  - replaced VMSS resource to force fresh bootstraps and verified node command line included `--dns-target-ip`.
  - validated health for all nodes before load runs.

### BT) Experiment setup
- Firewall shape: `Standard_D8as_v5`.
- Consumer/upstream: `Standard_D8as_v5` / `Standard_D4as_v5`.
- Consumer source IPs: `32` (`10.20.3.4..35`).
- Scenario:
  - `tls_intercept_http_path`, `keep_alive`, payload `1024`, `HTTP_REPEATS=1`.
  - tiers: `24000`, `30000`.
- Baseline knobs:
  - `DPDK_WORKERS=2`, `CONTROLPLANE_WORKER_THREADS=4`
  - `TLS_H2_MAX_CONCURRENT_STREAMS=128`, `TLS_H2_POOL_SHARDS=1`, `TLS_H2_SELECTION_INFLIGHT_WEIGHT=128`
  - `DPDK_FORCE_SHARED_RX_DEMUX=0`, `DPDK_SHARED_RX_OWNER_ONLY=1`.
- Artifacts root:
  - `cloud-tests/azure/artifacts/hscale-d8-20260314T100219Z`

### BU) Horizontal baseline results (`n=1/2/3`)
- `n=1` (`n1-up4`):
  - `24k`: invalid (`generator_limited`), effective `~6633 RPS`, `p99 ~60000ms`.
  - `30k`: invalid (`generator_limited`), effective `~6939 RPS`, `p99 ~60000ms`.
- `n=2` (`n2-up4`):
  - `24k`: fail, effective `~13674 RPS`, `error ~6.75%`, `p99 ~20409ms`.
  - `30k`: fail, effective `~13437 RPS`, `error ~8.53%`, `p99 ~33964ms`.
- `n=3` (`n3-up4`):
  - `24k`: fail-by-latency, effective `~23935 RPS`, `error ~0.0031%`, `p99 ~363ms`.
  - `30k`: fail-by-latency, effective `~27655 RPS`, `error ~0.0109%`, `p99 ~1968ms`.

### BV) Bottleneck evidence (why scale-out looked bad before)
- Node traffic distribution is even at `n=2` and `n=3`:
  - `n=2`: RX split about `50.3% / 49.7%`, TLS accept split about `49.7% / 50.3%`.
  - `n=3`: RX split about `34.2% / 33.3% / 32.5%` (24k) and `34.0% / 33.1% / 32.9%` (30k).
- Therefore, the main issue is **not** hot-node or LB skew.
- Baseline thread-level evidence (`n3-up4@30k`):
  - `dataplane-runtime` dominates per node (`~64-72%` average of one core).
  - DPDK worker thread is near idle in baseline (`~0.0-0.1%`), consistent with Azure single-worker guard behavior in this mode.
- Interpretation:
  - limiting path is per-node service-lane execution (owner/runtime thread), not cross-node load distribution.
  - Horizontal scale does work (roughly `~6.6k -> ~13.7k -> ~23.9k` effective from 1->2->3 at 24k target), but headroom at 30k is constrained by per-node path latency/queueing.

### BW) Multiworker experiments (`n=3`, `30k`)
- Variant A (`n3-up4-mw4`):
  - `DPDK_ALLOW_AZURE_MULTIWORKER=1`, `DPDK_WORKERS=4`, `DPDK_FORCE_SHARED_RX_DEMUX=0`, `DPDK_SHARED_RX_OWNER_ONLY=1`.
  - Result: **worse** (`effective ~20937 RPS`, `error ~4.26%`, `p99 ~9759ms`).
  - Evidence: large reconnect churn (`h2 pool reconnect` in thousands to tens of thousands).
- Variant B (`n3-up4-mw4-demux1`):
  - same as above but `DPDK_FORCE_SHARED_RX_DEMUX=1`, `DPDK_SHARED_RX_OWNER_ONLY=0`.
  - Result: recovers substantially (`effective ~26433 RPS`, `error ~0.0128%`, `p99 ~797ms`), but still below baseline effective RPS.
  - Evidence: reconnect churn collapses (single digits), worker threads carry meaningful load (`~66-75%` avg per `dpdk-worker-*`).
- Conclusion:
  - multiworker can reduce tail compared with bad owner-only pairing, but current multiworker tuning does not beat baseline throughput at `30k` yet.
  - owner-only + multiworker is a pathological combination in this path (pool reconnect storm).

### BX) Current conclusion / next tuning targets
- Horizontal scaling is functional with D8 nodes; prior non-scaling symptoms were dominated by:
  - bootstrap/binary drift incidents and
  - per-node service-lane saturation at high tiers.
- Highest-yield next steps:
  - profile and reduce `dataplane-runtime` critical-section/serialization costs in TLS intercept path.
  - if pursuing multiworker on Azure, treat `shared demux` as mandatory baseline and retune around:
    - worker count (`2/3/4`),
    - owner-only routing disabled,
    - H2 pool reuse/reconnect behavior under worker fan-out.

## 2026-03-14 D4 Debug Rerun (n1/n2/n3) + Hotspot Verification

### BY) New debug observability added in harness
- `cloud-tests/common/http-perf-collect.sh`
  - added per-firewall-node pre/post raw captures:
    - `raw/<stage>.<ip>.ss-s.txt`
    - `raw/<stage>.<ip>.softnet_stat.txt`
    - `raw/<stage>.<ip>.nstat.txt`
    - `raw/<stage>.<ip>.ip-link-s.txt`
- `cloud-tests/common/http-perf-run.sh`
  - added `firewall-metrics-per-instance-delta.json`:
    - per-instance delta series and a focused imbalance ranking for TLS intercept/H2 pool/DPDK/flow/lock metrics.
  - added `firewall-network-diag-summary.json`:
    - per-instance `softnet` deltas, NIC packet/drop deltas, focused `nstat` deltas.

### BZ) Full rerun with debug artifacts
- Artifact root: `cloud-tests/azure/artifacts/hscale-d4-debug-20260314T132121Z`
- Firewall scale/shape:
  - `n1`: 1x `Standard_D4as_v5`
  - `n2`: 2x `Standard_D4as_v5`
  - `n3`: 3x `Standard_D4as_v5`
- Matrix summary:
  - `n1`: `pass=5 fail=1 invalid=3`
  - `n2`: `pass=4 fail=3 invalid=2`
  - `n3`: `pass=4 fail=3 invalid=2`
- HTTP/HTTPS:
  - HTTPS keep-alive passed through 18k target for all node-count runs.
  - HTTP had error-gate failures at 12k/18k on `n2/n3`; one `n2@18k` run produced no load summary (infra/tooling flake).
- TLS+DPI:
  - `n2@6000` and `n3@6000` delivered ~6k effective but failed latency gate due very high p99 tails.
  - `n2/n3@12000` and `@18000` were `generator_limited` with `insufficient_vus` and large timeout tails.

### CA) Primary bottleneck evidence from new per-node debug
- In problematic mixed matrix runs, client connection distribution was balanced, but DPI request-body processing was not.
  - Example (`n3`, DPI `rps=6000`):
    - `client_tls_accept` share: ~`33/33/34%` across nodes.
    - `h2_request_body_read` share: `7.0/1.5/91.5%`.
    - `h2 pool hit` share matched that skew.
- Same run showed heavy H2 pool churn:
  - `h2_request_body_read`: `368,599`
  - `upstream_h2_pool reconnect`: `31,363`
  - `upstream_h2_ready` errors: `172`
- Kernel/NIC pressure was not the first-order limiter at this tier:
  - `softnet` dropped deltas were `0`,
  - NIC RX/TX dropped deltas were `0`,
  - lock contention counters remained `0`.

### CB) Focused DPI-only verification (fast feedback)
- Artifact root: `cloud-tests/azure/artifacts/dpi-hotspot-repeats-20260314T143830Z`
- Scenario: DPI only, keep-alive, 1024B, `rps=6000`, `HTTP_REPEATS=3`.
- Result: all 3 repeats `pass`, ~`6000 RPS`, low latency tails.
- Per-node distribution in all repeats was near-even for:
  - `client_tls_accept`,
  - `h2_request_body_read`,
  - `h2 pool hit`.
- H2 reconnect churn collapsed to negligible:
  - `2`, `2`, `5` reconnects across repeats (vs `31,363` in mixed run sample).
- A/B check (HTTPS warmup then DPI):
  - warmup artifact: `cloud-tests/azure/artifacts/ab-warmup-https-20260314T144609Z`
  - post-warmup DPI artifact: `cloud-tests/azure/artifacts/ab-after-https-dpi-20260314T144859Z`
  - post-warmup DPI stayed healthy and balanced at `~6000 RPS` with near-zero reconnect churn.

### CC) Interpretation and current best hypothesis
- The key limiter for DPI failures is runtime instability in upstream H2 session readiness/reuse (reconnect churn + `upstream_h2_ready` failures), not raw CPU, softnet drops, or NIC drops at 6k.
- Data points indicate the issue is at least partly stateful/intermittent (mixed matrix can trigger severe churn; focused DPI reruns can be healthy immediately after).
- Firewall runtime config observed on all D4 nodes during reruns:
  - `NEUWERK_CONTROLPLANE_WORKER_THREADS=2`
  - `NEUWERK_TLS_H2_MAX_CONCURRENT_STREAMS=128`
  - `NEUWERK_TLS_H2_POOL_SHARDS=1`
  - `NEUWERK_TLS_H2_SELECTION_INFLIGHT_WEIGHT=128`
  - `NEUWERK_DPDK_WORKERS=2`
  - `NEUWERK_DPDK_FORCE_SHARED_RX_DEMUX=0`
  - `NEUWERK_DPDK_SHARED_RX_OWNER_ONLY=1`

## 2026-03-14 Runtime Fix Validation (H2 Eviction + Backoff + Cross-shard Probe)

### CD) Runtime changes deployed and binary identity verified
- Applied runtime fixes in `trafficd` TLS intercept path:
  - evict unhealthy upstream H2 clients on ready/send/response failure paths,
  - bounded reconnect backoff (`NEUWERK_TLS_H2_RECONNECT_BACKOFF_BASE_MS`, `...MAX_MS`),
  - cross-shard probe fallback before reconnecting.
- Deployed binary hash verified across all three firewall nodes:
  - local: `b43b988645fc2ef690f02b798eec950b6c90eefc47aa3cfc59d2d078d27e69fe`
  - remote (`10.20.1.4/5/6`): same hash on `/usr/local/bin/neuwerk`; `neuwerk.service` active on all nodes.

### CE) Focused DPI-only check after fix (`6k,12k`)
- Artifact root: `cloud-tests/azure/artifacts/http-perf-matrix-20260314T154652Z-dpi-fix-6k12k`
- Scenario: `tls_intercept_http_path`, keep-alive, `1024B`, `RPS=6000,12000`, `HTTP_REPEATS=1`.
- Matrix summary:
  - `6000`: `pass`, effective `6000.16 RPS`, error `~8.15e-06`, p99 `~43.32ms`.
  - `12000`: `pass`, effective `12000.31 RPS`, error `0`, p99 `~42.73ms`.
- Critical churn/error signals:
  - `svc_tls_intercept_upstream_h2_ready_errors_total`: `0` at both tiers.
  - `svc_tls_intercept_upstream_h2_pool_total{result="reconnect"}`: `0` at both tiers.
  - `h2_request_body_read` distribution remained balanced:
    - `6000`: `122072 / 122912 / 122936`
    - `12000`: `242988 / 247133 / 245407`.

### CF) Mixed-sequence check (HTTPS then DPI) after fix
- Artifact root: `cloud-tests/azure/artifacts/http-perf-matrix-20260314T154652Z-mixed-https-dpi-fix`
- Scenario order: `https_l34_allow` then `tls_intercept_http_path`; keep-alive, `1024B`, `RPS=12000`.
- Results:
  - `https_l34_allow@12000`: `fail` (`error_rate_gate`), effective `12037.93`, error `~3.71%`.
  - `tls_intercept_http_path@12000`: `pass`, effective `12000.56`, error `0`, p99 `~42.77ms`.
- DPI churn/error signals stayed clean in mixed run too:
  - `svc_tls_intercept_upstream_h2_ready_errors_total=0`,
  - `svc_tls_intercept_upstream_h2_pool_total{result="reconnect"}=0`,
  - balanced per-node `h2_request_body_read`: `244132 / 246537 / 244391`.

### CG) Current conclusion after fix validation
- The TLS+DPI path is materially stabilized under the tested conditions (`6k/12k`, including mixed-sequence transition), with reconnect storms and upstream-ready failures removed in these runs.
- Remaining unrelated failure in this validation set is the standalone `https_l34_allow@12000` error-rate gate, which should be investigated separately from DPI churn mechanics.

## 2026-03-14 High-Tier DPI Re-check (Binary A/B + Apples-to-apples)

### CH) Environment and deployment state used for this check
- Azure shape at test time:
  - firewall VMSS: `3 x Standard_D4as_v5`
  - consumer VM: `Standard_D8as_v5`
  - upstream VM: `Standard_D4as_v5`
- Verified and used hashes:
  - previous known-good binary: `c14d9a07229572640f5a5a5c6a58ff74a54bf138bc4dce055b97353f87acb7ad`
  - local rebuilt runtime binary: `fe0e8971c5c4c11af3ac41030ac59c92e254e5ee3cc2cc02bad9ee4664c318f9`
- Release build compatibility check:
  - binary links to `librte_*.so.24` (Azure image-compatible).

### CI) Runs executed
- New binary, quick focus (inherited runtime + detailed metrics):
  - artifact: `cloud-tests/azure/http-perf-matrix-20260314T-investigate-newbin`
  - `20k`: pass, p99 `~104.38ms`
  - `24k`: fail-by-latency, p99 `~491.36ms`
- New binary, apples-to-apples vs earlier baseline:
  - artifact: `cloud-tests/azure/http-perf-matrix-20260314T-investigate-newbin-apples`
  - knobs: `RAMP_SECONDS=15`, `STEADY_SECONDS=30`, `CONTROLPLANE_WORKER_THREADS=4`, `TLS_H2_POOL_SHARDS=1`, `TLS_H2_MAX_CONCURRENT_STREAMS=128`, `TLS_H2_SELECTION_INFLIGHT_WEIGHT=128`, `TLS_H2_DETAILED_METRICS=0`
  - `20k`: pass, p99 `~91.46ms`
  - `24k`: fail-by-latency, p99 `~373.98ms`
- Rollback binary, same apples-to-apples knobs:
  - artifact: `cloud-tests/azure/http-perf-matrix-20260314T-investigate-rollback-apples`
  - `20k`: pass, p99 `~101.63ms`
  - `24k`: fail-by-latency, p99 `~764.69ms`

### CJ) Key bottleneck evidence from new-binary apples run
- Request distribution remained balanced across firewall nodes (no hot-node skew in `client_tls_accept` / `h2_request_body_read`).
- `24k` versus `20k` shows sharp queue/lock amplification while reconnect/error counters stay at zero:
  - `connect_wait/read`: `~0.0587 -> ~0.1208` (about `2.06x`)
  - `upstream_h2_send_lock_wait` average: `~0.132ms -> ~0.288ms` (about `2.19x`)
  - `upstream_h2_pool_lock_wait` average: `~0.0107ms -> ~0.0316ms` (about `2.96x`)
  - `svc_tls_intercept_upstream_h2_pool_total{result="reconnect"} = 0`
  - `svc_tls_intercept_upstream_h2_ready_errors_total{kind="other"} = 0`
  - `svc_tls_intercept_upstream_response_errors_total{kind="other"} = 0`

### CK) Interpretation update
- At current `3 x D4` topology and this workload shape, the practical DPI keep-alive knee is still around `~20k RPS` and `24k` remains latency-bound.
- Current failing mode at high tier is consistent with upstream H2 pool/send-path queueing/serialization, not reconnect storms, not upstream response failures, and not node-distribution imbalance.
- Rollback A/B did not outperform in this rerun window, indicating non-trivial run-to-run variance at the edge; however, the new lock/queue metrics provide direct evidence of the active limiting mechanism when `24k` fails.

### CL) Targeted knob check: `TLS_H2_MAX_REQUESTS_PER_CONNECTION=4000`
- Artifact: `cloud-tests/azure/http-perf-matrix-20260314T-investigate-maxreq4000`
- Scenario: DPI keep-alive `1024B`, `rps=24000`, same apples-to-apples knobs except `TLS_H2_MAX_REQUESTS_PER_CONNECTION=4000`.
- Result:
  - status: still `fail` by latency,
  - effective: `~24006.17 RPS`,
  - p95: `~172.18ms`,
  - p99: `~399.27ms`.
- Relative to immediate rollback apples run at `24k` with default request budget:
  - p95 improved (`~314.28ms -> ~172.18ms`),
  - p99 improved (`~764.69ms -> ~399.27ms`),
  - pool reconnects dropped (`25 -> 3` in these two runs),
  - but latency gate still fails.
- Takeaway:
  - increasing per-connection request budget can reduce churn and tail latency pressure, but it is not sufficient alone to clear high-tier latency failure.

## 2026-03-14 Send-path Lock Optimization Attempt (`StdMutex` sender clone lock)

### CM) Code change
- Updated `UpstreamH2Client.send_request` lock type from async mutex to synchronous mutex for the clone-only critical section:
  - `src/controlplane/trafficd.rs`
  - `src/controlplane/trafficd/intercept_runtime.rs`
- Rationale:
  - this lock protects a very short non-async operation (`clone`), so async mutex scheduling overhead can be avoided.
- Safety checks:
  - targeted tests passed:
    - `cargo test -p firewall --features dpdk --lib upstream_h2_`
    - `cargo test -p firewall --features dpdk --lib tls_intercept_runtime_h2_`

### CN) Fast 24k validation with new binary
- New binary hash deployed: `ba98adf7bf910e68b58ed739eccfe24ca67773537143c03e0b7043501a6924de`
- Base run (same knobs as apples run, `H2_STREAMS=128`):
  - artifact: `cloud-tests/azure/http-perf-matrix-20260314T-investigate-stdmutex-24k`
  - result: `fail`, effective `~24009.13`, p95 `~275.28ms`, p99 `~710.71ms`
  - interpretation: sender-lock wait dropped strongly, but overall latency worsened due increased pool-lock/connect-wait pressure.

### CO) Follow-up tuning with same binary (`H2_STREAMS=256`)
- Artifact: `cloud-tests/azure/http-perf-matrix-20260314T-investigate-stdmutex-24k-h2s256`
- Result:
  - `fail`, effective `~24006.40`, p95 `~139.31ms`, p99 `~357.43ms`, error `0`.
- Compared with prior apples control (`...investigate-newbin-apples`, `H2_STREAMS=128`):
  - p95 improved (`~220.45ms -> ~139.31ms`),
  - p99 improved slightly (`~373.98ms -> ~357.43ms`),
  - still fails latency gate.

### CP) `H2_STREAMS=256` + `MAX_REQUESTS_PER_CONNECTION=4000`
- Artifact: `cloud-tests/azure/http-perf-matrix-20260314T-investigate-stdmutex-24k-h2s256-maxreq4000`
- Result:
  - `fail`, effective `~24005.57`, p95 `~168.46ms`, p99 `~382.77ms`, error `0`.
- In this run, increasing max requests per connection on top of `H2_STREAMS=256` regressed tails versus `H2_STREAMS=256` alone.

### CQ) Current takeaway from this iteration
- The sender-lock optimization is not a standalone win at `H2_STREAMS=128` in this workload.
- Best observed combination in this mini-cycle is:
  - new binary + `H2_STREAMS=256` (still fail, but best p95/p99 among these immediate 24k reruns).
- Remaining limiter is still high-tier queueing/serialization (now dominated by pool-lock/connect-wait behavior once sender-lock wait is reduced).

## 2026-03-15 Observability Upgrade For Scaling Diagnostics (P0)

### CR) `http-perf-run` diagnostics enrichment
- Extended per-run `result.json` generation to include:
  - per-consumer offered/achieved/error (`results.per_consumer`),
  - thread hotspot summary (`diagnostics.thread_hotspot`),
  - per-firewall TLS accept counts (`diagnostics.tls_client_accept_by_firewall_instance`).
- This makes each run self-describing for generator pressure, load-distribution, and hot-thread analysis.

### CS) `http-perf-matrix` aggregation enrichment
- Extended `combo-result.json` and `matrix-summary.json` to carry:
  - `classification` and `status_reason_counts`,
  - generator-limit rollups (`generator_limited_runs`, `generator_limit_counts`, `generator_limited_combo_count`),
  - per-consumer median offered/achieved/error summaries,
  - median hot-thread indicators (`max_thread_cpu_pct_max`, `max_dpdk_worker_cpu_imbalance_ratio`),
  - median per-firewall `client_tls_accept` counts.
- Goal: avoid false scaling conclusions from generator-limited or highly imbalanced runs.

### CT) `scaling-benchmark` summary quality fields
- Extended shape extraction and `summary.{json,csv,md}` with HTTPS/DPI lane quality counters:
  - invalid combos and generator-limited combo counts for the handshake lanes.
- This adds explicit data-quality signals next to throughput/HS numbers.

## 2026-03-16 CPS Investigation Follow-up (Aggressive Mode)

### CU) Critical deploy issue found during CPS rerun
- Initial `1x2` rerun failed before traffic due firewall process crash:
  - `dpdk preinit failed error=dpdk io backend not available (build with --features dpdk and install DPDK)`.
- Cause: deployed `/usr/local/bin/neuwerk` binary was not a DPDK-enabled build.
- Fix applied:
  - rebuilt with `make build.release` (`--all-features`),
  - redeployed binary to firewall nodes,
  - verified `/health=200` and `neuwerk.service=active`.

### CV) CPS observability validation with aggressive mode
- Since `dp_flow_opens_total` is disabled in aggressive mode, CPS interpretation now uses host TCP counters:
  - consumer `Tcp.ActiveOpens` delta/CPS,
  - upstream `Tcp.PassiveOpens` delta/CPS (primary),
  - upstream `TcpExt.ListenDrops/ListenOverflows` deltas.
- Observed behavior in reruns:
  - firewall CPS counter remained `0.0` as expected,
  - upstream passive-open CPS tracked client CPS closely,
  - listen drops remained `0` in these runs.

### CW) Focused CPS reruns (Azure, aggressive mode)
- Artifacts:
  - `cloud-tests/azure/artifacts/cps-validate-1x2-rerun-20260316T082301Z`
  - `cloud-tests/azure/artifacts/cps-validate-3x2-rerun-20260316T082922Z`
  - `cloud-tests/azure/artifacts/cps-validate-3x2-highworkers-20260316T083400Z`
- Quick results:
  - `1x2` max observed CPS:
    - client: `~7378`
    - upstream passive opens: `~7391`
  - `3x2` max observed CPS (workers up to 128):
    - client: `~13586`
    - upstream passive opens: `~13602`
  - `3x2` high-worker check (128/256/512):
    - peak at workers `256`: client `~13918`, upstream passive opens `~13930`.

### CX) Comparison vs prior aggressive-focused baseline
- Previous baseline artifacts (`scaling-benchmark-aggressive-focused-20260316T051733Z`) showed:
  - `1x2` client CPS `~4262`
  - `3x2` client CPS `~3640` (non-scaling / regression pattern).
- After sink+observability fixes and correct DPDK binary deployment:
  - `1x2`: `~7378` (about `+73%` vs baseline),
  - `3x2`: `~13586` (about `+273%` vs baseline 3x2),
  - horizontal behavior improved materially (`3x2` now ~`1.84x` `1x2` on this harness).

### CY) Current interpretation
- The previously low/flat CPS signal was primarily setup/measurement-driven, not a clean firewall dataplane ceiling:
  - invalid/non-DPDK deployment masked runs,
  - upstream acceptor implementation and missing host-side CPS counters obscured true behavior.
- Remaining ceiling in this quick setup is likely load-generator-side/harness-side (single consumer VM/driver model) before full firewall saturation:
  - firewall CPU stayed around low/mid-50% on max `3x2` run,
  - upstream CPU stayed low, no listen drops.

## 2026-03-16 Test Hardening Before Next Full Rerun

### CZ) Guardrails implemented
- Added strict firewall preflight in scaling benchmark:
  - verifies node count, `/health=200`, `neuwerk.service=active`, and deployed binary md5 equals `NEUWERK_BINARY_PATH`.
- Added CPS quality gate enforcement:
  - no generator-limited signatures,
  - client success ratio must meet threshold,
  - upstream `ListenDrops`/`ListenOverflows` deltas must stay within thresholds.
- Added sanity stage ahead of full matrix:
  - `RUN_SANITY_PRECHECK=1` default,
  - optional `ONLY_SANITY_PRECHECK=1` for quick drift check without full run.
- Standardized CPS defaults for comparable matrix runs:
  - workers `64,128,256,512`,
  - run seconds `20`,
  - repeats `3`.

### DA) Sanity precheck validation
- Executed `ONLY_SANITY_PRECHECK=1` on shape `2x3` with current infra.
- Outcome: sanity precheck passed end-to-end including strict preflight and CPS quality gate.
- CPS sanity result snapshot:
  - client `~12719.5 CPS`,
  - upstream passive opens `~12772.4 CPS`,
  - quality gate `pass=true`, generator-limited runs `0`.

## 2026-03-17 CPS Investigation (TRex ASTF `target_host`, Full TCP Handshake)

### DB) Scope and fixed baseline
- Goal for this phase:
  - improve completed full TCP-handshake CPS through the firewall dataplane,
  - not local-generator CPS.
- Infra under test:
  - firewall `3 x Standard_D4as_v5`
  - consumer `1 x Standard_D4as_v5`
  - upstream `1 x Standard_D2as_v5`
- Common load command shape for all focused reruns:
  - `make -C cloud-tests/azure cps.matrix.trex.astf WORKERS_LIST=64,96,128 RUN_SECONDS=6 WARMUP_SECONDS=2 REPEATS=1 TARGET_PORT=9000 CPS_TREX_ASTF_SERVER_IP_MODE=target_host CPS_TREX_ASTF_CPS_PER_WORKER=500 CPS_TREX_ASTF_MAX_CPS=400000`
- Fixed baseline artifact after deploying the no-SNAT handshake observability fix:
  - `cloud-tests/azure/artifacts/cps-matrix-20260317T-baseline2-retaless`

### DC) Observability added for CPS path
- Added per-worker handshake counters:
  - `dp_tcp_handshake_events_total{worker,event}` with `event in {syn_in,syn_out,synack_in,synack_out,completed}`
  - dataplane wiring in:
    - `src/dataplane/engine.rs`
    - `src/dataplane/engine/packet_path.rs`
    - `src/dataplane/engine/no_snat.rs`
    - `src/dataplane/engine/common.rs`
    - `src/dataplane/flow.rs`
- Added per-worker handshake drop counters:
  - `dp_tcp_handshake_drops_total{worker,phase,reason}`
  - reasons now include handshake-path misses such as `flow_missing`, `policy_deny`, `service_not_ready`, plus SNAT rewrite/allocation failures on SNAT path.
- Added per-worker / per-shard state-lock wait and hold metrics:
  - `dp_state_lock_wait_seconds_worker`
  - `dp_state_lock_wait_seconds_shard`
  - `dp_state_lock_hold_seconds_worker`
  - `dp_state_lock_hold_seconds_shard`
  - instrumentation in:
    - `src/runtime/dpdk/run.rs`
    - `src/controlplane/metrics.rs`
    - `src/controlplane/metrics/construct.rs`
    - `src/controlplane/metrics/methods.rs`
- Added queue / utilization surfaces used in this investigation:
  - `dpdk_rx_packets_queue_total`
  - `dpdk_rx_bytes_queue_total`
  - `dpdk_tx_packets_queue_total`
  - `dpdk_tx_bytes_queue_total`
  - `dpdk_flow_steer_queue_utilization_ratio`
  - `dpdk_service_lane_forward_queue_utilization_ratio`
- Added CPS harness/runtime override passthrough for focused DPDK tuning:
  - `DPDK_LOCKLESS_QPW`
  - `DPDK_RX_RING_SIZE`
  - `DPDK_TX_RING_SIZE`
  - `DPDK_MBUF_POOL_SIZE`
  - `DPDK_HOUSEKEEPING_INTERVAL_PACKETS`
  - `DPDK_HOUSEKEEPING_INTERVAL_US`
  - files:
    - `cloud-tests/common/lib.sh`
    - `cloud-tests/common/run-cps-matrix.sh`
    - `cloud-tests/azure/scripts/cps-matrix.sh`
    - `cloud-tests/azure/Makefile`

### DD) Critical datapath finding before tuning
- The current CPS path is **not** using shared-RX demux / shared-IO:
  - `dpdk_shared_io_lock_contended_total=0`
  - `dpdk_flow_steer_dispatch_packets_total=0`
  - `dpdk_service_lane_forward_packets_total=0`
  - direct hardware queue counters are active via `dpdk_rx_packets_queue_total`.
- So shared-RX-owner handling is not the active limiter on this path.

### DE) Worker/core imbalance finding
- The firewall cluster is running mixed worker widths in queue-per-worker mode:
  - `10.20.1.4`: workers `0,1,2`
  - `10.20.1.5`: workers `0,1,2`
  - `10.20.1.6`: workers `0,1`
- At baseline `w64`, per-node total load is similar, but the 2-worker node carries much heavier per-worker load:
  - `10.20.1.4` RX queues: `74883 / 74869 / 74431`
  - `10.20.1.5` RX queues: `75908 / 75406 / 75608`
  - `10.20.1.6` RX queues: `112752 / 113545`
- Baseline `w64` completed handshakes per worker show the same imbalance:
  - `10.20.1.4`: `14835 / 14919 / 14880`
  - `10.20.1.5`: `14839 / 14717 / 14642`
  - `10.20.1.6`: `22236 / 22322`
- Baseline `w64` state-lock contention per worker is also highest on the 2-worker node:
  - `10.20.1.4`: `43967 / 53268 / 51533`
  - `10.20.1.5`: `43255 / 52083 / 50023`
  - `10.20.1.6`: `59437 / 65443`
- Firewall CPU stayed pinned on the same node in every rerun:
  - baseline `w64`: `10.20.1.4=75.08%`, `10.20.1.5=75.06%`, `10.20.1.6=100.00%`
  - baseline `w96`: `74.71% / 74.74% / 99.70%`
  - baseline `w128`: `74.86% / 74.84% / 99.73%`
- Conclusion from these counters:
  - the current limiter is not aggregate cluster load,
  - it is one firewall node with only 2 active workers saturating before the other two nodes.

### DF) Explicit handshake-drop finding
- The completion gap is mostly **not** explicit firewall drop logic.
- Aggregate handshake drops remained tiny in all focused runs:
  - baseline: `19 / 3 / 0` at `w64 / w96 / w128`
  - `workers=2`: `10 / 2 / 7`
  - `workers=2 + lockless`: `7 / 0 / 0`
  - `lockless-auto`: `5 / 1 / 0`
- Dominant explicit drop reason observed when present was `phase=synack reason=flow_missing`, but counts were too small to explain the CPS collapse.

### DG) Focused A/B commands
- Consumer pre-clean used before reruns:
```bash
bash -lc 'set -euo pipefail; source cloud-tests/common/lib.sh; \
JUMPBOX_IP=$(cd cloud-tests/azure/terraform && terraform output -raw jumpbox_public_ip); \
FIRST_CONSUMER=$(cd cloud-tests/azure/terraform && terraform output -json consumer_private_ips | jq -r ".[0]"); \
KEY_PATH=cloud-tests/.secrets/ssh/azure_e2e; \
ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$FIRST_CONSUMER" \
  "sudo killall -9 _t-rex-64 t-rex-64 2>/dev/null || true; rm -f /tmp/cps_trex_astf_* /tmp/trex_cfg_astf_*.yaml; true"'
```
- Baseline reference:
```bash
make -C cloud-tests/azure cps.matrix.trex.astf \
  ARTIFACT_DIR=artifacts/cps-matrix-20260317T-baseline2-retaless \
  WORKERS_LIST=64,96,128 RUN_SECONDS=6 WARMUP_SECONDS=2 REPEATS=1 TARGET_PORT=9000 \
  CPS_TREX_ASTF_SERVER_IP_MODE=target_host \
  CPS_TREX_ASTF_CPS_PER_WORKER=500 \
  CPS_TREX_ASTF_MAX_CPS=400000
```
- Force 2 workers on all firewall nodes:
```bash
make -C cloud-tests/azure cps.matrix.trex.astf \
  ARTIFACT_DIR=artifacts/cps-matrix-20260317T-workers2 \
  WORKERS_LIST=64,96,128 RUN_SECONDS=6 WARMUP_SECONDS=2 REPEATS=1 TARGET_PORT=9000 \
  DPDK_WORKERS=2 \
  CPS_TREX_ASTF_SERVER_IP_MODE=target_host \
  CPS_TREX_ASTF_CPS_PER_WORKER=500 \
  CPS_TREX_ASTF_MAX_CPS=400000
```
- Force 2 workers and enable lockless queue-per-worker:
```bash
make -C cloud-tests/azure cps.matrix.trex.astf \
  ARTIFACT_DIR=artifacts/cps-matrix-20260317T-workers2-lockless \
  WORKERS_LIST=64,96,128 RUN_SECONDS=6 WARMUP_SECONDS=2 REPEATS=1 TARGET_PORT=9000 \
  DPDK_WORKERS=2 \
  DPDK_LOCKLESS_QPW=1 \
  CPS_TREX_ASTF_SERVER_IP_MODE=target_host \
  CPS_TREX_ASTF_CPS_PER_WORKER=500 \
  CPS_TREX_ASTF_MAX_CPS=400000
```
- Enable lockless queue-per-worker on the baseline worker plan:
```bash
make -C cloud-tests/azure cps.matrix.trex.astf \
  ARTIFACT_DIR=artifacts/cps-matrix-20260317T-lockless-auto \
  WORKERS_LIST=64,96,128 RUN_SECONDS=6 WARMUP_SECONDS=2 REPEATS=1 TARGET_PORT=9000 \
  DPDK_LOCKLESS_QPW=1 \
  CPS_TREX_ASTF_SERVER_IP_MODE=target_host \
  CPS_TREX_ASTF_CPS_PER_WORKER=500 \
  CPS_TREX_ASTF_MAX_CPS=400000
```

### DH) Result table (completed CPS)
| Config | Artifact | w64 CPS | w96 CPS | w128 CPS | Notes |
| --- | --- | ---: | ---: | ---: | --- |
| baseline (`retaless` QPW) | `cloud-tests/azure/artifacts/cps-matrix-20260317T-baseline2-retaless` | `12150.34` | `9668.61` | `8793.87` | best overall tested configuration |
| `DPDK_WORKERS=2` | `cloud-tests/azure/artifacts/cps-matrix-20260317T-workers2` | `12018.71` | `9403.50` | `8986.22` | slightly better only at `w128` |
| `DPDK_WORKERS=2` + `DPDK_LOCKLESS_QPW=1` | `cloud-tests/azure/artifacts/cps-matrix-20260317T-workers2-lockless` | `12053.73` | `9546.65` | `8779.60` | removes lock contention, no overall CPS win |
| `DPDK_LOCKLESS_QPW=1` (auto workers) | `cloud-tests/azure/artifacts/cps-matrix-20260317T-lockless-auto` | `11251.15` | `9458.89` | `8730.45` | clear regression vs baseline |

### DI) Lock / retry / flow-state comparison
- Baseline aggregate lock contention was real but moderate:
  - `dp_state_lock_contended_total`: `419009 / 382296 / 371047`
  - `dp_state_lock_wait_seconds_sum`: `2.961 / 2.785 / 2.630`
- `DPDK_LOCKLESS_QPW=1` removed those counters completely:
  - `dp_state_lock_contended_total=0`
  - `dp_state_lock_wait_seconds_sum=0`
- But completed CPS did **not** improve:
  - `workers2 + lockless` vs baseline:
    - `w64`: `-0.80%`
    - `w96`: `-1.26%`
    - `w128`: `-0.16%`
  - `lockless-auto` vs baseline:
    - `w64`: `-7.40%`
    - `w96`: `-2.17%`
    - `w128`: `-0.72%`
- SYN retransmit timeouts remained high and tracked the CPS collapse more closely than lock wait:
  - baseline `tcps_rexmttimeo_syn`: `484924 / 931625 / 1176654`
  - `workers2 + lockless`: `487448 / 931912 / 1178322`
  - `lockless-auto`: `497140 / 934621 / 1174211`
- Interpretation:
  - flow-state lock contention exists,
  - but it is secondary,
  - the bottleneck is reached first via node/worker saturation and handshake retry pressure.

### DJ) Candidate evaluation
- Worker/core pinning strategy:
  - tested indirectly via `DPDK_WORKERS=2`.
  - Result: not a general win.
  - It helped only slightly at the highest overload point and hurt `w64/w96`.
- Shared-RX demux / owner handling:
  - not relevant on this CPS path today.
  - All focused runs stayed in queue-per-worker mode with zero shared-IO contention and zero flow-steer dispatch.
- Housekeeping cadence:
  - not promoted to first-class A/B in this phase.
  - Rationale: no queue-depth growth, no shared-IO pressure, and no drop counters pointing to housekeeping starvation on this path.
- Queue / RX-TX descriptor / mempool sizing:
  - not promoted to first-class A/B in this phase.
  - Rationale: `dpdk_rx_dropped_total=0`, `dpdk_tx_dropped_total=0`, and no queue utilization metric showed a descriptor shortage signature.
- Flow-state / shard strategy:
  - tested via `DPDK_LOCKLESS_QPW=1`.
  - Result: zero lock wait/hold overhead, but no completed-CPS gain.
  - This falsifies lock contention as the primary limiter for the current Azure CPS path.
- `DPDK_PIN_STATE_SHARD_GUARD` was left for later because lockless QPW already showed that removing state-lock cost does not recover CPS here.

### DK) Current limiting component and best tested change
- **Current limiting component:** one firewall node (`10.20.1.6`) running only 2 active workers in queue-per-worker mode and saturating at `~100%` CPU, while the other two nodes remain around `~75%`.
- Best tested configuration for overall completed CPS remains the fixed baseline:
  - `NEUWERK_DPDK_ALLOW_RETALESS_MULTI_QUEUE=1`
  - default auto worker plan (`3 / 3 / 2` observed)
- Best narrow overload-only tweak:
  - `DPDK_WORKERS=2` gives a small `w128` gain (`8986.22` vs `8793.87`, about `+2.2%`),
  - but it regresses the lower offered-load points, so it is not the general recommendation.

### DL) Expected next gain
- Highest-value next step is **not** more lock work.
- Highest-value next gain is to remove the mixed-capacity node condition:
  - determine why `10.20.1.6` exposes only 2 usable CPUs/workers on a `Standard_D4as_v5`,
  - or replace/rebuild the node until all three firewall nodes run the same worker width.
- Expected gain from fixing that asymmetry:
  - roughly the missing fraction of cluster worker capacity, on the order of `~10-20%` completed CPS in this setup, before additional flow-state tuning becomes first-order again.
- Secondary next step after node uniformity:
  - raise consumer source-IP headroom above the current `8` source IPs so follow-up reruns do not hit harness-side port/source reuse pressure first.

### DM) Fresh release build, all-D4 replacement, harness fix, and clean rerun
- Fresh release binary built locally:
  - command: `make build.release`
  - binary: `target/release/neuwerk`
  - md5: `7670a4eb004a5fcf5b60a139f19c3eaf`
- Uploaded the fresh binary through Terraform without changing policy:
  - command:
    ```bash
    terraform -chdir=cloud-tests/azure/terraform apply -auto-approve \
      -var neuwerk_vmss_size=Standard_D4as_v5 \
      -var neuwerk_instance_count=3 \
      -var neuwerk_dpdk_workers=0 \
      -var consumer_count=1 \
      -var consumer_vm_size=Standard_D4as_v5 \
      -var upstream_vm_size=Standard_D2as_v5 \
      -var consumer_secondary_private_ip_count=7 \
      -var consumer_trex_dual_nic_enabled=true \
      -var neuwerk_binary_path=/home/moritz/dev/neuwerk-rs/firewall/target/release/neuwerk
    ```
- Verified the live problem was a stale firewall VM, not the VMSS model:
  - before replacement:
    - `neuwerk-e2e-5b2hop-fw_125f9358  Standard_D2as_v5`
    - `neuwerk-e2e-5b2hop-fw_9dea9744  Standard_D4as_v5`
    - `neuwerk-e2e-5b2hop-fw_a5721168  Standard_D4as_v5`
- Replaced the stale instance with a manual surge/delete rollout and verified all live firewall nodes are true 4-vCPU D4s:
  - after replacement:
    - `neuwerk-e2e-5b2hop-fw_6575d249  Standard_D4as_v5`
    - `neuwerk-e2e-5b2hop-fw_9dea9744  Standard_D4as_v5`
    - `neuwerk-e2e-5b2hop-fw_a5721168  Standard_D4as_v5`
  - live management IPs:
    - `10.20.1.4`
    - `10.20.1.5`
    - `10.20.1.7`
- Verified all three live firewalls run the same binary and effective env:
  - `md5sum /usr/local/bin/neuwerk` -> `7670a4eb004a5fcf5b60a139f19c3eaf`
  - `nproc --all` -> `4`
  - `systemctl show neuwerk.service -p Environment --value` includes:
    - `NEUWERK_DPDK_ALLOW_AZURE_MULTIWORKER=1`
    - `NEUWERK_DPDK_ALLOW_RETALESS_MULTI_QUEUE=1`
    - `NEUWERK_DPDK_PERF_MODE=aggressive`
- During the first rerun, the benchmark harness rewrote `95-benchmark-dpdk.conf` and accidentally dropped `NEUWERK_DPDK_ALLOW_RETALESS_MULTI_QUEUE=1`.
  - effect:
    - two firewalls stayed in `QueuePerWorker`
    - the fresh node fell back to `SharedRxDemux`
    - aggregate metrics became contaminated with nonzero `dpdk_shared_io_lock_contended_total` and `dpdk_flow_steer_dispatch_packets_total`
  - contaminated artifact:
    - `cloud-tests/azure/artifacts/cps-matrix-20260317T-rebuilt-d4all`
- Fixed the harness so CPS runs now preserve and verify `NEUWERK_DPDK_ALLOW_RETALESS_MULTI_QUEUE`:
  - code:
    - `cloud-tests/common/lib.sh`
    - `cloud-tests/common/run-cps-matrix.sh`
    - `cloud-tests/azure/scripts/cps-matrix.sh`
    - `cloud-tests/azure/Makefile`
- Reapplied the runtime override and verified all three nodes restarted in pure queue-per-worker mode:
  - log signature on all three nodes:
    - `dpdk continuing without explicit reta override ...`
    - `dpdk starting worker threads worker_count=3 mode=QueuePerWorker`
- Clean rerun command:
  ```bash
  make -C cloud-tests/azure cps.matrix.trex.astf \
    ARTIFACT_DIR=artifacts/cps-matrix-20260317T-rebuilt-d4all-retaless \
    WORKERS_LIST=64,96,128 \
    RUN_SECONDS=6 \
    WARMUP_SECONDS=2 \
    REPEATS=1 \
    TARGET_PORT=9000 \
    CPS_TREX_ASTF_SERVER_IP_MODE=target_host \
    CPS_TREX_ASTF_CPS_PER_WORKER=500 \
    CPS_TREX_ASTF_MAX_CPS=400000 \
    DPDK_ALLOW_RETALESS_MULTI_QUEUE=1
  ```
- Clean rerun artifact:
  - `cloud-tests/azure/artifacts/cps-matrix-20260317T-rebuilt-d4all-retaless`

| run | artifact | w64 completed CPS | w96 completed CPS | w128 completed CPS | notes |
| --- | --- | ---: | ---: | ---: | --- |
| original clean baseline | `cloud-tests/azure/artifacts/cps-matrix-20260317T-baseline2-retaless` | `11590.09` | `9669.55` | `8774.43` | clean `QueuePerWorker`, but mixed live node sizes (`D4/D4/D2`) |
| rebuilt cluster, contaminated | `cloud-tests/azure/artifacts/cps-matrix-20260317T-rebuilt-d4all` | `12324.32` | `9658.97` | `9014.19` | invalid for comparison; mixed `QueuePerWorker` + `SharedRxDemux` |
| rebuilt cluster, clean | `cloud-tests/azure/artifacts/cps-matrix-20260317T-rebuilt-d4all-retaless` | `11655.93` | `9722.56` | `8931.26` | valid all-D4 same-binary rerun |

- Clean before/after vs original clean baseline:
  - `w64`: `+65.83 CPS` (`+0.57%`)
  - `w96`: `+53.01 CPS` (`+0.55%`)
  - `w128`: `+156.83 CPS` (`+1.79%`)
- The clean rerun removed the contamination completely:
  - `dpdk_shared_io_lock_contended_total=0` at `w64/w96/w128`
  - `dpdk_flow_steer_dispatch_packets_total=0` at `w64/w96/w128`
- Firewall load is now evenly balanced across the three live nodes:
  - `w96` per-node flow opens:
    - `10.20.1.4=63295`
    - `10.20.1.5=62366`
    - `10.20.1.7=61666`
  - `w128` per-node flow opens:
    - `10.20.1.4=54306`
    - `10.20.1.5=53434`
    - `10.20.1.7=53822`
- Consumer side still shows only `8` source IPs in the live rerun and the harness warns accordingly.
  - The clean rerun context confirms:
    - `consumer_source_ip_count_unique_all=8`
    - `runtime_overrides_requested.dpdk_allow_retaless_multi_queue=1`

### DN) Updated conclusion after the all-D4 clean rerun
- Replacing the stale `D2` firewall and ensuring the same binary on all three firewalls **did fix** the worker imbalance and removed the hot-node asymmetry.
- It did **not** unlock the expected `10-20%` completed-CPS gain.
- Updated limiting picture:
  - firewall dataplane worker capacity is still the first-order limiter:
    - with `3` dataplane workers on a `4` vCPU firewall VM, the three firewall nodes now sit at `~75%` host CPU average during load, which is consistent with the three dataplane worker cores being effectively saturated while one host core remains non-dataplane.
    - lockless/shared-demux/flow-steer counters are not the problem on the clean run.
  - generator-side source-space pressure is now the clearest secondary limiter masking follow-up gains:
    - the live consumer still has only `8` source IPs,
    - ASTF success ratio collapses from `0.6903` at `w64` to `0.3944` at `w96` and `0.3105` at `w128`,
    - ASTF reports client-side throttle/flow-overflow pressure at the highest tier.
- Current limiting component:
  - **firewall dataplane worker saturation on the full TCP-handshake path remains the primary limiter**, even after cluster uniformity is restored.
  - **consumer source-IP / 4-tuple headroom is the next limiter that now needs to be removed to get a cleaner read on any further firewall tuning.**
- Expected next gain:
  - near-term measurement gain:
    - recreate the consumer with `32` source IPs (`consumer_secondary_private_ip_count=31`) and rerun the new sharded ASTF target-port mode (`TARGET_PORTS=9000-9015`).
    - this should reduce source-port reuse and ASTF flow-overflow noise so completed-CPS changes reflect the firewall more directly.
  - near-term firewall gain:
    - once consumer/source-space pressure is removed, the next likely wins are reductions in per-handshake dataplane worker cost rather than more state-lock work, because lockless QPW and all-D4 uniformity both failed to produce a large completed-CPS step-up.

### DO) 32 source IPs, 16 target ports, and the first sharded attempt failure
- To remove consumer tuple pressure and shard the upstream listener side, updated the upstream cloud-init so the upstream VM always enables `longtcp@9001..9015` in addition to `longtcp.service` on `9000`:
  - code:
    - `cloud-tests/azure/terraform/cloud-init/upstream.yaml.tmpl`
  - implementation note:
    - the systemd enable loop needed escaped Terraform interpolation: `longtcp@$${port}.service`
- Recreated the consumer and upstream with the wider source-IP inventory and the port-shard listeners:
  - command:
    ```bash
    terraform -chdir=cloud-tests/azure/terraform apply -auto-approve \
      -var neuwerk_vmss_size=Standard_D4as_v5 \
      -var neuwerk_instance_count=3 \
      -var neuwerk_dpdk_workers=0 \
      -var consumer_count=1 \
      -var consumer_vm_size=Standard_D4as_v5 \
      -var upstream_vm_size=Standard_D2as_v5 \
      -var consumer_secondary_private_ip_count=31 \
      -var consumer_trex_dual_nic_enabled=true \
      -var neuwerk_binary_path=/home/moritz/dev/neuwerk-rs/firewall/target/release/neuwerk
    ```
- Post-apply validation:
  - consumer primary NIC now carries `32` source IPs: `10.20.3.4..10.20.3.35`
  - consumer TRex NIC remains `10.20.4.5`
  - upstream VM listens on `10.20.4.4:9000..9015`
  - important path detail:
    - the ASTF target-host mode uses `TARGET_HOST=${UPSTREAM_IP}` (`10.20.4.4`), not the VIP, so sharded target ports do not require ILB listener expansion for this benchmark
- Direct validation from the consumer confirmed the intended benchmark path:
  - `10.20.4.4:9000`
  - `10.20.4.4:9001`
  - `10.20.4.4:9002`
  - `10.20.4.4:9015`
- First sharded run attempt was **invalid** because the rebuilt consumer no longer had TRex installed:
  - command:
    ```bash
    make -C cloud-tests/azure cps.matrix.trex.astf.sharded \
      ARTIFACT_DIR=artifacts/cps-matrix-20260317T-d4all-32src-sharded-retaless \
      WORKERS_LIST=64,96,128 \
      RUN_SECONDS=6 \
      WARMUP_SECONDS=2 \
      REPEATS=1 \
      CPS_TREX_ASTF_SERVER_IP_MODE=target_host \
      CPS_TREX_ASTF_CPS_PER_WORKER=500 \
      CPS_TREX_ASTF_MAX_CPS=400000 \
      DPDK_ALLOW_RETALESS_MULTI_QUEUE=1 \
      ASTF_SHARDED_TARGET_PORTS=9000-9015
    ```
  - invalid artifact:
    - `cloud-tests/azure/artifacts/cps-matrix-20260317T-d4all-32src-sharded-retaless`
  - failure signature:
    - `ModuleNotFoundError: No module named 'trex'`
  - do not use that artifact for CPS conclusions

### DP) TRex restore on the rebuilt consumer and successful sharded rerun
- Restored TRex manually on the rebuilt consumer:
  - command:
    ```bash
    source cloud-tests/common/lib.sh
    ssh_jump 4.185.82.209 /home/moritz/dev/neuwerk-rs/firewall/cloud-tests/.secrets/ssh/azure_e2e 10.20.3.4 '
      set -euo pipefail
      sudo mkdir -p /opt
      test -f /tmp/v3.08.tar.gz || wget --no-check-certificate -O /tmp/v3.08.tar.gz https://trex-tgn.cisco.com/trex/release/v3.08.tar.gz
      sudo rm -rf /opt/v3.08 /opt/trex
      sudo tar -xzf /tmp/v3.08.tar.gz -C /opt
      sudo ln -sfn /opt/v3.08 /opt/trex
    '
    ```
- Verified the restored runtime:
  - `/opt/trex/t-rex-64` exists
  - `/opt/trex/automation/trex_control_plane/interactive` exists
  - `PYTHONPATH=/opt/trex/automation/trex_control_plane/interactive python3 -c "import trex.astf.api; print(\"TREX_IMPORT_OK\")"` returns `TREX_IMPORT_OK`
- Cleared stale TRex state before rerunning:
  - command:
    ```bash
    source cloud-tests/common/lib.sh
    ssh_jump 4.185.82.209 /home/moritz/dev/neuwerk-rs/firewall/cloud-tests/.secrets/ssh/azure_e2e 10.20.3.4 \
      'sudo killall -9 _t-rex-64 t-rex-64 2>/dev/null || true; rm -f /tmp/cps_trex_astf_* /tmp/trex_cfg_astf_*.yaml'
    ```
- Successful sharded rerun command:
  ```bash
  make -C cloud-tests/azure cps.matrix.trex.astf.sharded \
    ARTIFACT_DIR=artifacts/cps-matrix-20260317T-d4all-32src-sharded-retaless-rerun \
    WORKERS_LIST=64,96,128 \
    RUN_SECONDS=6 \
    WARMUP_SECONDS=2 \
    REPEATS=1 \
    CPS_TREX_ASTF_SERVER_IP_MODE=target_host \
    CPS_TREX_ASTF_CPS_PER_WORKER=500 \
    CPS_TREX_ASTF_MAX_CPS=400000 \
    DPDK_ALLOW_RETALESS_MULTI_QUEUE=1 \
    ASTF_SHARDED_TARGET_PORTS=9000-9015
  ```
- Successful sharded artifact:
  - `cloud-tests/azure/artifacts/cps-matrix-20260317T-d4all-32src-sharded-retaless-rerun`

### DQ) Sharded result table and comparison against the clean single-port rerun
| run | artifact | source IPs | target ports | w64 completed CPS | w96 completed CPS | w128 completed CPS | notes |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| clean single-port rerun | `cloud-tests/azure/artifacts/cps-matrix-20260317T-rebuilt-d4all-retaless` | `8` | `1` | `11655.93` | `9722.56` | `8931.26` | all-D4 clean reference |
| sharded rerun | `cloud-tests/azure/artifacts/cps-matrix-20260317T-d4all-32src-sharded-retaless-rerun` | `32` | `16` | `12483.94` | `10414.50` | `9864.17` | same firewall fleet, wider consumer tuple space + target-port sharding |

- Before/after delta vs the clean single-port rerun:
  - `w64`: `11655.93 -> 12483.94` (`+828.01`, `+7.10%`)
  - `w96`: `9722.56 -> 10414.50` (`+691.95`, `+7.12%`)
  - `w128`: `8931.26 -> 9864.17` (`+932.91`, `+10.45%`)
- Client-side completed CPS moved by the same amount, confirming this is a real completed-handshake gain and not just a post-processing artifact:
  - client completed CPS:
    - `w64`: `11650.65 -> 12478.37`
    - `w96`: `9721.53 -> 10431.48`
    - `w128`: `8930.33 -> 9902.02`
- Success ratio improved at every offered-load tier:
  - `w64`: `0.6903 -> 0.7121`
  - `w96`: `0.3944 -> 0.4267`
  - `w128`: `0.3105 -> 0.3501`
- Retry/drop pressure remained high, but it improved enough to recover completed CPS:
  - client `tcps_conndrops`:
    - `w64`: `59458 -> 55268`
    - `w96`: `174421 -> 165123`
    - `w128`: `234922 -> 224394`
  - client `tcps_rexmttimeo_syn`:
    - `w64`: `486749 -> 479055`
    - `w96`: `929771 -> 916106`
    - `w128`: `1176599 -> 1184380`
- Firewall observations on the sharded rerun still point at the firewall as the main limiter:
  - firewall host CPU stayed flat at saturation:
    - `w64`: `~75.16%`
    - `w96`: `~74.75%`
    - `w128`: `~74.85%`
  - per-run firewall completed-flow visibility rose, but far less than the offered load:
    - firewall `tcp_cps_observed`:
      - `w64`: `13106.92 -> 13973.78`
      - `w96`: `16033.67 -> 16570.01`
      - `w128`: `13640.16 -> 14654.01`
  - lock contention was still present and even slightly higher than the single-port rerun, but that higher lock activity coexisted with higher completed CPS:
    - `dp_state_lock_wait_seconds_sum`:
      - `w64`: `3.782 -> 3.853`
      - `w96`: `3.501 -> 3.681`
      - `w128`: `3.354 -> 3.881`
    - interpretation:
      - the sharded gain came from removing consumer tuple pressure and target-port concentration, not from reducing state-lock cost
- Queue/descriptor/shared-IO counters still do not indicate a queueing bottleneck:
  - `dpdk_rx_dropped_total=0`
  - `dpdk_tx_dropped_total=0`
  - `dpdk_flow_steer_dispatch_packets_total=0`
  - `dpdk_shared_io_lock_contended_total=0`

### DR) Updated conclusion after the sharded rerun
- Changing the **test strategy** to use `32` consumer source IPs plus `16` target ports was the right fix.
- It delivered a real completed-handshake gain on the same firewall fleet:
  - about `+7%` at `w64`
  - about `+7%` at `w96`
  - about `+10%` at `w128`
- This confirms the previous read:
  - consumer tuple/source-port pressure was a real secondary limiter,
  - but it was **not** the primary limiter.
- Current limiting component:
  - **firewall dataplane worker saturation on the full TCP-handshake path is still the first-order limit** on `3x Standard_D4as_v5`.
  - Evidence:
    - all three firewall nodes remain pinned around `~75%` host CPU average during the sharded runs,
    - consumer and upstream still have spare CPU relative to the firewall,
    - queue drops / descriptor shortages / shared-RX contention remain absent,
    - completed CPS still falls sharply as offered load rises from `w64` to `w128`, even after the tuple-space fix.
- Expected next gain:
  - same-shape software gain is now likely bounded to incremental improvements in the firewall SYN / handshake fast path rather than another large measurement artifact cleanup.
  - a reasonable expectation for another same-infra tuning step is **low single-digit to maybe ~10%** if per-handshake dataplane cost can be reduced materially.
  - a larger step-up than that will likely require **more firewall dataplane capacity** (more usable worker cores per node or larger / more nodes), not more generator-side tuning.

## 2026-03-17 Observability Redeploy + Sharded CPS Rerun

### DS) New observability build and rollout
- Added harness-side summary extraction for the new CPS-focused labeled metrics:
  - `handshake_events_by_worker`
  - `handshake_drops_by_worker`
  - `state_lock_by_worker`
  - `state_lock_by_shard`
  - `dpdk_queue_by_queue`
  - `dpdk_flow_steer_by_worker`
  - `dpdk_service_lane`
  - `handshake_stage_timing_by_worker`
  - `table_probe_by_worker`
  - `nat_port_scan_by_worker`
- Added new dataplane metrics:
  - `dp_handshake_stage_seconds{worker,direction,stage}`
  - `dp_table_probe_steps{worker,table,operation,result}`
  - `dp_nat_port_scan_steps{worker,result}`
- Important rollout note:
  - first local build attempt used `cargo build --release`, producing non-DPDK md5 `7febaba8674d4303a1372fc441b0c572`.
  - direct rollout of that artifact caused `dpdk io backend not available (build with --features dpdk and install DPDK)` on `10.20.1.4`.
  - recovery was done immediately by restoring the known-good running binary md5 `7670a4eb004a5fcf5b60a139f19c3eaf` from `10.20.1.5` back onto `10.20.1.4`.
  - correct deploy-safe build command is:
    ```bash
    make build.release
    ```
  - corrected DPDK-enabled binary hashes:
    - md5: `d6367a3b0080e689e7a17627d0a41299`
    - sha256: `2834c031ddfb0aa3b9c3f7f25ba01e01641da3fedd284afe5aa2ed30073afba8`
- Sequential direct rollout completed to all live firewall nodes:
  - `10.20.1.4`
  - `10.20.1.5`
  - `10.20.1.7`
- Post-rollout verification:
  - all three nodes `systemctl is-active neuwerk.service == active`
  - all three return `200` on `https://<mgmt-ip>:8443/health`
  - all three run the same md5 `d6367a3b0080e689e7a17627d0a41299`
  - retained runtime knobs:
    - `NEUWERK_DPDK_ALLOW_AZURE_MULTIWORKER=1`
    - `NEUWERK_DPDK_ALLOW_RETALESS_MULTI_QUEUE=1`
    - `NEUWERK_DPDK_PERF_MODE=aggressive`

### DT) Rerun command and artifact
- Consumer sanity before rerun:
  - `32` source IPs still present on `10.20.3.4`
  - upstream still listening on `9000-9015`
  - all firewall nodes passed `/health` and `/ready`
- Rerun command:
  ```bash
  make -C cloud-tests/azure cps.matrix.trex.astf.sharded \
    ARTIFACT_DIR=artifacts/cps-matrix-20260317T-d4all-32src-sharded-retaless-obsv \
    WORKERS_LIST=64,96,128 \
    RUN_SECONDS=6 \
    WARMUP_SECONDS=2 \
    REPEATS=1 \
    CPS_TREX_ASTF_SERVER_IP_MODE=target_host \
    CPS_TREX_ASTF_CPS_PER_WORKER=500 \
    CPS_TREX_ASTF_MAX_CPS=400000 \
    DPDK_ALLOW_RETALESS_MULTI_QUEUE=1 \
    ASTF_SHARDED_TARGET_PORTS=9000-9015
  ```
- Artifact:
  - `cloud-tests/azure/artifacts/cps-matrix-20260317T-d4all-32src-sharded-retaless-obsv`

### DU) Result table vs prior sharded rerun
| run | prior sharded rerun | observability rerun | delta |
| --- | ---: | ---: | ---: |
| `w64` completed CPS | `12483.94` | `11926.48` | `-557.46` (`-4.47%`) |
| `w96` completed CPS | `10414.50` | `10399.28` | `-15.22` (`-0.15%`) |
| `w128` completed CPS | `9864.17` | `9653.34` | `-210.83` (`-2.14%`) |

- The rerun is close enough to the prior sharded result that the limiting shape is unchanged:
  - `w64` still lands in the `~11.9k-12.5k` class
  - `w96` still lands in the `~10.4k` class
  - `w128` still lands in the `~9.6k-9.9k` class
- Success ratio remains the dominant gating failure:
  - `w64`: `0.6940`
  - `w96`: `0.4275`
  - `w128`: `0.3374`
- Client retry/drop pressure is still concentrated in SYN handshake timeout/drop counters:
  - `w64`: `tcps_conndrops=58,748`
  - `w96`: `tcps_conndrops=164,886`
  - `w128`: `tcps_conndrops=228,616`

### DV) Signals pointing away from PMD / queue imbalance
- Per-queue packet distribution is extremely even on every rerun tier:
  - aggregate RX queue coefficient of variation:
    - `w64`: `0.24%`
    - `w96`: `0.30%`
    - `w128`: `0.32%`
  - aggregate TX queue coefficient of variation:
    - `w64`: `0.24%`
    - `w96`: `0.31%`
    - `w128`: `0.32%`
- Per-worker completed-handshake counts are also evenly spread:
  - completed-handshake coefficient of variation:
    - `w64`: `0.58%`
    - `w96`: `0.67%`
    - `w128`: `0.80%`
- Explicit firewall-side handshake drops are negligible:
  - total `dp_tcp_handshake_drops_total` delta:
    - `w64`: `15`
    - `w96`: `21`
    - `w128`: `8`
  - all observed drop reason deltas were `flow_missing`, and they are far too small to explain the CPS collapse.
- Shared-RX/software-forwarding queue wait counters remain effectively absent:
  - `dpdk_flow_steer_queue_wait_seconds_count` delta: `0`
  - `dpdk_service_lane_forward_queue_wait_seconds_count` delta: `0`
- There is still no evidence of DPDK queue-drop or descriptor exhaustion as the primary limiter in this run class.

### DW) Signals pointing to firewall dataplane worker saturation
- Firewall CPU remains flat and pinned at the same ceiling on every node and every offered-load tier:
  - `w64`: `~74.8%` on each firewall node
  - `w96`: `~74.7%` on each firewall node
  - `w128`: `~74.8%` on each firewall node
- This is the expected host-wide signature of `3` dataplane workers saturating on a `4 vCPU` VM:
  - one core worth of headroom remains outside the dataplane workers,
  - but the usable dataplane worker budget is already exhausted.
- Consumer and upstream are materially less loaded during the same runs:
  - consumer host CPU:
    - `w64`: `~21.7%`
    - `w96`: `~25.1%`
    - `w128`: `~26.2%`
  - upstream host CPU:
    - `w64`: `~37.0%`
    - `w96`: `~35.1%`
    - `w128`: `~33.6%`
- Interpretation:
  - the system is not generator-CPU-limited,
  - the upstream is not CPU-bound,
  - the firewall dataplane workers are the component already at the effective compute ceiling.

### DX) What the new lock metrics say
- State-lock wait cost is present but modest and stable:
  - aggregate per-worker average wait time stays around `~7-10 us`
  - aggregate per-worker average hold time stays around:
    - worker `0`: `~2.05 us`
    - worker `1`: `~0.19 us`
    - worker `2`: `~0.26 us`
- The worker-0 hold-time skew is consistent across all three firewall nodes and all load tiers.
- Interpretation:
  - there is a real worker-0-specific extra cost in the dataplane fast path,
  - but it does **not** show up as queue imbalance or completion imbalance,
  - so it currently looks more like owner/housekeeping/state-path overhead inside the dataplane worker loop than a PMD RX/TX distribution problem.

### DY) Important observability gap discovered in the rerun
- The newly added stage/probe histograms did **not** yield usable live-run deltas:
  - `dp_handshake_stage_seconds_*`
  - `dp_table_probe_steps_*`
  - `dp_nat_port_scan_steps_*`
- In the captured metrics, these series showed only the baseline sample shape:
  - `_count = 1`
  - `_sum = 0`
  - delta `0` between pre/post snapshots
- Example from `post.w96.r1.10_20_1_4.metrics.prom`:
  - `dp_handshake_stage_seconds_count{direction="outbound",stage="flow_probe",worker="0"} 1`
  - `dp_handshake_stage_seconds_sum{direction="outbound",stage="flow_probe",worker="0"} 0`
  - `dp_nat_port_scan_steps_count{result="allocated",worker="0"} 1`
  - `dp_nat_port_scan_steps_sum{result="allocated",worker="0"} 0`
- Conclusion from this:
  - the added metric families are present in the export path,
  - but they are not yet recording real handshake-path observations under load,
  - so they are not sufficient yet to isolate exact cost split across:
    - flow lookup
    - NAT allocation/reverse lookup
    - policy evaluation
    - rewrite
    - final ACK / completion handling

### DZ) Updated conclusion after the observability rerun
- Current limiting component:
  - **firewall dataplane worker CPU on the full TCP-handshake path remains the primary limiter** on `3x Standard_D4as_v5`.
- Best current read on “PMD/DPDK vs elsewhere”:
  - evidence is **against PMD queue imbalance / RSS / queueing** as the first-order problem,
  - evidence is **for an engine/dataplane-worker hot path cost** inside the handshake fast path.
- Strongest evidence:
  - per-queue packet distribution is essentially perfectly balanced,
  - per-worker completions are balanced,
  - explicit firewall drop counters are tiny,
  - shared-RX/service-lane wait counters are zero,
  - every firewall node pins at the same `~75%` host CPU ceiling while consumer/upstream do not.
- Remaining uncertainty:
  - the new stage/probe observability is not yet capturing live work, so we still cannot cleanly separate:
    - flow-table cost
    - NAT table/port-scan cost
    - policy/state-machine cost
    - worker-0 owner/housekeeping overhead
- Expected next gain:
  - after fixing the stage/probe observability so it records real live deltas, the next same-shape code win is likely still in the **low single-digit to ~10%** range.
  - a materially larger jump on this exact shape is unlikely without adding more usable firewall dataplane worker capacity.

## 2026-03-17 Stage/Probe Metrics Fix (No-SNAT Path) + Full CPS Rerun

### EA) Root cause of missing stage/probe metrics
- The new handshake-stage / probe instrumentation had been added mainly in the SNAT packet path (`packet_path.rs`).
- Azure ASTF CPS benchmark traffic in this setup runs with `snat_mode=None`, so the live dataplane path is `src/dataplane/engine/no_snat.rs`.
- Result:
  - `dp_tcp_handshake_events_total` moved (already instrumented in both paths),
  - but `dp_handshake_stage_seconds` / `dp_table_probe_steps` / `dp_nat_port_scan_steps` appeared stuck or baseline-only in the no-SNAT runs.

### EB) Code fixes applied
- Added stage/probe instrumentation to the no-SNAT handshake path:
  - file: `src/dataplane/engine/no_snat.rs`
  - outbound:
    - `flow_probe`
    - `flow_state`
    - `policy_eval_miss`
    - `policy_eval_hit`
    - `flow` table probe recording
  - inbound:
    - `flow_probe`
    - `flow_state`
    - `policy_eval`
    - `flow` table probe recording
- Removed misleading startup seeding behavior for new histogram families:
  - file: `src/controlplane/metrics/construct.rs`
  - changed from `.observe(0.0)` to label pre-creation only (`with_label_values(...)`) for:
    - `dp_handshake_stage_seconds`
    - `dp_table_probe_steps`
    - `dp_nat_port_scan_steps`
- Build validation:
  - `cargo fmt`
  - `cargo check`
  - `make build.release`
- New deployed DPDK binary:
  - md5: `e690af22caaccc0d8acd73ea84b84175`
  - sha256: `620d566d45e1f029d37f501468e3ffd2385ca59128a1dfc31a9153ee87e2c95a`
- Rollout:
  - deployed sequentially to `10.20.1.4`, `10.20.1.5`, `10.20.1.7`
  - verified all nodes `active` and `/health=200`

### EC) Focus verification (single tier) to confirm metric movement
- Artifact:
  - `cloud-tests/azure/artifacts/cps-matrix-20260317T-w96-stagefix-verify`
- Command:
  ```bash
  make -C cloud-tests/azure cps.matrix.trex.astf.sharded \
    ARTIFACT_DIR=artifacts/cps-matrix-20260317T-w96-stagefix-verify \
    WORKERS_LIST=96 RUN_SECONDS=6 WARMUP_SECONDS=2 REPEATS=1 \
    CPS_TREX_ASTF_SERVER_IP_MODE=target_host \
    CPS_TREX_ASTF_CPS_PER_WORKER=500 CPS_TREX_ASTF_MAX_CPS=400000 \
    DPDK_ALLOW_RETALESS_MULTI_QUEUE=1 ASTF_SHARDED_TARGET_PORTS=9000-9015
  ```
- Verification result:
  - `dp_handshake_stage_seconds_{count,sum}` now show large positive deltas across workers/stages.
  - `dp_table_probe_steps_{count,sum}` now show large positive deltas for `flow` lookup hit/miss.
  - `dp_nat_port_scan_steps` remained unused in this bench (expected with `snat_mode=None`).

### ED) Full rerun on fixed instrumentation
- Artifact:
  - `cloud-tests/azure/artifacts/cps-matrix-20260317T-d4all-32src-sharded-retaless-obsv-fixed`
- Command:
  ```bash
  make -C cloud-tests/azure cps.matrix.trex.astf.sharded \
    ARTIFACT_DIR=artifacts/cps-matrix-20260317T-d4all-32src-sharded-retaless-obsv-fixed \
    WORKERS_LIST=64,96,128 RUN_SECONDS=6 WARMUP_SECONDS=2 REPEATS=1 \
    CPS_TREX_ASTF_SERVER_IP_MODE=target_host \
    CPS_TREX_ASTF_CPS_PER_WORKER=500 CPS_TREX_ASTF_MAX_CPS=400000 \
    DPDK_ALLOW_RETALESS_MULTI_QUEUE=1 ASTF_SHARDED_TARGET_PORTS=9000-9015
  ```

### EE) Before/after table (fixed-observability rerun vs previous observability rerun)
| run | previous observability rerun | fixed-observability rerun | delta |
| --- | ---: | ---: | ---: |
| `w64` completed CPS | `11926.48` | `12148.65` | `+222.17` (`+1.86%`) |
| `w96` completed CPS | `10399.28` | `10084.54` | `-314.74` (`-3.03%`) |
| `w128` completed CPS | `9653.34` | `10236.32` | `+582.98` (`+6.04%`) |

- Run-to-run jitter exists, but the overall performance class is unchanged:
  - still roughly `~10k-12k` completed CPS across `w64/w96/w128`,
  - still `success_ratio_gate` limited on all tiers.

### EF) New evidence from now-working stage/probe metrics
- Queue balance remains very tight (still not PMD-imbalance shaped):
  - queue RX CV:
    - `w64`: `0.198%`
    - `w96`: `0.293%`
    - `w128`: `0.307%`
  - queue TX CV:
    - `w64`: `0.204%`
    - `w96`: `0.301%`
    - `w128`: `0.303%`
- Firewall CPU remains pinned while consumer/upstream remain lower:
  - firewall host CPU mean stays `~74.3-74.7%` on all tiers,
  - consumer `~22-25%`, upstream `~34-37%`.
- Handshake stage timing (aggregate average):
  - outbound `flow_probe` avg:
    - `w64`: `0.179 us`
    - `w96`: `0.189 us`
    - `w128`: `0.202 us`
  - outbound `flow_state` avg:
    - `w64`: `0.171 us`
    - `w96`: `0.166 us`
    - `w128`: `0.198 us`
  - outbound `policy_eval_miss` avg:
    - `w64`: `0.309 us`
    - `w96`: `0.266 us`
    - `w128`: `0.263 us`
- Flow-table probe depth (strong new signal):
  - `flow lookup hit` avg steps:
    - `w64`: `1.662`
    - `w96`: `1.668`
    - `w128`: `1.857`
  - `flow lookup miss` avg steps:
    - `w64`: `2.742`
    - `w96`: `2.706`
    - `w128`: `3.794`
- Interpretation:
  - as offered load rises to `w128`, miss probe depth grows significantly (`~2.7 -> ~3.8`), and hit probe depth also rises.
  - this points to growing cost/pressure in flow-table lookup behavior under high churn, on top of already saturated firewall worker CPU.

### EG) Updated bottom line after stage/probe fix
- The issue is still not best explained by PMD queueing / RSS imbalance.
- Strongest current evidence points to firewall dataplane engine-side handshake cost under worker CPU saturation, with flow-table probe depth becoming materially worse at high offered load.
- In this no-SNAT bench profile:
  - NAT port-scan metrics are not a useful discriminator (path not exercised),
  - flow-table path and policy/state path are the key remaining targets.
- Practical next high-signal experiments:
  1. Reduce flow-table probe depth under churn (hash/table sizing/load-factor strategy) and rerun same matrix.
  2. Add explicit counters for policy fast-path hit/miss transitions and flow-entry lifecycle churn (insert/evict/reuse rates per worker).
  3. Re-check worker-0 owner/housekeeping overhead split with the now-working stage data to quantify non-flow-lookup overhead.

## 2026-03-17 Flow Table Capacity A/B (`NEUWERK_FLOW_TABLE_CAPACITY=131072`)

### EH) One-change runtime override
- Applied runtime-only override on all firewall nodes:
  - drop-in: `/etc/systemd/system/neuwerk.service.d/96-flow-table-capacity.conf`
  - value: `Environment=NEUWERK_FLOW_TABLE_CAPACITY=131072`
- Kept policy and all other CPS knobs constant:
  - `NEUWERK_DPDK_ALLOW_AZURE_MULTIWORKER=1`
  - `NEUWERK_DPDK_ALLOW_RETALESS_MULTI_QUEUE=1`
  - `NEUWERK_DPDK_PERF_MODE=aggressive`

### EI) Commands and artifacts
- Full matrix under flow-capacity override:
  ```bash
  make -C cloud-tests/azure cps.matrix.trex.astf.sharded \
    ARTIFACT_DIR=artifacts/cps-matrix-20260317T-d4all-32src-sharded-retaless-flowcap131072 \
    WORKERS_LIST=64,96,128 RUN_SECONDS=6 WARMUP_SECONDS=2 REPEATS=1 \
    CPS_TREX_ASTF_SERVER_IP_MODE=target_host \
    CPS_TREX_ASTF_CPS_PER_WORKER=500 CPS_TREX_ASTF_MAX_CPS=400000 \
    DPDK_ALLOW_RETALESS_MULTI_QUEUE=1 ASTF_SHARDED_TARGET_PORTS=9000-9015
  ```
- Invalid run note:
  - `w96` in this artifact is invalid due consumer SSH disconnect:
    - `raw/cps.w96.r1.consumer.10_20_3_4.err` contains `Connection to 10.20.3.4 closed by remote host.`
    - `runs/run.w96.r1.json` has unusable client/upstream values.
- Clean `w96` rerun:
  - artifact: `cloud-tests/azure/artifacts/cps-matrix-20260317T-flowcap131072-w96-rerun`
- Repeat robustness check (`w96`, `REPEATS=2`):
  - artifact: `cloud-tests/azure/artifacts/cps-matrix-20260317T-flowcap131072-w96-repeatcheck2`
  ```bash
  make -C cloud-tests/azure cps.matrix.trex.astf.sharded \
    ARTIFACT_DIR=artifacts/cps-matrix-20260317T-flowcap131072-w96-repeatcheck2 \
    WORKERS_LIST=96 RUN_SECONDS=6 WARMUP_SECONDS=2 REPEATS=2 \
    TARGET_PORT=9000 CPS_TREX_ASTF_SERVER_IP_MODE=target_host \
    CPS_TREX_ASTF_CPS_PER_WORKER=500 CPS_TREX_ASTF_MAX_CPS=400000 \
    DPDK_ALLOW_AZURE_MULTIWORKER=1 DPDK_ALLOW_RETALESS_MULTI_QUEUE=1 \
    DPDK_PERF_MODE=aggressive ASTF_SHARDED_TARGET_PORTS=9000-9015
  ```

### EJ) Before/after table (completed CPS)
- Baseline source: `cloud-tests/azure/artifacts/cps-matrix-20260317T-d4all-32src-sharded-retaless-obsv-fixed`
- Tuned source:
  - `w64/w128`: `...flowcap131072` full matrix
  - `w96`: mean of `...flowcap131072-w96-repeatcheck2` repeats (`r1/r2`)

| run | baseline completed CPS | tuned completed CPS | delta |
| --- | ---: | ---: | ---: |
| `w64` | `12148.65` | `12282.74` | `+134.09` (`+1.10%`) |
| `w96` | `10084.54` | `10397.72` | `+313.18` (`+3.11%`) |
| `w128` | `10236.32` | `9961.37` | `-274.95` (`-2.69%`) |

- `w96` repeat-check spread remained high:
  - `r1`: `10773.75` CPS
  - `r2`: `10021.68` CPS
  - stdev: `376.03` CPS (`~3.6%` of mean)

### EK) Probe-depth/latency signals under flow-capacity override
- `w96` miss-probe depth in repeatcheck2 stayed in the same class as baseline:
  - baseline miss avg steps: `2.706`
  - tuned repeat `r1`: `2.528`
  - tuned repeat `r2`: `2.650`
- Prior single rerun showed a much higher miss depth (`4.062`) and was treated as a noisy outlier; repeatcheck2 did not reproduce that spike.
- Handshake-stage average timing remained sub-microsecond and did not show a clear, stable improvement trend unique to this override.

### EL) Decision: rollback override (not kept)
- Because gains were mixed by tier and not robust (notably `w128` regression), this runtime change was rolled back.
- Rollback command used on each firewall (`10.20.1.4`, `10.20.1.5`, `10.20.1.7`):
  ```bash
  sudo rm -f /etc/systemd/system/neuwerk.service.d/96-flow-table-capacity.conf
  sudo systemctl daemon-reload
  sudo systemctl reset-failed neuwerk.service || true
  sudo systemctl restart neuwerk.service
  ```
- Post-rollback verification:
  - `neuwerk.service` active on all nodes
  - `systemctl show neuwerk.service -p Environment` no longer contains `NEUWERK_FLOW_TABLE_CAPACITY`
  - benchmark DPDK overrides remain applied

### EM) Updated conclusion after flow-capacity A/B
- Current limiting component remains firewall dataplane worker compute on the handshake path.
- Evidence still points away from PMD/RSS queue imbalance and toward dataplane fast-path cost under high churn.
- `NEUWERK_FLOW_TABLE_CAPACITY=131072` is not adopted as a default on this shape.
- Expected next gain:
  - prioritize per-worker flow lifecycle churn visibility plus targeted table strategy changes that reduce miss-probe work at high offered load,
  - likely remaining headroom in low single digits unless dataplane worker capacity is increased.

### EN) Post-rollback sanity check
- Artifact:
  - `cloud-tests/azure/artifacts/cps-matrix-20260317T-postrollback-w96-sanity`
- Command:
  ```bash
  make -C cloud-tests/azure cps.matrix.trex.astf.sharded \
    ARTIFACT_DIR=artifacts/cps-matrix-20260317T-postrollback-w96-sanity \
    WORKERS_LIST=96 RUN_SECONDS=6 WARMUP_SECONDS=2 REPEATS=1 \
    TARGET_PORT=9000 CPS_TREX_ASTF_SERVER_IP_MODE=target_host \
    CPS_TREX_ASTF_CPS_PER_WORKER=500 CPS_TREX_ASTF_MAX_CPS=400000 \
    DPDK_ALLOW_AZURE_MULTIWORKER=1 DPDK_ALLOW_RETALESS_MULTI_QUEUE=1 \
    DPDK_PERF_MODE=aggressive ASTF_SHARDED_TARGET_PORTS=9000-9015
  ```
- Result:
  - client CPS: `10423.97`
  - upstream completed CPS (manual from upstream pre/post PassiveOpens): `10424.99`
  - confirms rollback returned to expected `~10k-10.5k` class behavior.

## 2026-03-17 Additional Observability + Incomplete-TCP Timeout A/B

### EO) New observability added in code
- Added per-worker flow lifecycle counter:
  - metric: `dp_flow_lifecycle_events_total{worker,event,reason}`
  - hooks:
    - flow open (`event=open`, `reason=new`)
    - flow close (`event=close`, reason from close path, e.g. `tcp_rst`, `tcp_fin`, `policy_drop`)
    - idle-timeout eviction (`event=close`, `reason=idle_timeout`, batched by count)
- Added this metric group to CPS artifact aggregation:
  - `flow_lifecycle_by_worker` in `cloud-tests/common/run-cps-matrix.sh`
- Files changed:
  - `src/controlplane/metrics.rs`
  - `src/controlplane/metrics/construct.rs`
  - `src/controlplane/metrics/methods.rs`
  - `src/dataplane/engine.rs`
  - `cloud-tests/common/run-cps-matrix.sh`

### EP) Runtime-tunable incomplete TCP timeout added
- Added optional flow-table timeout split for incomplete TCP flows:
  - env: `NEUWERK_FLOW_INCOMPLETE_TCP_IDLE_TIMEOUT_SECS`
  - behavior:
    - applies only to TCP flows where handshake is not marked complete
    - if unset, behavior remains unchanged (falls back to existing idle timeout)
- File changed:
  - `src/dataplane/flow.rs`

### EQ) Build + rollout for this investigation pass
- Build validation:
  - `cargo check`
  - `make build.release`
- Deployed binary to all firewall nodes (`10.20.1.4`, `10.20.1.5`, `10.20.1.7`):
  - md5: `d412ef64cedaa53e6ec41c158b3e9388`
  - sha256: `e1312f212aa2e645ce5a5fdab1797e2c591e2fd06f325109b46a5461f0b2db4b`
- Verified:
  - `neuwerk.service` active on all nodes
  - `make -C cloud-tests/azure health` passed

### ER) Focused live verification of new flow-lifecycle metric
- Artifact:
  - `cloud-tests/azure/artifacts/cps-matrix-20260317T-flow-lifecycle-metric-verify`
- Command:
  ```bash
  make -C cloud-tests/azure cps.matrix.trex.astf.sharded \
    ARTIFACT_DIR=artifacts/cps-matrix-20260317T-flow-lifecycle-metric-verify \
    WORKERS_LIST=96 RUN_SECONDS=6 WARMUP_SECONDS=2 REPEATS=1 \
    TARGET_PORT=9000 CPS_TREX_ASTF_SERVER_IP_MODE=target_host \
    CPS_TREX_ASTF_CPS_PER_WORKER=500 CPS_TREX_ASTF_MAX_CPS=400000 \
    DPDK_ALLOW_AZURE_MULTIWORKER=1 DPDK_ALLOW_RETALESS_MULTI_QUEUE=1 \
    DPDK_PERF_MODE=aggressive ASTF_SHARDED_TARGET_PORTS=9000-9015
  ```
- Result:
  - completed CPS (`upstream_tcp.passive_open_cps_observed`): `10515.42`
  - `dp_flow_lifecycle_events_total` delta: `353940`
  - aggregated lifecycle deltas:
    - `open/new`: `217332`
    - `close/tcp_rst`: `135960`
    - `close/tcp_fin`: `648`
    - `close/idle_timeout`: `0`
- Interpretation:
  - handshake load creates very high open/close churn in short windows,
  - with default long idle timeout, many newly opened flows remain active beyond the 6s window.

### ES) A/B: incomplete TCP timeout override (`3s`) vs control
- Control artifact (no override):
  - `cloud-tests/azure/artifacts/cps-matrix-20260317T-incomplete-timeout-control`
- Tuned artifact (`NEUWERK_FLOW_INCOMPLETE_TCP_IDLE_TIMEOUT_SECS=3`):
  - `cloud-tests/azure/artifacts/cps-matrix-20260317T-incomplete-timeout-3s`
- Shared command shape:
  ```bash
  make -C cloud-tests/azure cps.matrix.trex.astf.sharded \
    ARTIFACT_DIR=<artifact> \
    WORKERS_LIST=96,128 RUN_SECONDS=6 WARMUP_SECONDS=2 REPEATS=1 \
    TARGET_PORT=9000 CPS_TREX_ASTF_SERVER_IP_MODE=target_host \
    CPS_TREX_ASTF_CPS_PER_WORKER=500 CPS_TREX_ASTF_MAX_CPS=400000 \
    DPDK_ALLOW_AZURE_MULTIWORKER=1 DPDK_ALLOW_RETALESS_MULTI_QUEUE=1 \
    DPDK_PERF_MODE=aggressive ASTF_SHARDED_TARGET_PORTS=9000-9015
  ```
- Result table:

| run | control completed CPS | timeout=3s completed CPS | delta |
| --- | ---: | ---: | ---: |
| `w96` | `10471.69` | `10162.78` | `-308.91` (`-2.95%`) |
| `w128` | `9775.83` | `9543.98` | `-231.85` (`-2.37%`) |

- Supporting signal changes:
  - active-flow end-of-run delta dropped sharply:
    - `w96`: `+65820` -> `-6`
    - `w128`: `+41595` -> `+28`
  - idle-timeout closes appeared only in tuned run:
    - `w96`: `104393`
    - `w128`: `123891`
  - probe depth:
    - `w128` miss avg improved (`3.333 -> 2.679`)
    - but completed CPS still regressed.

### ET) Decision and updated bottleneck read
- `NEUWERK_FLOW_INCOMPLETE_TCP_IDLE_TIMEOUT_SECS=3` is **not kept** (rolled back on all firewall nodes).
- This A/B gives strong evidence that:
  - flow-state retention/churn materially affects table pressure and probe depth,
  - but overly aggressive timeout causes completed-handshake regressions (likely evicting still-relevant in-flight state).
- Updated best current diagnosis:
  - primary limiter remains firewall dataplane fast-path compute under high churn,
  - not PMD/RSS queue imbalance.
- Next highest-value step:
  - keep new lifecycle observability,
  - test moderate/informed incomplete-flow timeout or handshake-state-specific eviction policy (not a single hard 3s),
  - validate on both short (`6s`) and longer steady windows to separate transient vs steady-state gains.

## 2026-03-17 Flow-Table Internal Metrics + 30s Steady-State A/B

### EU) Additional observability added
- Added per-worker flow-table internals:
  - `dp_flow_table_capacity{worker}`
  - `dp_flow_table_tombstones{worker}`
  - `dp_flow_table_used_slots_ratio{worker}`
  - `dp_flow_table_tombstone_ratio{worker}`
  - `dp_flow_table_resize_events_total{worker,reason}`
- Added TCP handshake close-age histogram:
  - `dp_tcp_handshake_close_age_seconds{worker,reason,completion}`
  - completion label values: `completed` / `incomplete`
- Extended CPS artifact summarization:
  - include new labeled metric groups:
    - `flow_table_internal_by_worker`
    - `handshake_close_age_by_worker`
  - include histogram-bucket-derived quantiles (p50/p95/p99) in:
    - `aggregate.derived_histogram_quantiles.table_probe_steps`
    - `aggregate.derived_histogram_quantiles.tcp_handshake_close_age_seconds`
- Files changed in this pass:
  - `src/dataplane/flow.rs`
  - `src/dataplane/engine.rs`
  - `src/controlplane/metrics.rs`
  - `src/controlplane/metrics/construct.rs`
  - `src/controlplane/metrics/methods.rs`
  - `cloud-tests/common/run-cps-matrix.sh`

### EV) Build and rollout for this pass
- Validation:
  - `cargo fmt`
  - `cargo check`
  - `make build.release`
- Deployed binary to all firewalls:
  - md5: `af3520890e6ceec07ba741d7667574ea`
  - sha256: `bf81877b50e181ef68d153a7ca8bd05b02d9a28e5355f3bbb77d8012f57978d7`
- Verified:
  - `neuwerk.service` active on `10.20.1.4`, `10.20.1.5`, `10.20.1.7`
  - `make -C cloud-tests/azure health` passed
  - runtime env returned to baseline DPDK knobs after experiments (no timeout override kept)

### EW) 30s steady-state control baseline
- Artifact:
  - `cloud-tests/azure/artifacts/cps-matrix-20260317T-steady30-control`
- Command:
  ```bash
  make -C cloud-tests/azure cps.matrix.trex.astf.sharded \
    ARTIFACT_DIR=artifacts/cps-matrix-20260317T-steady30-control \
    WORKERS_LIST=96,128 RUN_SECONDS=30 WARMUP_SECONDS=5 REPEATS=1 \
    TARGET_PORT=9000 CPS_TREX_ASTF_SERVER_IP_MODE=target_host \
    CPS_TREX_ASTF_CPS_PER_WORKER=500 CPS_TREX_ASTF_MAX_CPS=400000 \
    DPDK_ALLOW_AZURE_MULTIWORKER=1 DPDK_ALLOW_RETALESS_MULTI_QUEUE=1 \
    DPDK_PERF_MODE=aggressive ASTF_SHARDED_TARGET_PORTS=9000-9015
  ```
- Completed CPS (upstream passive-open observed):
  - `w96`: `12523.91` (`duration_seconds_observed=38.80`)
  - `w128`: `13156.06` (`duration_seconds_observed=41.39`)

### EX) 30s steady-state moderate timeout A/B (`20s`)
- Applied runtime override:
  - `/etc/systemd/system/neuwerk.service.d/97-flow-incomplete-timeout.conf`
  - `Environment=NEUWERK_FLOW_INCOMPLETE_TCP_IDLE_TIMEOUT_SECS=20`
- Artifact:
  - `cloud-tests/azure/artifacts/cps-matrix-20260317T-steady30-timeout20`
- Same command shape as control, only timeout override changed.

| run | control completed CPS | timeout=20s completed CPS | delta |
| --- | ---: | ---: | ---: |
| `w96` | `12523.91` | `12576.99` | `+53.09` (`+0.42%`) |
| `w128` | `13156.06` | `13217.86` | `+61.80` (`+0.47%`) |

- Supporting signals:
  - active-flow delta reduced substantially:
    - `w96`: `+196409 -> -12344`
    - `w128`: `+132058 -> +26307`
  - idle-timeout close events became large:
    - `w96`: `287378`
    - `w128`: `265575`
  - probe-depth tail changed unevenly:
    - `w96` miss p95 improved (`9.08 -> 8.05`)
    - `w128` miss p95 worsened (`6.76 -> 9.44`)
  - handshake close-age p95 for incomplete flows dropped sharply in tuned run (expected with faster eviction), but this is not a direct throughput win signal.

### EY) Decision for timeout=20s
- Not adopted as default yet; rolled back after run.
- Rationale:
  - CPS uplift is small (`~0.4-0.5%`) on single repeats and below noise confidence for this setup.
  - tail probe behavior is mixed across worker tiers.
  - needs repeat validation before committing runtime policy changes.

### EZ) Updated conclusion after this pass
- New evidence further supports engine/state churn as the central bottleneck surface:
  - flow lifecycle churn is very high,
  - flow-table tombstone/used-slot dynamics and close-age tails are measurable and tunable,
  - PMD/RSS imbalance remains unsupported as first-order cause.
- Next concrete step:
  - run repeat-backed steady-state sweep for timeout values (`20/45/90s`) with `REPEATS>=2`,
  - include quantile-based acceptance gates (probe p95/p99 + completed CPS), not means alone.

## 2026-03-17 SYN-only Timeout Split + Hash-Hotpath Retest

### FA) New binary build and rollout
- User patch under test:
  - SYN-only incomplete TCP timeout path default `3s` (`NEUWERK_FLOW_INCOMPLETE_TCP_SYN_SENT_IDLE_TIMEOUT_SECS` override)
  - SYN+SYNACK incomplete path still uses `NEUWERK_FLOW_INCOMPLETE_TCP_IDLE_TIMEOUT_SECS`
  - mixed 32-bit flow hash hot-path in probe/insert path
- Build:
  - `make build.release`
  - local md5: `125f93a1ec4e95203a83a71543542529`
  - local sha256: `c0c5d44d12d631b751d28784c6ef924ecc2da06750be2e230159769bb36d58a9`
- Rollout command path:
  - source helper: `cloud-tests/common/lib.sh` (`ssh_jump`)
  - deployed to `/usr/local/bin/neuwerk` on `10.20.1.4`, `10.20.1.5`, `10.20.1.7`
  - restarted `neuwerk.service` on all nodes
  - verified remote md5 on all 3 nodes = `125f93a1ec4e95203a83a71543542529`
  - verified `/etc/systemd/system/neuwerk.service.d/97-flow-incomplete-timeout.conf` absent on all nodes
  - verified `make -C cloud-tests/azure health` passed

### FB) CPS retest commands and artifacts
- Main matrix command:
  ```bash
  make -C cloud-tests/azure cps.matrix.trex.astf.sharded \
    ARTIFACT_DIR=artifacts/cps-matrix-20260317T215307Z-synsent3s-hashmix-retest \
    WORKERS_LIST=64,96,128 RUN_SECONDS=6 WARMUP_SECONDS=2 REPEATS=1 TARGET_PORT=9000 \
    CPS_TREX_ASTF_SERVER_IP_MODE=target_host \
    CPS_TREX_ASTF_CPS_PER_WORKER=500 CPS_TREX_ASTF_MAX_CPS=400000 \
    DPDK_ALLOW_AZURE_MULTIWORKER=1 DPDK_ALLOW_RETALESS_MULTI_QUEUE=1 DPDK_PERF_MODE=aggressive \
    ASTF_SHARDED_TARGET_PORTS=9000-9015
  ```
- `w96` rerun (first pass had harness collection issue: `Connection to 10.20.3.4 closed by remote host`, consumer JSON empty):
  ```bash
  make -C cloud-tests/azure cps.matrix.trex.astf.sharded \
    ARTIFACT_DIR=artifacts/cps-matrix-20260317T215307Z-synsent3s-hashmix-retest-w96-retry \
    WORKERS_LIST=96 RUN_SECONDS=6 WARMUP_SECONDS=2 REPEATS=1 TARGET_PORT=9000 \
    CPS_TREX_ASTF_SERVER_IP_MODE=target_host \
    CPS_TREX_ASTF_CPS_PER_WORKER=500 CPS_TREX_ASTF_MAX_CPS=400000 \
    DPDK_ALLOW_AZURE_MULTIWORKER=1 DPDK_ALLOW_RETALESS_MULTI_QUEUE=1 DPDK_PERF_MODE=aggressive \
    ASTF_SHARDED_TARGET_PORTS=9000-9015
  ```

### FC) Before/after completed-CPS table (baseline vs new binary)
- Baseline reference artifact:
  - `cloud-tests/azure/artifacts/cps-matrix-20260317T-d4all-32src-sharded-retaless-obsv-fixed`

| workers | offered CPS | baseline completed CPS | new completed CPS | delta | baseline success_ratio | new success_ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `64` | `32000` | `12148.65` | `11848.94` | `-299.71` (`-2.47%`) | `0.6997` | `0.6880` |
| `96` | `48000` | `10084.54` | `10659.67` | `+575.14` (`+5.70%`) | `0.4173` | `0.4348` |
| `128` | `64000` | `10236.32` | `9755.67` | `-480.65` (`-4.70%`) | `0.3559` | `0.3412` |

Notes:
- `w96` new datapoint above uses `...-w96-retry` artifact.
- Firewall CPU remained essentially unchanged (`~74.4-74.5%` avg), with consumer/upstream still low.

### FD) Signals on limiting component (PMD vs elsewhere)
- PMD/queue-layer evidence does **not** indicate primary loss source:
  - `dpdk_rx_dropped_total` delta = `0` at `w64/w96/w128`
  - `dpdk_rx_packets_queue_total` deltas are balanced across queues (no queue starvation signature)
- Flow-state/handshake evidence points to dataplane state retention/eviction path:
  - `dp_tcp_handshake_drops_total{phase="synack",reason="flow_missing"}` jumped from near-zero baseline to:
    - `w64`: `18 -> 11928`
    - `w96`: `19 -> 15393`
    - `w128`: `17 -> 20995`
  - flow average lifetime collapsed vs baseline:
    - baseline: `~14.7s-22.6s`
    - new: `~0.76s-1.14s`
  - with load, SYN->SYNACK conversion worsens:
    - `w64`: `synack_in/syn_in = 0.543`
    - `w96`: `0.462`
    - `w128`: `0.437`

### FE) Current conclusion after this retest
- Current limiting component remains **firewall dataplane flow-state/handshake path**, not DPDK PMD queue drops.
- New default SYN-only `3s` timeout is likely too aggressive for this workload shape: it substantially increases `synack/flow_missing` drops and hurts completed CPS at higher offered load (`w128`), even though `w96` showed a one-point gain.
- Expected next gain:
  - isolate hash hot-path effect from timeout policy by keeping this binary and running:
    - `NEUWERK_FLOW_INCOMPLETE_TCP_SYN_SENT_IDLE_TIMEOUT_SECS=300` (restore old retention behavior),
    - then a moderate sweep (`20/45/90`) with `REPEATS>=2`,
  - accept changes only if completed CPS improves at `w96` and `w128` together with non-regressing success ratio.

## 2026-03-17 SYN-only Timeout Default Reverted (Opt-in) + Phase Metrics Retest

### FF) Code behavior verified
- Verified in source before build:
  - `src/dataplane/flow.rs` now defaults SYN-only timeout to `incomplete_tcp_idle_timeout_secs` unless `NEUWERK_FLOW_INCOMPLETE_TCP_SYN_SENT_IDLE_TIMEOUT_SECS` is explicitly set.
  - mixed 32-bit flow hash (`flow_hash` + `finalize_hash32`) remains in the hot path.
  - close-age phase labels emitted via `handshake_phase.label()` (`unknown/syn_only/synack_seen/completed`).

### FG) Build, rollout, and health
- Build:
  - `make build.release`
  - local md5: `46aa6dfe162ff7db31909d39666ddcf4`
  - local sha256: `bc31b1f3647e632dd96335463e4350452dd80545a34dbbced7478148457eda4f`
- Rolled out to all firewalls (`10.20.1.4`, `10.20.1.5`, `10.20.1.7`) at `/usr/local/bin/neuwerk`, restarted `neuwerk.service`.
- Verified all remote md5 values match `46aa6dfe162ff7db31909d39666ddcf4`.
- Verified no explicit SYN-only timeout override in service environment (`NEUWERK_FLOW_INCOMPLETE_TCP_SYN_SENT_IDLE_TIMEOUT_SECS` unset).
- `make -C cloud-tests/azure health` passed.

### FH) CPS retest command and artifact
- Command:
  ```bash
  make -C cloud-tests/azure cps.matrix.trex.astf.sharded \
    ARTIFACT_DIR=artifacts/cps-matrix-20260317T222056Z-synsent-defaultoptin-retest \
    WORKERS_LIST=64,96,128 RUN_SECONDS=6 WARMUP_SECONDS=2 REPEATS=1 TARGET_PORT=9000 \
    CPS_TREX_ASTF_SERVER_IP_MODE=target_host \
    CPS_TREX_ASTF_CPS_PER_WORKER=500 CPS_TREX_ASTF_MAX_CPS=400000 \
    DPDK_ALLOW_AZURE_MULTIWORKER=1 DPDK_ALLOW_RETALESS_MULTI_QUEUE=1 DPDK_PERF_MODE=aggressive \
    ASTF_SHARDED_TARGET_PORTS=9000-9015
  ```
- Artifact:
  - `cloud-tests/azure/artifacts/cps-matrix-20260317T222056Z-synsent-defaultoptin-retest`

### FI) Before/after table (baseline, previous 3s default, new opt-in default)

| workers | baseline completed CPS | prior 3s-default CPS | new opt-in-default CPS | new vs 3s | new vs baseline | prior 3s `synack/flow_missing` | new `synack/flow_missing` |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `64` | `12148.65` | `11848.94` | `12099.27` | `+250.33` | `-49.38` | `11928` | `12` |
| `96` | `10084.54` | `10659.67` | `10175.94` | `-483.73` | `+91.40` | `15393` | `13` |
| `128` | `10236.32` | `9755.67` | `9872.83` | `+117.16` | `-363.48` | `20995` | `4` |

- Success ratio (baseline -> 3s default -> new opt-in default):
  - `w64`: `0.699745 -> 0.688031 -> 0.687958`
  - `w96`: `0.417276 -> 0.434759 -> 0.416162`
  - `w128`: `0.355908 -> 0.341180 -> 0.346360`

### FJ) Observability readout from this run
- PMD/queue path still not primary limiter:
  - `dpdk_rx_dropped_total=0` at `w64/w96/w128`
  - queue deltas remain balanced.
- Handshake-state evidence improved sharply vs prior 3s-default run:
  - `dp_tcp_handshake_drops_total{phase="synack",reason="flow_missing"}` dropped from tens of thousands to near-zero (`12/13/4`).
- In this 6s test shape, close-age `reason="idle_timeout"` counts are empty (expected with long default timeouts), so this run cannot directly classify idle-timeout closes by phase.
- `reason="tcp_rst"` close-age phase counts show most closes in `completed`, with a smaller `synack_seen` bucket.

### FK) Updated conclusion
- Reverting SYN-only `3s` to opt-in default removes the pathological `synack/flow_missing` explosion while keeping hash hot-path gains.
- This supports your updated diagnosis: the dominant issue is handshake flow-state retention/churn behavior, not PMD RX drops.
- To directly answer the idle-close phase question (`syn_only` vs `synack_seen`) we need either:
  - a longer run that exceeds idle timeout horizon, or
  - a controlled temporary timeout override for observation-only experiments.

## 2026-03-17 Longer Run (60s) on Opt-in SYN-only Timeout Build

### FL) Command and artifact
- Command:
  ```bash
  make -C cloud-tests/azure cps.matrix.trex.astf.sharded \
    ARTIFACT_DIR=artifacts/cps-matrix-20260317T-long60-synsent-defaultoptin \
    WORKERS_LIST=64,96,128 RUN_SECONDS=60 WARMUP_SECONDS=5 REPEATS=1 TARGET_PORT=9000 \
    CPS_TREX_ASTF_SERVER_IP_MODE=target_host \
    CPS_TREX_ASTF_CPS_PER_WORKER=500 CPS_TREX_ASTF_MAX_CPS=400000 \
    DPDK_ALLOW_AZURE_MULTIWORKER=1 DPDK_ALLOW_RETALESS_MULTI_QUEUE=1 DPDK_PERF_MODE=aggressive \
    ASTF_SHARDED_TARGET_PORTS=9000-9015
  ```
- Artifact:
  - `cloud-tests/azure/artifacts/cps-matrix-20260317T-long60-synsent-defaultoptin`

### FM) Long-run results

| workers | attempted connects | successful connects | completed CPS | success_ratio | failed connects |
| --- | ---: | ---: | ---: | ---: | ---: |
| `64` | `1,920,001` | `791,647` | `11525.30` | `0.4123` | `1,128,354` |
| `96` | `2,880,001` | `982,150` | `13524.57` | `0.3410` | `1,897,851` |
| `128` | `3,643,428` | `1,064,316` | `13738.13` | `0.2921` | `2,579,112` |

- Firewall CPU remained near prior ceiling (`~74.1-74.2%` avg, max ~`75.6-75.9%`).

### FN) Longer-run handshake evidence
- PMD drops still absent:
  - `dpdk_rx_dropped_total = 0` for all `w64/w96/w128`.
- `synack/flow_missing` remains low compared to the prior 3s-default regression:
  - `w64`: `1144`
  - `w96`: `632`
  - `w128`: `599`
- New close-age phase view (`reason="idle_timeout"`):
  - `w64`: none observed
  - `w96`: none observed
  - `w128`: `syn_only=675`, `synack_seen=19`

### FO) Interpretation update
- The longer run continues to support that the main issue is handshake-state churn in the dataplane flow table, not PMD RX drops.
- With your opt-in timeout default, the catastrophic `synack/flow_missing` behavior is gone.
- The new phase labels now show that when idle-timeout closes do appear in a longer run, they are dominated by `syn_only` (not `synack_seen`) in this shape (`w128`).

## 2026-03-17 Syn-only Side-Structure Feasibility Review

### FP) What the current dataplane path does
- In SNAT mode, outbound SYN on flow miss currently allocates a full `FlowEntry` and inserts into `FlowTable` before NAT/rewrite.
- Inbound SYNACK path resolves reverse NAT first, then requires a `FlowTable` hit for the original flow; miss increments `dp_tcp_handshake_drops_total{phase="synack",reason="flow_missing"}` and drops.
- All of this happens under the state-shard mutex (`src/runtime/dpdk/run.rs`, `lock_state_shard_blocking`), so per-packet flow-table work contributes directly to lock hold time.

### FQ) Signals relevant to a syn-only structure
- From the 60s run (`cps-matrix-20260317T-long60-synsent-defaultoptin`):
  - large half-open gap remains:
    - `w128`: `syn_in=1,852,007`, `synack_in=1,127,962` (delta `724,045`)
  - per-node active flow growth during run is substantial:
    - `10.20.1.4`: `251,599 -> 317,413` (`+65,814`)
    - `10.20.1.5`: `246,446 -> 315,586` (`+69,140`)
    - `10.20.1.7`: `255,173 -> 322,804` (`+67,631`)
  - PMD drops still zero.
  - `synack/flow_missing` stays low after the default revert (hundreds over 60s, not tens of thousands).
- Probe profile is not pathological:
  - flow lookup miss p95 is around `~8`, p99 `~14-17`
  - hit p95 around `~3.3-4.9`
- Interpretation:
  - a cheaper syn-only structure is plausible for reducing churn/occupancy and lock hold costs,
  - but current evidence does not indicate a likely “2x success ratio” quick win from table mechanics alone.

### FR) Recommended design (medium-sized, targeted)
- Add a side `SynOnlyTable` (per shard, under same shard lock initially):
  - key: `FlowKey`
  - value (compact): `last_seen`, `first_seen`, `policy_generation`, `source_group` (compact ref), `intercept_requires_service`
- Transition rules:
  - outbound new SYN: insert/update `SynOnlyTable` instead of full `FlowTable` entry
  - inbound SYNACK:
    - if full flow hit: existing behavior
    - if full flow miss + syn-only hit: promote to full `FlowEntry` and continue
  - outbound ACK-only/non-SYN packet on syn-only hit: promote then continue
  - any close/remove path: remove from whichever table owns the flow
- Timeout:
  - keep syn-only timeout short and explicit (separate env), independent of full-flow idle timeout.

### FS) Observability needed before/with implementation
- Add:
  - `dp_syn_only_active_flows{worker}`
  - `dp_syn_only_promotions_total{worker,reason}` (e.g. `synack`, `ack`)
  - `dp_syn_only_evictions_total{worker,reason}` (`idle_timeout`, `replaced`, `promoted`)
  - `dp_syn_only_lookup_total{worker,result}` for miss/hit cost tracking
- Keep existing handshake/drop metrics to compare against control.

### FT) Risk/benefit assessment
- Benefit likely:
  - lower full-flow table occupancy from half-open SYN churn,
  - somewhat lower probe cost / lock hold time under high offered CPS.
- Main risks:
  - handshake edge-case regressions during promotion paths,
  - policy generation/source-group consistency during promotion,
  - complexity across SNAT and no-SNAT paths.
- Practical expectation:
  - likely incremental gain, not a step-function throughput jump, unless current lock-hold pressure is heavily dominated by syn-only inserts on this specific traffic mix.

## 2026-03-18 Syn-only Side-Structure Implementation (Feature-Flagged)

### FU) Implemented dataplane behavior
- Added a feature-gated syn-only side table to `EngineState`:
  - `syn_only: SynOnlyTable`
  - `syn_only_enabled: bool` from `NEUWERK_DPDK_SYN_ONLY_TABLE`
- Outbound SNAT path (`src/dataplane/engine/packet_path.rs`):
  - On flow-miss SYN and policy allow/pending-tls, insert/update syn-only state instead of full `FlowTable` entry when enabled.
- Inbound SNAT path:
  - On SYNACK with flow-table miss, attempt `syn_only.promote(...)`; if hit, materialize full `FlowEntry` and continue normal path.
- Close/cleanup paths:
  - `remove_flow_state(...)` now removes syn-only ownership when no full flow exists.
  - Housekeeping eviction now evicts syn-only entries and tears down NAT state for those keys.

### FV) Added observability
- Added new metrics:
  - `dp_syn_only_active_flows{worker}` (gauge)
  - `dp_syn_only_lookup_total{worker,result}`
  - `dp_syn_only_promotions_total{worker,reason}`
  - `dp_syn_only_evictions_total{worker,reason}`
- Wired into CPS artifact metric grouping in:
  - `cloud-tests/common/run-cps-matrix.sh` group `syn_only_by_worker`

### FW) Build/test validation
- Validation commands run:
  - `cargo check -q`
  - `cargo test -q syn_only_table -- --nocapture`
  - `cargo test -q dataplane::engine::tests:: -- --nocapture`
  - `make build.release`
- Release binary:
  - `target/release/neuwerk`
  - `md5: 552f0b7ce4210d0de392b8ebcc3b3d50`

### FX) Next A/B command (same infra, one change at a time)
- Control (feature off):
  ```bash
  make -C cloud-tests/azure cps.matrix.trex.astf \
    WORKERS_LIST=64,96,128 RUN_SECONDS=6 WARMUP_SECONDS=2 REPEATS=1 TARGET_PORT=9000 \
    CPS_TREX_ASTF_SERVER_IP_MODE=target_host CPS_TREX_ASTF_CPS_PER_WORKER=500 CPS_TREX_ASTF_MAX_CPS=400000
  ```

## 2026-03-18 A/B Retest on New Binary (Control vs Syn-only Feature)

### FY) Deployment + run commands executed
- Deployed `target/release/neuwerk` to all firewall nodes (`10.20.1.4`, `10.20.1.5`, `10.20.1.7`) and restarted service.
- Binary checksum on all firewalls after deploy:
  - `552f0b7ce4210d0de392b8ebcc3b3d50`
- Control run:
  ```bash
  make -C cloud-tests/azure cps.matrix.trex.astf \
    ARTIFACT_DIR=artifacts/cps-matrix-20260318T-synonly-ab-control \
    WORKERS_LIST=64,96,128 RUN_SECONDS=6 WARMUP_SECONDS=2 REPEATS=1 TARGET_PORT=9000 \
    CPS_TREX_ASTF_SERVER_IP_MODE=target_host CPS_TREX_ASTF_CPS_PER_WORKER=500 CPS_TREX_ASTF_MAX_CPS=400000 \
    DPDK_ALLOW_AZURE_MULTIWORKER=1 DPDK_ALLOW_RETALESS_MULTI_QUEUE=1 DPDK_SYN_ONLY_TABLE=0
  ```
- Treatment run:
  ```bash
  make -C cloud-tests/azure cps.matrix.trex.astf \
    ARTIFACT_DIR=artifacts/cps-matrix-20260318T-synonly-ab-treatment \
    WORKERS_LIST=64,96,128 RUN_SECONDS=6 WARMUP_SECONDS=2 REPEATS=1 TARGET_PORT=9000 \
    CPS_TREX_ASTF_SERVER_IP_MODE=target_host CPS_TREX_ASTF_CPS_PER_WORKER=500 CPS_TREX_ASTF_MAX_CPS=400000 \
    DPDK_ALLOW_AZURE_MULTIWORKER=1 DPDK_ALLOW_RETALESS_MULTI_QUEUE=1 DPDK_SYN_ONLY_TABLE=1
  ```

### FZ) Before/after (completed handshakes)

| workers | completed CPS control | completed CPS treatment | delta | success ratio control | success ratio treatment | synack flow_missing control | synack flow_missing treatment |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `64` | `11848.34` | `11449.20` | `-399.14` (`-3.37%`) | `0.6803` | `0.6690` | `7` | `18` |
| `96` | `9715.56` | `9966.40` | `+250.84` (`+2.58%`) | `0.3965` | `0.4078` | `2` | `8` |
| `128` | `9268.19` | `9277.24` | `+9.06` (`+0.10%`) | `0.3203` | `0.3210` | `6` | `2` |

### GA) A/B interpretation
- The syn-only side-structure shows a small positive effect at higher worker count (`w96`), near-neutral at `w128`, and regression at `w64` in this short-run shape.
- `w128` remains generator-limited in both control and treatment (`trex_astf_err_c_nf_throttled`, `trex_astf_err_flow_overflow`), so it is not a clean dataplane-only comparison point.
- Net: this change is not a step-function gain for completed CPS in the current setup; impact is modest and tier-dependent.

### GB) Observability note from this retest
- `dp_syn_only_*` series were not present in the collected labeled delta groups for these runs, so promotion/eviction counts were not directly visible in artifacts despite the code-path implementation.
- Existing handshake metrics were still available and used for comparison (`syn_in`, `synack_in`, `completed`, `synack/flow_missing`).
- Treatment (feature on):
  ```bash
  make -C cloud-tests/azure cps.matrix.trex.astf \
    DPDK_SYN_ONLY_TABLE=1 \
    WORKERS_LIST=64,96,128 RUN_SECONDS=6 WARMUP_SECONDS=2 REPEATS=1 TARGET_PORT=9000 \
    CPS_TREX_ASTF_SERVER_IP_MODE=target_host CPS_TREX_ASTF_CPS_PER_WORKER=500 CPS_TREX_ASTF_MAX_CPS=400000
  ```

## 2026-03-18 Direct-to-Upstream CPS (Firewall Bypassed)

### GC) Goal
- Measure ASTF CPS to upstream host with the firewall dataplane removed from the forwarding path.

### GD) Route bypass + restore commands used
- Consumer->upstream route switched to local VNet routing:
  ```bash
  az network route-table route create \
    -g neuwerk-azure-e2e \
    --route-table-name neuwerk-e2e-5b2hop-consumer-rt \
    -n consumer-to-upstream \
    --address-prefix 10.20.4.0/24 \
    --next-hop-type VnetLocal
  ```
- Upstream->consumer route switched to local VNet routing:
  ```bash
  az network route-table route create \
    -g neuwerk-azure-e2e \
    --route-table-name neuwerk-e2e-5b2hop-upstream-rt \
    -n upstream-to-consumer \
    --address-prefix 10.20.3.0/24 \
    --next-hop-type VnetLocal
  ```
- CPS matrix command (same workload shape):
  ```bash
  make -C cloud-tests/azure cps.matrix.trex.astf \
    WORKERS_LIST=64,96,128 RUN_SECONDS=6 WARMUP_SECONDS=2 REPEATS=1 TARGET_PORT=9000 \
    CPS_TREX_ASTF_SERVER_IP_MODE=target_host CPS_TREX_ASTF_CPS_PER_WORKER=500 CPS_TREX_ASTF_MAX_CPS=400000 \
    DPDK_ALLOW_AZURE_MULTIWORKER=1 DPDK_ALLOW_RETALESS_MULTI_QUEUE=1
  ```
- Routes restored to firewall dataplane LB (`VirtualAppliance -> 10.20.2.10`) after run:
  ```bash
  az network route-table route create \
    -g neuwerk-azure-e2e \
    --route-table-name neuwerk-e2e-5b2hop-consumer-rt \
    -n consumer-to-upstream \
    --address-prefix 10.20.4.0/24 \
    --next-hop-type VirtualAppliance \
    --next-hop-ip-address 10.20.2.10

  az network route-table route create \
    -g neuwerk-azure-e2e \
    --route-table-name neuwerk-e2e-5b2hop-upstream-rt \
    -n upstream-to-consumer \
    --address-prefix 10.20.3.0/24 \
    --next-hop-type VirtualAppliance \
    --next-hop-ip-address 10.20.2.10
  ```

### GE) Artifacts
- Direct-path matrix artifact:
  - `/home/moritz/dev/neuwerk-rs/firewall/cloud-tests/azure/artifacts/cps-matrix-20260317T233430Z`
- Route-toggle + runner log:
  - `/home/moritz/dev/neuwerk-rs/firewall/cloud-tests/azure/artifacts/cps-direct-upstream-20260317T233424Z.log`

### GF) Results (completed handshakes / upstream passive-open CPS)

| workers | firewall path (control) | direct to upstream (bypass firewall) | delta |
| --- | ---: | ---: | ---: |
| `64` | `11848.34` | `2915.19` | `-8933.15` (`-75.40%`) |
| `96` | `9715.56` | `2686.89` | `-7028.66` (`-72.34%`) |
| `128` | `9268.19` | `2153.83` | `-7114.36` (`-76.76%`) |

### GG) Interpretation
- This direct-path experiment does not indicate the firewall dataplane is the limiting factor in this test shape.
- Bypassing the firewall reduced completed handshake CPS by ~72-77% versus the recent firewall-path control run.
- `w128` remained generator-limited in both firewall and direct runs.
- During direct-path runs, firewall dataplane traffic counters stayed near zero, consistent with successful path bypass.

## 2026-03-18 Clean Direct Baseline (Consumer Upstream-NIC Source)

### GH) Why this baseline was needed
- The prior `cps.matrix` direct attempt used bound source IPs from `10.20.3.0/24` and produced `TimeoutError` on all connects (both firewall and direct route modes), so it was not a valid direct baseline.
- Manual verification showed unbound connects succeeded because Linux selected consumer `eth1` source `10.20.4.5` (same subnet as upstream `10.20.4.4`).

### GI) Clean direct command executed
```bash
make -C cloud-tests/azure cps.matrix \
  ARTIFACT_DIR=artifacts/cps-matrix-20260317T235509Z-direct-clean-src10.20.4.5-python \
  WORKERS_LIST=16,32,64,96,128 \
  RUN_SECONDS=6 WARMUP_SECONDS=2 REPEATS=1 TARGET_PORT=9000 \
  CPS_CLIENT_BACKEND=python CPS_CLIENT_MODE=process CPS_CLOSE_MODE=rst CONNECT_TIMEOUT_MS=500 \
  CPS_SOURCE_IPS_CSV_OVERRIDE=10.20.4.5 \
  DPDK_ALLOW_AZURE_MULTIWORKER=1 DPDK_ALLOW_RETALESS_MULTI_QUEUE=1
```

### GJ) Artifacts
- `/home/moritz/dev/neuwerk-rs/firewall/cloud-tests/azure/artifacts/cps-matrix-20260317T235509Z-direct-clean-src10.20.4.5-python`
- `/home/moritz/dev/neuwerk-rs/firewall/cloud-tests/azure/artifacts/cps-direct-clean-src10.20.4.5-20260317T235509Z.log`

### GK) Clean direct baseline results (completed handshakes)

| workers | completed CPS (client) | completed CPS (upstream passive-opens) | success ratio | status |
| --- | ---: | ---: | ---: | --- |
| `16` | `15112.67` | `15113.67` | `0.9991` | `pass` |
| `32` | `14463.81` | `14465.06` | `0.9977` | `pass` |
| `64` | `14972.79` | `14973.79` | `0.9966` | `pass` |
| `96` | `14787.12` | `14788.28` | `0.9948` | `pass` |
| `128` | `14934.52` | `14935.52` | `0.9945` | `pass` |

### GL) Interpretation
- This is a valid clean direct baseline for consumer->upstream traffic without firewall traversal, and it is stable around `~14.5k-15.1k` completed CPS in this shape.
- It uses one direct source IP (`10.20.4.5`) on consumer `eth1`; tuple headroom is therefore lower than the 32-IP firewall-path source setup.

## 2026-03-18 CPS Setup Validation: ASTF Source-Interface Bug

### GM) Limiting setup issue identified
- The ASTF CPS harness allowed silent source-IP fallback inside `trex_cps_astf_driver.py`: when `CPS_SOURCE_IPS_CSV_OVERRIDE` contained IPs not on the selected client interface, the driver quietly fell back to the default interface pool.
- In this topology, that converted intended direct-upstream tests into mixed/wrong path tests (observed as non-zero firewall flow-opens in “direct” runs).

### GN) Fix implemented
- `cloud-tests/common/trex/trex_cps_astf_driver.py`
  - Added strict source-IP/interface validation (`CPS_TREX_ASTF_STRICT_SOURCE_IP_MATCH`, default `1`).
  - If requested source IPs do not exist on the selected client interface, the driver now fails with an explicit error instead of silently falling back.
  - Added `requested_source_ips` to ASTF diagnostics payload.
- `cloud-tests/common/run-cps-matrix.sh`
  - Added consumer inventory of all interface IPv4 pools (`interface_ipv4s`).
  - Added per-consumer ASTF client-interface resolution based on effective source IP pool.
  - Added pass-through of `CPS_TREX_ASTF_CLIENT_IFACE`, `CPS_TREX_ASTF_SERVER_IFACE`, `CPS_TREX_ASTF_STRICT_SOURCE_IP_MATCH`.
  - Added resolved `astf_client_iface` to consumer artifact JSON for auditability.
- `cloud-tests/azure/Makefile` and `cloud-tests/azure/scripts/cps-matrix.sh`
  - Added pass-through for ASTF interface controls and source-route control variables so `make ... VAR=...` style invocations work as expected.

### GO) Re-test commands
```bash
# Intended direct path (eth1 source), firewall bypass; verify harness uses eth1 and firewall opens stay zero.
make -C cloud-tests/azure cps.matrix.trex.astf \
  ARTIFACT_DIR=cloud-tests/azure/artifacts/cps-matrix-20260318T-investigate-direct-eth1-fixed \
  WORKERS_LIST=64,96,128 RUN_SECONDS=6 WARMUP_SECONDS=2 REPEATS=1 TARGET_PORT=9000 \
  CPS_TREX_ASTF_SERVER_IP_MODE=target_host CPS_TREX_ASTF_CPS_PER_WORKER=500 CPS_TREX_ASTF_MAX_CPS=400000 \
  CPS_SOURCE_IPS_CSV_OVERRIDE=10.20.4.5 CPS_MIN_SOURCE_IP_COUNT_WARN=1 CPS_VALIDATE_SOURCE_ROUTE=0

# Firewall path (target_host via eth0/source-route policy)
make -C cloud-tests/azure cps.matrix.trex.astf \
  ARTIFACT_DIR=cloud-tests/azure/artifacts/cps-matrix-20260318T-investigate-fw-routed-fixed \
  WORKERS_LIST=64,96,128 RUN_SECONDS=6 WARMUP_SECONDS=2 REPEATS=1 TARGET_PORT=9000 \
  CPS_TREX_ASTF_SERVER_IP_MODE=target_host CPS_TREX_ASTF_CPS_PER_WORKER=500 CPS_TREX_ASTF_MAX_CPS=400000 \
  CPS_VALIDATE_SOURCE_ROUTE=1 CPS_AUTO_FIX_SOURCE_ROUTE=1
```

### GP) Evidence and result comparison
- Artifacts:
  - Pre-fix “direct” run (actually falling back to `eth0`):  
    `/home/moritz/dev/neuwerk-rs/firewall/cloud-tests/azure/artifacts/cps-matrix-20260318T-investigate-direct-eth1-src45`
  - Fixed direct run (true `eth1` source):  
    `/home/moritz/dev/neuwerk-rs/firewall/cloud-tests/azure/artifacts/cps-matrix-20260318T-investigate-direct-eth1-fixed`
  - Fixed firewall-path run:  
    `/home/moritz/dev/neuwerk-rs/firewall/cloud-tests/azure/artifacts/cps-matrix-20260318T-investigate-fw-routed-fixed`

| run | w64 client iface | w64 source ips | w64 firewall flow-opens cps | w64 upstream passive-open cps | w64 client cps |
| --- | --- | ---: | ---: | ---: | ---: |
| pre-fix “direct” (`...src45`) | `eth0` (fallback) | `32` | `9212.541` | `1775.208` | `4322.216` |
| fixed direct (`...eth1-fixed`) | `eth1` | `1` | `0.0` | `1746.514` | `7824.427` |
| fixed firewall (`...fw-routed-fixed`) | `eth0` | `32` | `12114.922` | `1640.426` | `4313.038` |

### GQ) Conclusion
- A real test-setup bug was present and is now fixed: ASTF no longer silently falls back to the wrong source interface.
- Direct-vs-firewall path interpretation is now trustworthy (path attribution is explicit in artifacts via `client_iface`, `source_ips`, and firewall flow-opens).
- After setup fix, the dominant throughput gap is no longer attributable to path mis-selection; it is in handshake completion quality (`upstream passive-open cps` remains low and far below offered/attempted rates in both shapes), which should now be investigated as a dataplane/upstream handshake behavior issue rather than harness ambiguity.

## 2026-03-18 Multi-Source Direct Baseline + Synchronized Packet Capture

### GR) Consumer upstream-NIC source-pool expansion
- Goal: remove single-source-IP tuple pressure from direct baseline and test with a larger valid `eth1` source pool.
- Azure NIC changes on `neuwerk-e2e-5b2hop-consumer-0-trex-nic`:
  - added secondary IP configs for `10.20.4.6-9,11-35`.
  - `10.20.4.10` is reserved by upstream ILB frontend (`upstream-fe`) and cannot be used.
- Guest-side temporary activation for this live run:
  - `sudo ip addr add 10.20.4.X/24 dev eth1` for the added addresses.

### GS) Direct retest with multi-source (`eth1`)
- Command:
  ```bash
  SOURCES=$(python3 - <<'PY'
  print(','.join(f'10.20.4.{i}' for i in range(11,36)))
  PY
  )

  make -C cloud-tests/azure cps.matrix.trex.astf \
    ARTIFACT_DIR=cloud-tests/azure/artifacts/cps-matrix-20260318T-direct-eth1-25src-w64 \
    WORKERS_LIST=64 RUN_SECONDS=6 WARMUP_SECONDS=2 REPEATS=1 TARGET_PORT=9000 \
    CPS_TREX_ASTF_SERVER_IP_MODE=target_host CPS_TREX_ASTF_CPS_PER_WORKER=500 CPS_TREX_ASTF_MAX_CPS=400000 \
    CPS_SOURCE_IPS_CSV_OVERRIDE="$SOURCES" CPS_MIN_SOURCE_IP_COUNT_WARN=1 CPS_VALIDATE_SOURCE_ROUTE=0
  ```
- Artifact:
  - `/home/moritz/dev/neuwerk-rs/firewall/cloud-tests/azure/artifacts/cps-matrix-20260318T-direct-eth1-25src-w64`
- Observed (`w64`):
  - `client_iface=eth1`
  - `source_ip_count=25` (`10.20.4.11-10.20.4.35`)
  - `firewall dp flow-opens = 0`
  - `client cps = 5152.17`
  - `upstream passive-open cps = 1974.18`
  - `success_ratio = 0.3174`

### GT) Firewall-path run for capture (`w64`)
- Command:
  ```bash
  make -C cloud-tests/azure cps.matrix.trex.astf \
    ARTIFACT_DIR=cloud-tests/azure/artifacts/cps-matrix-20260318T-fw-routed-w64-pcap \
    WORKERS_LIST=64 RUN_SECONDS=6 WARMUP_SECONDS=2 REPEATS=1 TARGET_PORT=9000 \
    CPS_TREX_ASTF_SERVER_IP_MODE=target_host CPS_TREX_ASTF_CPS_PER_WORKER=500 CPS_TREX_ASTF_MAX_CPS=400000 \
    CPS_VALIDATE_SOURCE_ROUTE=1 CPS_AUTO_FIX_SOURCE_ROUTE=1
  ```
- Artifact:
  - `/home/moritz/dev/neuwerk-rs/firewall/cloud-tests/azure/artifacts/cps-matrix-20260318T-fw-routed-w64-pcap`
- Observed (`w64`):
  - `client cps = 4438.09`
  - `upstream passive-open cps = 1883.67`
  - `success_ratio = 0.2670`
  - `dpdk_rx_dropped_total delta = 0`, `dpdk_tx_dropped_total delta = 0`

### GU) Synchronized packet capture commands and artifacts
- Capture commands used (started before matrix run):
  ```bash
  # Consumer
  ssh_jump ... 10.20.3.4 \
    "sudo timeout 70 tcpdump -n -U -i eth0 -s 128 -w /tmp/cps_fw_w64_consumer_eth0.pcap 'tcp port 9000 and host 10.20.4.4'"

  # Upstream
  ssh_jump ... 10.20.4.4 \
    "sudo timeout 70 tcpdump -n -U -i eth0 -s 128 -w /tmp/cps_fw_w64_upstream_eth0.pcap 'tcp port 9000'"
  ```
- Copied artifacts:
  - `/home/moritz/dev/neuwerk-rs/firewall/cloud-tests/azure/artifacts/cps-matrix-20260318T-fw-routed-w64-pcap/pcap/consumer_eth0.pcap`
  - `/home/moritz/dev/neuwerk-rs/firewall/cloud-tests/azure/artifacts/cps-matrix-20260318T-fw-routed-w64-pcap/pcap/upstream_eth0.pcap`
  - `/home/moritz/dev/neuwerk-rs/firewall/cloud-tests/azure/artifacts/cps-matrix-20260318T-fw-routed-w64-pcap/pcap/analysis.json`

### GV) Packet-level evidence summary
- Consumer (`eth0`) saw:
  - SYN out packets: `149,181`
  - SYN-ACK in packets: `64,731`
  - Stream view: `64,730` SYN streams, `64,730` SYN-ACK streams, `64,000` ACK-out streams.
- Upstream (`eth0`) saw:
  - SYN in packets: `152,587`
  - SYN-ACK out packets: `184,771`
  - Stream view: `131,151` SYN streams, `137,972` SYN-ACK streams, `89,413` ACK-in streams.
- Derived:
  - SYN-ACK packets seen at consumer vs sent by upstream: `35.03%`
  - Upstream SYN stream count vs consumer SYN stream count: `2.026x`

### GW) Updated conclusion from this step
- The issue is not explained by PMD RX/TX drops (`dpdk_rx_dropped_total=0`, `dpdk_tx_dropped_total=0` in this run).
- The packet trace indicates substantial handshake-path distortion between consumer and upstream on the firewall traversal path:
  - upstream observes ~2x SYN stream cardinality vs consumer capture,
  - and a large share of upstream SYN-ACK traffic does not reappear at consumer.
- This points to a middle-path state/churn behavior (flow-state/NAT/ownership/retry dynamics in the firewall path) rather than a raw NIC drop bottleneck.
