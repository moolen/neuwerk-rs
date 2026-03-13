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
  - propagates both to service drop-in + `/etc/neuwerk/firewall.env`
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
- Attempting to roll forward with local `target/release/firewall` introduced an ABI mismatch on Azure nodes:
  - runtime error: `librte_eal.so.26: cannot open shared object file`.
  - local hash was `460cec7f...` and was not deploy-safe for this image.
- Recovery path:
  - extracted known-good running binary from healthy node (`sha256 c14d9a07229572640f5a5a5c6a58ff74a54bf138bc4dce055b97353f87acb7ad`),
  - republished that exact artifact to Terraform storage blob via `firewall_binary_path`,
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
