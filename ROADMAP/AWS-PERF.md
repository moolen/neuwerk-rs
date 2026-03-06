# AWS GWLB/GENEVE Performance Worklog

Date: 2026-03-03
Region/AZ: eu-central-1 / eu-central-1a
Scope: DPDK dataplane + AWS GWLB/GENEVE path (single AZ, desired=1, no ASG lifecycle logic)

## Environment used

- Firewall / consumer / upstream instances: `c6in.xlarge` (Intel, 4 vCPU)
- Jumpbox: `t3.small`
- Traffic path: consumer -> GWLB endpoint -> firewall (DPDK) -> upstream
- Firewall dataplane mode: `dpdk`
- Encapsulation: `geneve` (UDP/6081)
- Runtime knobs (final):
  - `NEUWERK_DPDK_WORKERS=0` (auto -> 4 workers)
  - `NEUWERK_DPDK_STATE_SHARDS=32`
  - `NEUWERK_DPDK_HOUSEKEEPING_INTERVAL_PACKETS=64`
  - `NEUWERK_DPDK_HOUSEKEEPING_INTERVAL_US=250`
  - `NEUWERK_DPDK_MBUF_DATA_ROOM=4096`
  - `NEUWERK_DPDK_OVERLAY_DEBUG=0`

## What was tried and measured

## 2026-03-03 update: state-shard guard pinning A/B (same host, same matrix)

Goal:
- Validate whether pinned state-shard lock guards improve throughput enough to justify lock-hold tradeoffs.

Code/runtime changes:
- Added guarded shard-lock pinning path in DPDK worker loop (see `src/main.rs`), with env knobs:
  - `NEUWERK_DPDK_PIN_STATE_SHARD_GUARD`
  - `NEUWERK_DPDK_PIN_STATE_SHARD_BURST` (default `64`)
- After A/B, changed code default to **off**:
  - `NEUWERK_DPDK_PIN_STATE_SHARD_GUARD` now defaults to `false` when unset.

Bench setup:
- Same deployed AWS bench (`c6in.xlarge` firewall/consumer/upstream, single AZ).
- Same matrix for both modes: `iperf3 -t 20`, `P=1/4/16`, `5` runs per `P`.
- Artifacts:
  - Off: `cloud-tests/aws/artifacts/iperf-matrix-pinning-off-20260303T191552Z.csv`
  - On:  `cloud-tests/aws/artifacts/iperf-matrix-pinning-on-20260303T192151Z.csv`

Results summary (Gbps sender):

Pinning off:
- `P=1`: min `1.242`, med `1.292`, mean `1.311`, p95 `1.451`, max `1.451`
- `P=4`: min `1.942`, med `2.148`, mean `2.345`, p95 `2.826`, max `2.826`
- `P=16`: min `2.560`, med `2.578`, mean `2.582`, p95 `2.604`, max `2.604`
- Retransmits (avg): `P=1 365.6`, `P=4 1072.0`, `P=16 1602.6`
- Lock contention counter delta: `+783434`

Pinning on:
- `P=1`: min `1.182`, med `1.271`, mean `1.256`, p95 `1.291`, max `1.291`
- `P=4`: min `2.207`, med `2.718`, mean `2.548`, p95 `2.822`, max `2.822`
- `P=16`: min `1.498`, med `2.546`, mean `2.336`, p95 `2.558`, max `2.558`
- Retransmits (avg): `P=1 703.4`, `P=4 1232.8`, `P=16 1890.4`
- Lock contention counter delta: `+300892`
- Lock wait sum delta: `+69.123477s`

Interpretation:
- Pinning can raise `P=4` median in some runs, but it increases retransmits and introduces severe tail instability (notably a `P=16` outlier at `1.498 Gbps`).
- Aggregate lock wait time grew substantially with pinning enabled in this A/B run.
- For current GWLB/GENEVE workload, pinning is not robust enough as a default.

Decision:
- Keep shard-guard pinning available as an opt-in experiment.
- Default remains **off** (code default and deployed env now set to `NEUWERK_DPDK_PIN_STATE_SHARD_GUARD=0`).
- Post-revert smoke (`iperf3 -P 4 -t 20`) measured `2.712 Gbps` sender throughput.

## 2026-03-03 update: flow-steer copy reduction + ENA RSS/RETA init cleanup

Changes:
- `src/main.rs`:
  - Added `flow_steer_payload(&mut Packet) -> Vec<u8>`.
  - Shared-RX demux now avoids an extra copy when the packet is already owned (`std::mem::replace(...).into_vec()` path).
  - Steered packet receive now uses `Packet::new(frame)` instead of `Packet::from_bytes(&frame)` to avoid a second copy.
  - Added unit tests:
    - `flow_steer_payload_moves_owned_packet_without_copy`
    - `flow_steer_payload_copies_borrowed_packet`
- `src/dataplane/dpdk_adapter.rs`:
  - Added driver-name extraction/logging from `rte_eth_dev_info`.
  - Added ENA-specific RSS initialization guard:
    - if ENA reports only limited RSS bits (`0x10000` style), use PMD default `rss_hf=0` instead of forcing unsupported hash fields.
  - `configure_rss_reta(...)` now takes reported `reta_size` and probes a tighter candidate order (`reported`, then `128/64/256/512`) to avoid noisy unsupported-size attempts.

Validation:
- `cargo check --features dpdk`: pass
- `cargo test --features dpdk flow_steer_payload -- --nocapture`: pass
- `cargo build --release --features dpdk`: pass

Deployment note (important):
- `terraform apply` updated S3 objects, but the running firewall VM did not automatically pull the new binary.
- New binary was copied to the firewall VM (`/usr/local/bin/firewall`) and `firewall.service` was restarted before final benchmarking.

Runtime log deltas after new binary restart:
- Now logged:
  - `dpdk: driver=net_ena ... reta_size=0 rss_offloads=0x10000`
  - `dpdk: driver net_ena using PMD default rss_hf due to limited supported_hf=0x10000`
  - `dpdk: rss supported_hf=0x10000 selected_hf=0x0`
- No longer seen:
  - `multi-queue configure with rss_hf=0x10000 failed (ret=-22); retrying with rss_hf=0`
  - `ena_rss_reta_update(): Requested indirection table size (512/256) isn't supported ...`
- Still seen (expected on ENA):
  - `ena_rss_hash_set(): Setting RSS hash fields is not supported. Using default values: 0xc30`

Benchmarks (same matrix: 5 runs each, `iperf3 -t 20`, `P=1/4/16`):
- Artifact: `cloud-tests/aws/artifacts/iperf-matrix-20260303T181740Z.csv`
- Sender summary:
  - `P=1`: min `1.240`, median `1.287`, mean `1.371`, p95 `1.544`, max `1.544` Gbps
  - `P=4`: min `2.101`, median `2.195`, mean `2.363`, p95 `2.763`, max `2.763` Gbps
  - `P=16`: min `2.571`, median `2.588`, mean `2.585`, p95 `2.603`, max `2.603` Gbps
- Additional `P=4` rerun (5x) artifact:
  - `cloud-tests/aws/artifacts/iperf-p4-rerun-20260303T182348Z.csv`
  - Summary: min `2.136`, median `2.248`, mean `2.368`, p95 `2.693`, max `2.693` Gbps
- `make run-tests` explicit throughput check (single `P=4` run): `~2.69 Gbps`

Takeaway:
- RSS/RETA initialization cleanup reduced noisy ENA fallback errors and made startup behavior more deterministic.
- This iteration did **not** produce a stable throughput uplift versus the previous ~`2.7-2.8 Gbps` best-case envelope.
- Current dataplane remains in roughly the same ceiling range with significant run-to-run variance in `P=4` matrix runs.

## 2026-03-03 update: mbuf-native RX packet handoff (code)

Changes:
- Added `FrameIo::recv_packet` + `finish_rx_packet` APIs to support zero-copy receive handoff.
- Implemented `DpdkIo::recv_packet` with borrowed `Packet` over mbuf payload for single-segment packets.
- Added explicit mbuf lifetime management (`held_rx_mbuf`) and deterministic release after packet processing (`finish_rx_packet`), including drop safety.
- Updated single-worker and multi-worker loops to use `recv_packet` and always release mbufs after processing/dispatch.

Validation:
- `cargo check --features dpdk`: pass
- AWS Terraform deploy in `eu-central-1a`: pass (`c6in.xlarge` for firewall/consumer/upstream)
- `make health`: pass
- `make policy-smoke`: pass
- `make run-tests`: pass

Benchmark results (same bench, `iperf3 -t 20`):
- With fresh terraform defaults (`encap-mtu=1500`): significantly lower throughput (`P=4` around `1.8 Gbps`).
- After restoring parity settings used in prior runs (`--encap-mtu 1800` + `NEUWERK_DPDK_PORT_MTU=1800`):
  - `P=1`: `1.36-1.38 Gbps`
  - `P=4`: `2.77-2.87 Gbps`
  - `P=16`: `2.62-2.72 Gbps`

Takeaway:
- The mbuf-native RX handoff did not regress throughput under parity settings and remains in the previous performance envelope.
- MTU parity is a major confounder; comparisons must keep `encap-mtu`/port MTU consistent.

## 0) Stabilization before test runs

Change:
- Fixed partial `PacketBuf` refactor compile break in `src/dataplane/packet.rs` (`self.buf = PacketBuf::owned(buf)`).

Result:
- `cargo check --features dpdk` passes again, so benchmark/deploy/test loop is back to a valid state.

## 1) Overlay hot path cleanup (code)

Changes:
- `Packet::into_vec` added.
- `overlay::encap` reworked to build outer frame in one buffer (removed intermediate payload vec copies).
- Overlay debug prints gated by `NEUWERK_DPDK_OVERLAY_DEBUG`.

Result:
- Removed extra allocations/copies from GENEVE encap path.
- Contributed to measurable end-to-end throughput improvement in later runs (see item 2 baseline comparison).

## 2) DPDK housekeeping lock reduction (code)

Changes:
- Moved worker-0 housekeeping work off per-packet path into interval scheduling:
  - packet interval + time interval + forced-on-idle
- New envs:
  - `NEUWERK_DPDK_HOUSEKEEPING_INTERVAL_PACKETS`
  - `NEUWERK_DPDK_HOUSEKEEPING_INTERVAL_US`

Measured impact (same AWS bench, `iperf3 -P 4`):
- Before this change: ~2.16 Gbps
- After this change (`64/250`): up to ~2.84 Gbps
- Aggressive intervals (`256/1000`) regressed to ~2.04 Gbps

Takeaway:
- Housekeeping frequency is throughput-critical; too infrequent hurt this workload.

## 3) Validation run after stabilization

- `make health`: pass
- `make run-tests`: policy smoke pass (full configured suite), throughput step pass
- `make run-tests` throughput (`-P 4`): ~2.15 Gbps sender/receiver in that run

Additional direct probes from consumer VM:
- `iperf3 -P 1 -t 20`: ~1.39 Gbps
- `iperf3 -P 4 -t 20`: ~2.77 Gbps (best recheck: ~2.80 Gbps in shard sweep)
- `iperf3 -P 16 -t 20`: ~2.56 Gbps

Takeaway:
- Throughput scales from 1->4 streams, then plateaus; adding more streams does not increase aggregate bandwidth.

## 4) Runtime tuning sweep (no code)

### State shard sweep (`iperf3 -P 4`)
- `NEUWERK_DPDK_STATE_SHARDS=1`: ~1.86 Gbps (regression)
- `NEUWERK_DPDK_STATE_SHARDS=4`: ~2.27 Gbps
- `NEUWERK_DPDK_STATE_SHARDS=8`: ~2.58 Gbps
- `NEUWERK_DPDK_STATE_SHARDS=16`: ~2.81 Gbps (best in this sweep)
- `NEUWERK_DPDK_STATE_SHARDS=32`: ~2.77 Gbps

Takeaway:
- Very low sharding causes lock contention collapse.
- Sweet spot on this host is around 16-32; 32 is safe, 16 marginally higher in one run.

### Worker count check (`iperf3 -P 4`)
- `NEUWERK_DPDK_WORKERS=2`: ~2.31 Gbps
- `NEUWERK_DPDK_WORKERS=0` (auto=4 workers): ~2.76 Gbps

Takeaway:
- Multi-core scaling is real in current implementation; 4 workers materially outperform 2 workers.

## Observations from firewall logs/metrics

- ENA PMD is in use (`librte_net_ena.so.26` preloaded).
- RSS-related log signals:
  - `multi-queue configure with rss_hf=0x10000 failed (ret=-22); retrying with rss_hf=0`
  - `ena_rss_hash_set(): Setting RSS hash fields is not supported. Using default values: 0xc30`
  - `ena_rss_reta_update(): Requested indirection table size (512/256) isn't supported (expected: 128)`
- Queue counters show distribution across 4 queues (not fully single-queue collapsed).
- ENA allowance xstats (`bw_in/out_allowance_exceeded`, `pps_allowance_exceeded`) stayed `0` during tested runs.

Interpretation:
- We are currently bottlenecked primarily in software path/lock/packet handling overhead, plus PMD capability constraints, not AWS allowance throttles.

## Why throughput is still low vs "up to 25 Gbps"

- Instance "up to" bandwidth is a theoretical ceiling under ideal traffic profiles and with an optimized dataplane.
- Current path includes GWLB/GENEVE encap/decap overhead and full firewall processing.
- Packet path still alloc/copy heavy in places (not fully mbuf-native end-to-end).
- Shared state synchronization still contributes measurable contention.
- ENA RSS/offload capability behavior limits some tuning options.

## Teardown status

Historical note:
- Earlier in this worklog, one full teardown was completed (`Destroy complete! Resources: 52 destroyed.`).

Current status:
- Environment is currently deployed (not torn down) for active performance iteration.

## Next steps (priority order)

1. Complete mbuf-native fast path in DPDK RX/TX processing.
- Goal: avoid `Vec<u8>` materialization in hot path.
- Requirement: keep memory ownership/lifetime safety explicit and test-covered.

2. Reduce dataplane state lock pressure further.
- Keep shard count in 16-32 range by default on 4-vCPU hosts.
- Add per-worker temporary state caches where safe.
- Continue using lock metrics as objective gates.

3. Reduce run-to-run variance in the `P=4` benchmark.
- Split measurements into:
  - clean-start throughput-only runs
  - post-policy-smoke runs
- Capture per-run lock contention/queue counters to correlate low outliers with runtime state.

4. Expand benchmark matrix.
- Run repeated trials (`n>=5`) for `P=1/4/8/16` and compute median/p95.
- Separate "immediately after policy-smoke" vs "clean-start throughput-only" to remove run-order bias.

5. Profile for top CPU consumers.
- Capture `perf`/flamegraphs on firewall under `P=4` and `P=16`.
- Rank by CPU% and remove top 2-3 hotspots per iteration.

6. Evaluate larger instance class after software-path wins.
- Re-test on `c6in.2xlarge` (or newer Intel class) to check linearity once software bottlenecks are reduced.

## Repro commands used

- Health: `cd cloud-tests/aws && make health`
- Full validation + throughput: `cd cloud-tests/aws && make run-tests`
- Direct throughput: `iperf3 -J -c <upstream-ip> -p 5201 -t 20 -P <n>` (run from consumer via jumpbox)
- Firewall metrics:
  - `curl -s http://127.0.0.1:8080/metrics | egrep 'dp_state_lock|dpdk_rx_bytes_queue_total|dpdk_tx_bytes_queue_total|dpdk_xstat{name="(bw_in_allowance_exceeded|bw_out_allowance_exceeded|pps_allowance_exceeded)"}'`
- Teardown:
  - `cd cloud-tests/aws/terraform && terraform destroy -auto-approve -var 'firewall_binary_path=../../../target/release/firewall'`
