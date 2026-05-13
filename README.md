# Micro-Joule Attribution Engine (MJAE)

MJAE is a cross-platform, headless systems daemon that builds a **Trust Layer**
for AI energy auditing. It runs in heterogeneous data centers — Linux H100
clusters, Windows Server farms, and macOS-based local dev — and turns raw
kernel-level telemetry into a **signed `AmalgafySeal`** that proves how many
micro-joules each process actually burned and *on which physical machine*.

> "Anyone can say the GPU used 300 W. Only MJAE can say *Process 1024* used
> 287 W of it because it saturated the 16-bit float units — and that this
> measurement came from SoC die `XYZ`."

## Capabilities

| Surface | Backend | Telemetry source |
| --- | --- | --- |
| **Linux** | [`LinuxProvider`](src/providers/linux.rs) | Aya eBPF hooks on `dma_fence:dma_fence_signaled` (GPU activity windows) + `sched:sched_switch`, plus `/sys/class/powercap/intel-rapl:0/energy_uj` for package power |
| **Windows** | [`WindowsProvider`](src/providers/windows.rs) | eBPF-for-Windows for process lifecycle + handle opens to Direct3D / CUDA, plus NVML FFI (`nvmlDeviceGetComputeRunningProcesses_v3`, `nvmlDeviceGetPowerUsage`) for power-plane telemetry |
| **macOS** | [`AppleSiliconProvider`](src/providers/apple_silicon.rs) | Raw IOReport FFI (`IOReportCreateSubscription` → `IOReportCreateSamplesDelta`) sampling the Apple Silicon SoC power planes (`Energy Model` group, CPU / GPU / ANE channels) |

Every provider implements the same [`EnergyProvider`](src/core/provider.rs)
trait, so the daemon's main loop is OS-agnostic.

## Architecture

```
┌────────────┐  ┌────────────┐  ┌────────────┐
│ LinuxProv. │  │ WinProv.   │  │ AppleProv. │
└─────┬──────┘  └─────┬──────┘  └─────┬──────┘
      │ 100 ms tick   │ 100 ms tick   │ 100 ms tick
      │ Δ energy      │ Δ energy      │ Δ energy
      ▼               ▼               ▼
        ┌───────────────────────────────┐
        │     AmalgafyRegistry          │  ← lock-free, ordered,
        │     PID → cumulative µJ       │     process-wide singleton
        └────────────────┬──────────────┘
                         │  snapshot()
                         ▼
                ┌─────────────────┐    ┌──────────────────┐
                │  AmalgafySigner │ ←─ │ HardwareIdentity │
                │  Ed25519 + JCS  │    │ (IOKit / m-id /  │
                └────────┬────────┘    │  NVML UUID)      │
                         ▼             └──────────────────┘
                  AmalgafySeal  ← published every 60 s,
                                  cryptographically bound to
                                  the host's hardware fingerprint
```

### The Unified Registry

[`AmalgafyRegistry`](src/core/registry.rs) is the single source of truth.
The directive calls for "a lock-free, global `BTreeMap<u32, u64>`"; we back
it with [`crossbeam_skiplist::SkipMap`], which preserves `BTreeMap`'s ordered
semantics while supporting wait-free reads and lock-free atomic accumulation
through an internal `AtomicU64` per slot. A process-wide handle is exposed
via `global_registry()`.

```rust
use mjae::global_registry;

let registry = global_registry();
registry.add_micro_joules(1024, 287_000); // Process 1024: +287 mJ
let total = registry.total_micro_joules();
```

### The Differential Sampling Daemon

Every provider gets a default
[`start_sampling_loop`](src/core/provider.rs) implementation that turns its
`sample_power_state()` into a **non-blocking 100 ms tokio loop**:

```rust
use std::sync::Arc;
use mjae::{AmalgafyRegistry, LinuxProvider, EnergyProvider, global_registry};

let registry = Arc::new(AmalgafyRegistry::new()); // or global_registry()
let mut provider = LinuxProvider::new("NV-H100-SXM5-SN-0001");

tokio::spawn(async move {
    let _ = provider.start_sampling_loop(&registry).await;
});
```

On each tick the loop:

1. Calls `sample_power_state()` to grab a fresh hardware snapshot.
2. Differences it against the `previous_snapshot` to get a Δ in **µJ**, using
   `window_energy_uj(burst_power_uw, Δt_ns)`.
3. Splits the Δ across the provider's `active_pids()` set (the
   `dma_fence` submitters on Linux, NVML compute contexts on Windows,
   IOReport task PIDs on macOS) and feeds the result into the
   `AmalgafyRegistry` without locks. When the active set is empty the Δ is
   bucketed under PID `0` so the energy stays accountable.
4. Logs an industrial **Heartbeat** line so operators see the running
   cumulative Δ in their telemetry pipeline.

### Hardware Identity & Audit-Spoof Resistance

[`HardwareIdentity`](src/core/hardware.rs) probes the host for its best
available fingerprint:

* **macOS** — `IOPlatformSerialNumber` via IOKit (`IOPlatformExpertDevice`).
* **Linux** — `/etc/machine-id`, falling back to the GPU UUID under
  `/sys/class/drm/*/device/uuid` for diskless / immutable images.
* **Windows** — NVML `nvmlDeviceGetUUID`.

The probe never panics: if every source fails it returns a `synthetic:*`
identity tagged with `HardwareIdentitySource::Synthetic` so auditors can
flag the seal as unverifiable instead of trusting silent garbage.

The identity is sealed into every `AmalgafySeal`, which is what defeats
"Audit Spoofing" — an attacker cannot replay host A's manifest as if it came
from host B, even if both daemons share the same Ed25519 signing key.

### Deterministic Attribution Model

[`deterministic_attribution_uj`](src/core/attribution.rs) implements

$$E_{attributed} = (P_{total} - P_{idle}) \times \frac{T_{process\\_on\\_accelerator}}{T_{total\\_busy}} \times T_{total\\_busy}$$

i.e. the burst power above idle, scaled by the share of accelerator-busy
time the target PID actually owned. The Windows path additionally exposes
[`nvml_window_energy_uj`](src/core/attribution.rs), the closed-form NVML
energy:

$$E(\mu J) = P(\mathit{mW}) \times \Delta t(\mathit{ms})$$

which matches `nvmlDeviceGetPowerUsage`'s native unit so the sampling loop
doesn't have to hand-roll unit conversions at the call site.

When no accelerator activity is detected at all, the daemon falls back to
[`rapl_fallback_uj`](src/core/attribution.rs), which scales the RAPL
`energy_uj` delta by the process's CPU-time share for CPU-only auditing.

### The Amalgafy Seal

Every `AMALGAFY_SEAL_INTERVAL_SECS` (60 s) the daemon publishes a signed
[`AmalgafySeal`](src/core/signer.rs):

```rust
use ed25519_dalek::SigningKey;
use mjae::{AmalgafySigner, HardwareIdentity, global_registry};

let signer = AmalgafySigner::new(SigningKey::from_bytes(&secret));
let identity = HardwareIdentity::probe();
let attributions = /* Vec<PidEnergyAttribution> from providers */;
let total = global_registry().total_micro_joules();
let seal = signer.seal(attributions, "NV-H100-SXM5-SN-0001", total, identity)?;
seal.verify()?;
```

The signature is a **detached Ed25519** signature over a *canonical* JSON
encoding (keys sorted lexicographically, no insignificant whitespace) of the
payload. It explicitly covers the **hardware serial**, the
**hardware identity fingerprint**, and the **total joules**, defeating
"Manifest Spoofing" *and* "Audit Spoofing" — an attacker cannot swap a
high-energy payload for a different machine, replay it on another host, or
zero out the total without invalidating the signature.

### Per-Fence Correlation (Linux)

`LinuxProvider::correlate_fence(DmaFenceEvent)` bridges the
`dma_fence:dma_fence_signaled` tracepoint with the GPU power data sampled
from sysfs/NVML:

```rust
use mjae::{DmaFenceEvent, LinuxProvider};

let mut provider = LinuxProvider::new("NV-H100-SXM5-SN-0001");
provider.mark_pid_active(4242);

let attribution = provider.correlate_fence(DmaFenceEvent {
    submitter_pid: 4242,
    submitted_at_ns: 1_000_000_000,
    signaled_at_ns: 1_200_000_000,
    gpu_power_uw: 250_000_000,
});
// → 50 J allocated to PID 4242 over its dma_fence window.
```

## Crate layout

```
src/
├── core/
│   ├── attribution.rs   deterministic / RAPL-fallback / NVML energy math
│   ├── hardware.rs      HardwareIdentity probe (macOS IOKit / Linux machine-id / Windows NVML UUID)
│   ├── manifest.rs      legacy per-PID signed manifest
│   ├── provider.rs      EnergyProvider trait + 100 ms differential sampling loop
│   ├── registry.rs      AmalgafyRegistry + global_registry()
│   └── signer.rs        AmalgafySigner / AmalgafySeal / canonical_json
└── providers/
    ├── apple_silicon.rs IOReport FFI + Energy Model deltas (macOS)
    ├── linux.rs         Aya eBPF dma_fence + RAPL sampler (Linux)
    └── windows.rs       NVML FFI + eBPF-for-Windows ingestion (Windows)
```

Platform-specific providers are gated behind `#[cfg(target_os = "...")]` so
each compiled binary only carries the code path it actually needs.

## Build & test

```bash
cargo check --all-targets
cargo test
```

The crate is **UI-free**, `log`-based, and designed to be embedded inside a
`tokio` daemon. All hot paths use `u64` for µJ and `u64` for ns; the
registry uses `AtomicU64` plus a lock-free `SkipMap` so the 100 ms heartbeat
loop runs without contention.

## License

Dual-licensed under either of MIT or Apache-2.0 at your option.
