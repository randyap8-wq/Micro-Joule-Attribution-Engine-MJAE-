# Micro-Joule Attribution Engine (MJAE)

MJAE is a cross-platform, headless systems daemon that builds a **Trust Layer**
for AI energy auditing. It runs in heterogeneous data centers — Linux H100
clusters, Windows Server farms, and macOS-based local dev — and turns raw
kernel-level telemetry into a **signed `EnergyManifest`** that proves how many
micro-joules each process actually burned.

> "Anyone can say the GPU used 300 W. Only MJAE can say *Process 1024* used
> 287 W of it because it saturated the 16-bit float units."

## Capabilities

| Surface | Backend | Telemetry source |
| --- | --- | --- |
| **Linux** | [`LinuxProvider`](src/providers/linux.rs) | Aya eBPF hooks on `dma_fence:dma_fence_signaled` (GPU activity windows) and `sched:sched_switch` |
| **Windows** | [`WindowsProvider`](src/providers/windows.rs) | eBPF-for-Windows for process lifecycle + handle opens to Direct3D / CUDA, plus NVML FFI (`nvmlDeviceGetComputeRunningProcesses_v3`, `nvmlDeviceGetPowerUsage`) for power-plane telemetry |
| **macOS** | [`AppleSiliconProvider`](src/providers/apple_silicon.rs) | Raw IOReport FFI sampling the Apple Silicon SoC power planes (`Energy Model` group, GPU / ANE channels) |

Every provider implements the same [`EnergyProvider`](src/core/provider.rs)
trait, so the daemon's main loop is OS-agnostic.

## Architecture

```
┌────────────┐  ┌────────────┐  ┌────────────┐
│ LinuxProv. │  │ WinProv.   │  │ AppleProv. │
└─────┬──────┘  └─────┬──────┘  └─────┬──────┘
      │ sync_registry │ sync_registry │ sync_registry
      ▼               ▼               ▼
        ┌───────────────────────────────┐
        │     AmalgafyRegistry          │  ← lock-free, ordered,
        │     PID → cumulative µJ       │     process-wide singleton
        └────────────────┬──────────────┘
                         │  snapshot()
                         ▼
                ┌─────────────────┐
                │  AmalgafySigner │  Ed25519, canonical JSON
                └────────┬────────┘
                         ▼
                  AmalgafySeal  ← published every 60 s
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

### Deterministic Attribution Model

[`deterministic_attribution_uj`](src/core/attribution.rs) implements

$$E_{attributed} = (P_{total} - P_{idle}) \times \frac{T_{process\\_on\\_accelerator}}{T_{total\\_busy}} \times T_{total\\_busy}$$

i.e. the burst power above idle, scaled by the share of accelerator-busy
time the target PID actually owned. When no accelerator activity is detected
at all, the daemon falls back to [`rapl_fallback_uj`](src/core/attribution.rs),
which scales the RAPL `energy_uj` delta by the process's CPU-time share for
CPU-only auditing.

### The Amalgafy Seal

Every `AMALGAFY_SEAL_INTERVAL_SECS` (60 s) the daemon publishes a signed
[`AmalgafySeal`](src/core/signer.rs):

```rust
use ed25519_dalek::SigningKey;
use mjae::{AmalgafySigner, global_registry};

let signer = AmalgafySigner::new(SigningKey::from_bytes(&secret));
let attributions = /* Vec<PidEnergyAttribution> from providers */;
let total = global_registry().total_micro_joules();
let seal = signer.seal(attributions, "NV-H100-SXM5-SN-0001", total)?;
seal.verify()?;
```

The signature is a **detached Ed25519** signature over a *canonical* JSON
encoding (keys sorted lexicographically, no insignificant whitespace) of the
payload. It explicitly covers both the **hardware serial** and the **total
joules**, defeating "Manifest Spoofing" — an attacker cannot swap a
high-energy payload for a different machine, nor zero out the total, without
invalidating the signature.

## Crate layout

```
src/
├── core/
│   ├── attribution.rs   deterministic & RAPL-fallback energy math
│   ├── manifest.rs      legacy per-PID signed manifest
│   ├── provider.rs      EnergyProvider trait (incl. sync_registry)
│   ├── registry.rs      AmalgafyRegistry + global_registry()
│   └── signer.rs        AmalgafySigner / AmalgafySeal / canonical_json
└── providers/
    ├── apple_silicon.rs IOReport FFI (macOS)
    ├── linux.rs         Aya eBPF dma_fence hooks (Linux)
    └── windows.rs       NVML FFI + eBPF-for-Windows ingestion (Windows)
```

Platform-specific providers are gated behind `#[cfg(target_os = "...")]` so
each compiled binary only carries the code path it actually needs.

## Build & test

```bash
cargo check --all-targets
cargo test
```

The crate is `no-UI`, `log`-based, and designed to be embedded inside a
`tokio` daemon.

