# LeaseGuard

**Cryptographic impact-bounded authorization for disconnected hybrid-infrastructure control planes.**

Companion research prototype (in preparation, not yet submitted). Site: https://sunilgentyala.github.io/LeaseGuard/

## The problem

Hybrid and disaster-recovery infrastructure — storage arrays, Kubernetes clusters, hypervisor hosts, edge gateways, backup appliances, DR sites — has to keep operating when its enforcement point loses contact with the authorization or revocation authority. Every existing offline-capable credential scheme (self-contained OAuth/ACE-OAuth tokens, macaroons, cached workload identities, epoch- or heartbeat-revocable tokens) bounds only *time* or *delegation structure*. None of them bound *cumulative operational damage*: once issued, a stale or revoked-but-unreachable credential can authorize unbounded reads, writes, deletions, or provisioning for as long as the partition lasts.

## What LeaseGuard does

A LeaseGuard lease is a signed, self-contained credential that carries a **multi-dimensional cumulative impact budget** — operation count, data volume, object count, financial ceiling, and destructive-operation ceiling — instead of just a time window. The enforcement point tracks consumption against that budget in tamper-evident, hash-chained local state (a software simulator of a hardware monotonic counter). Once any dimension is exhausted, the enforcement point denies further mutating operations and drops to read-only, regardless of whether it can reach the authority. On reconnection, a reconciliation protocol detects local-state rollback and resolves forked enforcement state conservatively.

This repository is a **research simulator**, not a production integration: infrastructure adapters are typed operation classes with policy-authored cost weights, not real Kubernetes/VMware/storage-vendor SDK calls. See `docs/index.html` for the full novelty argument, formal model, and comparison against 7 baseline credential schemes.

## Repository layout

```
leaseguard/          core package: lease schema + signing, sealed monotonic counter,
                     enforcement point, authorization authority, reconciliation
experiments/         workload generator, baseline comparison harness, adversarial scenarios
tests/               correctness tests for every security property in the design
results/             CSV/markdown output from the experiment scripts (regenerable, not fabricated)
docs/                GitHub Pages site source
```

## Quickstart

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
python -m experiments.run_experiments   # writes results/results.csv
python -m experiments.scenarios         # writes results/scenarios.md
```

## Headline result

Running the same scripted workload against 7 baseline schemes and LeaseGuard, with a credential revoked 30 seconds into a control-plane partition, across partition durations of 1 minute to 24 hours (`results/results.csv`):

| Scheme | Post-revocation impact @ 1 min | @ 10 min | @ 1 hour | @ 24 hours |
|---|---|---|---|---|
| Bearer token / self-contained PoP / time-only lease | 5.2 | 14,060.9 | 84,365.4 | 2,040,839.2 |
| Epoch-revocable token | 5.2 | 14,060.9 | 84,365.4 | 84,365.4 |
| Heartbeat-dependent credential | 5.2 | 5.2 | 5.2 | 5.2 (near-zero availability) |
| **LeaseGuard** | **5.2** | **5060.9** | **5365.4** | **5397.7** |

Time-bounded schemes grow unbounded (or near-unbounded) with partition duration. LeaseGuard plateaus at its authorized budget and stays there — the property the design sets out to prove. The heartbeat scheme also stays flat, but at the cost of near-total unavailability once the partition exceeds its grace window (see the full CSV for the availability-vs-impact tradeoff across all 8 schemes).

## Honest limitations

- Local-state rollback is *detectable* at reconciliation, not *cryptographically impossible*, without a genuine hardware root of trust (TPM/TEE). Many real storage arrays and hypervisor hosts don't expose one today.
- Financial-impact and destructive-op weights are policy-authored estimates, not independently verified real-world damage.
- This is a simulator. Production integration with real Kubernetes admission webhooks, VMware/Hyper-V adapters, and storage-array APIs is future work.

## License

MIT — see `LICENSE`.
