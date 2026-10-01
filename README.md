# RedOS

**Evidence-backed security testing for AI systems — every finding traced to a real execution against a real target.**

RedOS attacks LLM applications, agents, and RAG pipelines, then proves what it found. Its central constraint is
enforced in code, not merely documented: **no finding can exist without an evidence chain from a live HTTP
execution**. Mocks are unreachable from production paths, and the storage boundary independently rejects
unprovenanced evidence.

> ⚠️ **Status: active development.** The engine (`engine/`) is the mature, tested subsystem. Several platform layers
> are design-stage, and some CI steps are placeholders. Read [Honest status](#honest-status) before relying on
> anything here.

---

## Why

Most AI-security tooling reports findings it *inferred*: a prompt that looks like an injection, an LLM's opinion that
a response is unsafe, a static scan of a config file. RedOS takes the opposite position — it executes attacks against
real endpoints and keeps the receipts.

```
AttackDefinition → AttackPlanner → AttackExecutor → TargetAdapter → ObservedExecution
                                                              ↓
                                                      EvidenceEvents → ExecutionResult
```

Every step is a real object with an ID. Outcomes are derived **only** from observed evidence — indicator matches in
real model output, real tool results, real retrieved documents. The engine cannot fabricate a success.

---

## Repository layout

| Path | What it is | State |
|---|---|---|
| `engine/` | **Attack & Execution Engine** — the core. 174 Python modules: adapters, attack plugins, planning, execution, campaigns, provenance, trust gates. | **Mature** |
| `security/` | **FastAPI + MongoDB API** — evidence ingestion, findings lifecycle, attack graph, remediation, regression, CVSS v3.1 severity. | Working, needs MongoDB |
| `platform/` | Fleet management, distributed execution, scheduler, workers, identity, storage, observability, audit. | Partial / design-stage |
| `platform/web/` | React frontend. | Partial |
| `src/` | Node + TypeScript API service (the artifact `deployment/Dockerfile` builds). | Early |
| `deployment/` | Hardened multi-stage Dockerfile + production Compose stack. | Working |
| `benchmarks/` | Benchmark framework and targets. | Early |
| `demo/` | Production-scale demonstration script. | Illustrative only (see caveats) |
| `docs/` | 31 canonical design + validation documents. | Reference |
| `reports/` | Generated trust-gate output (gitignored, regenerated). | Generated |

---

## Quick start

### 1. Engine — recommended starting point

The engine is the core value and needs the least infrastructure: no database, no Redis.

```bash
git clone https://github.com/KUNDURUHIMANEESHREDDY/redos.git
cd redos

python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

python -m pytest engine/tests -q
```

Requires **Python 3.11+**. The only runtime dependency is `httpx`; the `dev` extra adds `pytest` and `pytest-asyncio`.

### 2. Run the trust gate

RedOS ships its own release gate. It measures dependency locking, reproducibility, license inventory, malicious-package
detection, SBOM generation, secret scanning, dependency vulnerabilities, container configuration, migrations, API
contracts, chaos, rollback, security invariants, and self-red-teaming — then writes a JSON report.

```bash
python -m engine.security.trust_gate --root .
```

Takes ~85 seconds. Report is written to `reports/trust_gate/latest.json`. `get_trust.py` is a wrapper that prints a
summary. See [Trust gate](#trust-gate--ci) for what it currently reports.

### 3. API service (FastAPI + MongoDB)

```bash
pip install -r requirements.txt
cp .env.example .env          # then edit: Mongo URI and secrets
docker run -d -p 27017:27017 mongo:7.0

uvicorn security.main:app --reload --port 8000
```

- Swagger UI → <http://localhost:8000/docs>
- ReDoc → <http://localhost:8000/redoc>
- Health → <http://localhost:8000/health>

All endpoints except `/auth/*` and `/health` require a JWT bearer token. Obtain one via `POST /api/v1/auth/login`.

Configuration is read from `.env` (see `.env.example`): `MONGODB_URI`, `MONGODB_DB`, `REDIS_URI`, `SECRET_KEY`,
`CELERY_BROKER_URL`, `LOG_LEVEL`, `JSON_LOGS`.

### 4. Node / TypeScript service

```bash
npm ci
npm run build
npm test          # vitest, against platform/tests
npm run typecheck # tsc --noEmit
npm run dev       # vite
```

### 5. Production stack (Docker)

```bash
docker compose -f deployment/docker-compose.production.yml up --build
```

Brings up a hardened `api` + `worker` + `mongodb` + `redis` stack: non-root user, read-only root filesystem,
`no-new-privileges`, all capabilities dropped, CPU/memory limits, health checks, and secrets mounted from files under
`deployment/security/` rather than baked into the image. **You must create those secret files first** — see
[`deployment/security/README.md`](deployment/security/README.md).

---

## Attack families

Plugins are registered dynamically and discovered via `PLUGIN_REGISTRY` / `discover_plugins()`.

| Attack type | Module | What it probes |
|---|---|---|
| `prompt_injection` | `attacks/injection.py` | Instruction override and injection framings |
| `jailbreak` | `attacks/jailbreak.py` | Safety-bypass framings |
| `data_leakage` | `attacks/data_leakage.py` | System prompt and secret extraction |
| `tool_abuse` | `attacks/tool_abuse.py` | Inducing harmful tool invocations |
| `unsafe_tool_call` | `attacks/unsafe_tool.py` | Direct unsafe calls (shell, SQL) |
| `malicious_document` | `attacks/document.py` | Payloads embedded in retrieved documents |
| `rag_poisoning` | `attacks/rag_poison.py` | Poisoning retrieval corpora |
| `agent_escalation` | `attacks/escalation.py` | Privilege escalation across agent boundaries |
| `permission` | `attacks/permission.py` | Permission and authorization boundaries |
| `model_manipulation` | `attacks/manipulation.py` | Steering model behaviour |

Beyond the plugin layer, the engine implements reconnaissance and attack-surface discovery, hypothesis generation,
coverage- and observation-driven strategy selection, adaptive payload mutation, fuzzing, campaign orchestration with
replayable manifests, cross-family attack chaining, and regression comparison.

---

## Target support

Adapters are created through `create_adapter()`, which **never returns a mock adapter**.

| Target kind | Adapter | Protocol |
|---|---|---|
| `openai_compatible` | `OpenAICompatAdapter` | `POST /chat/completions` |
| `anthropic_compatible` | `AnthropicAdapter` | `POST /v1/messages` (content blocks) |
| `local_model` | `LocalModelAdapter` | OpenAI-compatible `/v1` surface (e.g. Ollama) |
| `custom_http` | `CustomHTTPAdapter` | Configurable path, body template, dot-path extraction |
| `agent` | `AgentAdapter` | `/chat/completions`, `GET /tools`, `POST /tools/{name}/invoke` |
| `rag` | `RAGAdapter` | `/chat/completions`, `POST /retrieve` |

Compatibility was validated against structurally different target emulators — bare chat-only targets, alternative tool
names, alternative RAG response shapes, auth-required endpoints, timeouts, flaky 503s, and malformed responses. Full
results and measured limitations: [`docs/TARGET_COMPATIBILITY.md`](docs/TARGET_COMPATIBILITY.md).

---

## Evidence & provenance guarantees

This is what distinguishes RedOS. The guarantees are mechanical, not aspirational.

**Provenance is stamped at observation time.** Every evidence event carries `provenance = live`, recorded from the
adapter that produced it.

**Mock evidence is rejected twice.**
1. *By construction* — `create_adapter()` has no path that returns a mock; test doubles live only in `engine/tests/`.
2. *By gate* — `FindingsGateway.submit()` re-validates the chain and raises `MockEvidenceRejected`
   (`MOCK_EVIDENCE_REJECTED`) if any event lacks live provenance, the execution isn't finalized, or required fields
   are missing.

**Chain validation** (`validate_evidence_chain`) checks: IDs present, execution finalized, at least one event, all
request/response/tool/retrieval events are `live`, timestamps monotonic, artifacts carry digests.

**Secrets never reach evidence.** API keys are referenced by `api_key_ref` and resolved from the environment via
`SecretsVault`; `CaptureEnforcer` redacts Authorization headers and known secret values before anything is recorded.

**SSRF is blocked before the adapter.** `SSRFPolicy` rejects non-HTTP(S) schemes, RFC1918 ranges, link-local addresses
(including the `169.254.169.254` metadata endpoint), and unresolvable hosts — emitting `ssrf.blocked` audit events
instead of connecting.

**Resource budgets cannot be exhausted by a payload.** `AttackPolicy` caps `max_turns`, `max_retries`, and
`max_artifacts`; `Sandbox` gates concurrency; `RateLimiter` throttles per-target request rate.

Detailed model: [`docs/PROVENANCE_MODEL.md`](docs/PROVENANCE_MODEL.md).

---

## Execution lifecycle

```
PENDING ──► RUNNING ──► SUCCESS
                │
                ├────────► FAILURE
                ├────────► TIMED_OUT
                ├────────► CANCELLED
                └────────► INDETERMINATE
```

`success` vs `failure` describes the **attack outcome** (indicators matched or not).
`timed_out` / `cancelled` / `indeterminate` describe **execution integrity**. The two are deliberately separate, so a
timeout is never miscounted as a failed attack. Full state machine:
[`docs/EXECUTION_LIFECYCLE.md`](docs/EXECUTION_LIFECYCLE.md).

**Replayability.** `AttackDefinition.replay_hash()` is a SHA-256 over the canonicalized attack type, plugin, params,
target fingerprint, policy, and prerequisites. Replaying the same definition against the same target configuration
reproduces an identical hash under a new `execution_id` — which is what makes regression testing meaningful.

---

## The frozen engine contract

[`docs/ENGINE_CONTRACT.md`](docs/ENGINE_CONTRACT.md) is canonical between the engine and its consumers. Changing it
requires updating the contract tests. The hard rules:

1. No hardcoded vulnerabilities, fabricated model responses, synthetic success, or placeholder data in production paths.
2. Mocks are isolated to tests and cannot be reached through `create_adapter` or `AttackOrchestrator`.
3. Every finding traces to real target → real execution → real observation → real evidence.
4. Every important object has an ID: `target_id`, `attack_id`, `plan_id`, `execution_id`, `event_id`, `finding_id`.
5. Security-relevant operations emit `audit` events.
6. Evidence capture is governed by `CapturePolicy`; secrets are redacted before recording.

### Error model

`ConfigurationError`, `SSRFBlocked`, `MissingSecret`, `PluginError`, `TargetUnreachable`, `TargetAuthError`,
`TargetProtocolError`, `TargetTimeout`, `AttackTimeout`, `AttackCancelled`, `PayloadError`, `UnsupportedOperation`,
`MockEvidenceRejected`, `ReplayMismatch`.

Each has a stable code, is recorded as an `error` evidence event, and **never fabricates a result**.

---

## Trust gate & CI

`.github/workflows/release.yml` implements a 16-stage gated release pipeline:

```
COMMIT → UNIT TESTS → INTEGRATION TESTS → SECURITY REGRESSION → SELF-RED-TEAM → BENCHMARKS
       → DEPENDENCY SCAN → SECRET SCAN → SBOM → CONTAINER SCAN → MIGRATION TEST
       → API CONTRACT TEST → CHAOS TEST → BUILD PROVENANCE → STAGING → SMOKE TEST → PRODUCTION
```

Gates live in `engine/security/`: `trust_gate`, `release_gate`, `supply_chain`, `migration_gate`, `contract_gate`,
`chaos_gate`, `provenance_gate`, `invariants_gate`, `rollback_gate`, `guard`.

The design philosophy is **measured, not declared** — controls that cannot execute in an environment report
`NOT VERIFIED` rather than claiming `PASS`.

### Current gate results

A clean local run on a fresh clone reports **16 gates: 14 pass, 2 warn, 0 fail — but `overall_status: FAIL`.**

This is *fail-closed by design*, not a bug: `overall_status` is `FAIL` if any gate's **score** falls below its
configured threshold, even when no gate's status is `FAIL`. Here the blocker is:

```
artifact_provenance score 0.5 < 0.6   (threshold)
```

Artifact provenance scores low because no cosign signing key is available in a local environment, so the chain cannot
be cryptographically verified. On a real signed release this gate scores higher. Expect the gate to fail out of the
box until signing is configured.

See [`docs/RELEASE_TRUST_GATE.md`](docs/RELEASE_TRUST_GATE.md) and [`docs/SUPPLY_CHAIN_SECURITY.md`](docs/SUPPLY_CHAIN_SECURITY.md).

---

## Documentation

<details>
<summary><b>Engine &amp; contract</b></summary>

| Document | Contents |
|---|---|
| [`ENGINE_CONTRACT.md`](docs/ENGINE_CONTRACT.md) | Frozen data contracts, policy defaults, error codes, hard rules |
| [`EXECUTION_LIFECYCLE.md`](docs/EXECUTION_LIFECYCLE.md) | Execution state machine and transition rules |
| [`PROVENANCE_MODEL.md`](docs/PROVENANCE_MODEL.md) | Evidence chain, provenance values, secret/SSRF/sandbox isolation |
| [`EXPERIMENT_ENGINE.md`](docs/EXPERIMENT_ENGINE.md) | Experiment selection and scoring |
| [`CAMPAIGN_ENGINE.md`](docs/CAMPAIGN_ENGINE.md) | Campaign orchestration and manifests |
| [`ATTACK_INTELLIGENCE.md`](docs/ATTACK_INTELLIGENCE.md) | Intelligence and learning layers |
| [`EVALUATION_METHODOLOGY.md`](docs/EVALUATION_METHODOLOGY.md) | How effectiveness is measured |

</details>

<details>
<summary><b>Architecture &amp; platform</b></summary>

| Document | Contents |
|---|---|
| [`ARCHITECTURE.md`](docs/ARCHITECTURE.md) | API contracts, RBAC, tenancy, data models, threat model |
| [`FLEET_ARCHITECTURE.md`](docs/FLEET_ARCHITECTURE.md) | Fleet and multi-target architecture |
| [`FLEET_INTELLIGENCE.md`](docs/FLEET_INTELLIGENCE.md) | Fleet intelligence layer |
| [`ENTERPRISE.md`](docs/ENTERPRISE.md) | Enterprise deployment concerns |
| [`ENTERPRISE_IDENTITY.md`](docs/ENTERPRISE_IDENTITY.md) | Identity and access |
| [`INTEGRATIONS.md`](docs/INTEGRATIONS.md) | Integration points |
| [`OPERATIONS.md`](docs/OPERATIONS.md) | Operational runbook |
| [`DISASTER_RECOVERY.md`](docs/DISASTER_RECOVERY.md) | DR procedures |

</details>

<details>
<summary><b>Security &amp; validation</b></summary>

| Document | Contents |
|---|---|
| [`SECURITY_GATES.md`](docs/SECURITY_GATES.md) | Security gate definitions |
| [`SECURITY_EFFECTIVENESS.md`](docs/SECURITY_EFFECTIVENESS.md) | Gate effectiveness measurements |
| [`REDOS_SELF_SECURITY.md`](docs/REDOS_SELF_SECURITY.md) | RedOS red-teaming itself |
| [`RELEASE_TRUST_GATE.md`](docs/RELEASE_TRUST_GATE.md) | Release gate pipeline and thresholds |
| [`SUPPLY_CHAIN_SECURITY.md`](docs/SUPPLY_CHAIN_SECURITY.md) | Supply chain verification results |
| [`INFRASTRUCTURE_TRUST_VALIDATION.md`](docs/INFRASTRUCTURE_TRUST_VALIDATION.md) | Infrastructure trust |
| [`PRODUCTION_SCALE_VALIDATION.md`](docs/PRODUCTION_SCALE_VALIDATION.md) | Production scale validation |
| [`SCALE_TESTING.md`](docs/SCALE_TESTING.md) | Scale testing |
| [`FINAL_RELEASE_VALIDATION.md`](docs/FINAL_RELEASE_VALIDATION.md) | Final release validation |
| [`GENERALIZATION_REPORT.md`](docs/GENERALIZATION_REPORT.md) | Generalization behaviour report |
| [`DR_VALIDATION.md`](docs/DR_VALIDATION.md) | DR validation |
| [`CONTINUOUS_SCANNING.md`](docs/CONTINUOUS_SCANNING.md) | Continuous scanning |
| [`RELEASE_PROCESS.md`](docs/RELEASE_PROCESS.md) | Release process |
| [`TARGET_COMPATIBILITY.md`](docs/TARGET_COMPATIBILITY.md) | Measured target compatibility + limitations |

Security subsystem docs live in [`security/docs/`](security/docs/): finding model, severity (CVSS), risk graph,
attack graph, remediation, regression, change detection, digital twin, knowledge base, posture, assurance, and
security analysis.

</details>

---

## Honest status

Limitations stated plainly rather than buried.

### Verified by running the code in this repo

**The full `engine/tests` suite does not complete.** It exceeded 15 minutes without finishing. Run it per-directory
instead.

**`engine/tests/targets` has 16 failing tests out of 49.** All fail for one root cause: `SSRFPolicy()` defaults to
`allow_loopback=False`, so the SSRF guard raises `SSRFBlocked` on the `127.0.0.1` URLs that the test emulators bind
to. The engine code behaves correctly — the *tests* are not configured to permit loopback.

**This contradicts the documentation.** [`docs/PROVENANCE_MODEL.md`](docs/PROVENANCE_MODEL.md) states that "loopback
(local models)" is *"allowed by default"*, but `engine/security/ssrf.py` defines `allow_loopback: bool = False`. The
docs are wrong on this point; the code default is the safer behaviour. Either the docs should be corrected, or the
tests should pass a loopback-permitting policy.

By contrast, `engine/tests/provenance` is **22 passed, 0 failed** — the provenance guarantees hold.

### Design-stage, not implemented in the engine

- **Remediation and a true attack-graph layer are design documents only.** They are described in
  `docs/ARCHITECTURE.md` and partially implemented in `security/`, but the `engine/` per-target pipeline does not
  include them.
- **MCP and multi-agent targets are unsupported** — `TargetKind` has no such values.
- **Native Ollama `/api/chat` is unimplemented**; Ollama works via its OpenAI-compatible `/v1` surface.

### Known engine limitations

- Tool capability is partly *assumed* from configuration rather than observed. Attacks fail honestly instead of
  fabricating success, but the hypothesis starts from an assumption.
- Tool listing is only probed on `agent` kind targets.
- Payload tool names are catalog defaults; differently-named targets fail honestly.
- Ollama's native protocol is unsupported.

### Repository hygiene — worth fixing

- **CI never runs.** `.github/workflows/release.yml` triggers on `main`, but the default branch is `master`.
- **No `LICENSE` file.** `security/main.py` declares MIT, but no license file is committed.
- **`run_trust.bat` hardcodes an absolute path** (`C:\Users\himaneeshreddyk\Downloads\redos`) — it fails for anyone else.
- **`demo/production_scale_demo.py` imports `redos.*`**, which does not match the actual package layout (`engine`,
  `security`, `platform`). Treat it as illustrative, not runnable.
- **Several CI stages are placeholders** — benchmarks, staging deploy, production promotion, and smoke test are
  `echo`-only and do not actually verify anything.
- **Committed generated artifacts**: `simple_test.txt`, `trust_gate_output.txt`, `sbom.json.sig`, and
  `redos_engine.egg-info/` are build output that arguably belongs out of version control.

---

## Contributing

1. Read [`docs/ENGINE_CONTRACT.md`](docs/ENGINE_CONTRACT.md) before touching engine code — it is frozen.
2. Any contract change must update `engine/tests/engine_integration/test_agent2_contract.py`.
3. No new code path may produce a finding without a validated `ExecutionResult`.
4. Run the tests and the trust gate before opening a PR:

   ```bash
   python -m pytest engine/tests/provenance engine/tests/security -q
   python -m engine.security.trust_gate --root .
   ```

---

## License

The application metadata in `security/main.py` declares **MIT**, but **no `LICENSE` file is currently committed**.
Add one before distributing — without a committed license there is no explicit grant to reuse this code.
