# Target Compatibility

This document records which target protocols RedOS supports, how it discovers
each one, and the known limitations. It was produced by the validation phase
(`engine/tests/targets/`): 27 tests across structurally different target
emulators. No engine code was modified during this phase — the compatibility
facts below are measured, not asserted.

## Supported target kinds

| Kind                  | Adapter                      | Endpoints used                                    | Capabilities discovered |
| --------------------- | ---------------------------- | ------------------------------------------------ | ----------------------- |
| `openai_compatible`   | `OpenAICompatAdapter`        | `POST /chat/completions`                          | chat, tools*            |
| `anthropic_compatible`| `AnthropicAdapter`           | `POST /v1/messages` (content blocks)              | chat                    |
| `local_model`         | `LocalModelAdapter`          | `POST /v1/chat/completions` (OpenAI surface)      | chat                    |
| `custom_http`         | `CustomHTTPAdapter`          | configurable path, body template, dot-paths       | chat, tool calls*       |
| `agent`               | `AgentAdapter`               | `/chat/completions`, `GET /tools`, `POST /tools/{name}/invoke` | chat, tools (names + schemas), tool execution |
| `rag`                 | `RAGAdapter`                 | `/chat/completions`, `POST /retrieve`             | chat, retrieval         |

\* Tool capability for `openai_compatible`/`custom_http` is declared by
configuration (`extra.tool_invoke_url`), not observed — see Limitations.

## What was validated

For every supported kind, a structurally different emulator was built
(`engine/tests/targets/emulators.py`) and the full pipeline executed:
registration → reconnaissance → attack-surface discovery → hypothesis
generation → experiment selection → adaptive attack → evidence → finding →
capability gating → replay/regression.

The emulators differ in protocol shape, response schema, tool names, retrieval
structure, and failure behavior — none of them reuse the internal test target:

| Emulator            | Protocol difference from the internal test target                  |
| ------------------- | ------------------------------------------------------------------ |
| `openai_bare`       | chat-only; no tool surface at all (no-tools case)                  |
| `agent_tools`       | tool names `execute_command`/`query_database`/`read_local_file` (different from payload defaults) |
| `anthropic`         | `/v1/messages` content-block schema                                |
| `ollama`            | local model behind the OpenAI-compatible `/v1` surface             |
| `custom_http`       | `{"prompt": [...]}` → `{"reply": {"text": ...}}`, no OpenAI conventions |
| `rag_variant`       | retrieval returns `{"results": [{"content": ...}]}` instead of `{"documents": [{"text": ...}]}` |
| `auth`              | 401 unless a valid bearer credential is presented                  |
| `timeout`           | chat endpoint sleeps 2s per request                                |
| `malformed_*`       | non-JSON body, missing `choices`, wrong-type `content`             |
| `flaky`             | two 503s then success                                              |
| `strict_no_tools`   | `agent` kind declared, but no `/tools` and the model refuses tool requests |

## Edge cases covered

- **No tools** — `openai_bare`: no tool hypothesis, no tool-family experiments
  are ever selected.
- **Different tool names** — `agent_tools`: discovery observes the real names;
  `unsafe_tool_call.shell`/`.sql` succeed through the observed tools while
  `tool_abuse.negation` fails honestly (its payload hardcodes the catalog
  default name `read_file`).
- **Different RAG structure** — `rag_variant`: retrieval parsing accepts
  `documents`/`results`/raw lists and `text`/`content` keys; `rag_poisoning.plant`
  succeeds through the variant structure.
- **Missing capabilities** — `strict_no_tools`: config-declared tool
  capability produces a tool hypothesis, but every tool attack fails honestly;
  no fabricated success.
- **Malformed responses** — non-JSON and wrong shapes produce
  INDETERMINATE/failure with an `error` evidence event; no crashes.
- **Timeouts** — per-turn timeout → `TIMED_OUT` execution, `indeterminate`
  outcome, `timeout` evidence event.
- **Authentication** — wrong key → 401 → INDETERMINATE with `error` event;
  valid key → pipeline runs normally.
- **Partial failures** — two 503s are absorbed by the retry loop
  (`max_retries=2`, `execution.retry` audit events); the third attempt succeeds.

## Known limitations (measured)

1. **Tool capability is partly assumption-based.** `ReconnaissanceRunner`
   seeds `tool_capability` from configuration (`tool_invoke_url` or `agent`
   kind), not from observation. When the tool listing is unavailable, the
   surface reports `tool_capability=True` with zero observed tool names. The
   system does not fabricate success in this state — tool attacks fail
   honestly — but the hypothesis is generated from an assumption. Evidence
   later corrects the record. See `docs/GENERALIZATION_REPORT.md` for the
   measured behavior on `strict_no_tools`.
2. **Tool listing is only probed on `agent` kind.** `list_tools` is not
   implemented for `openai_compatible`, `anthropic_compatible`, `local_model`,
   or `custom_http`; those targets cannot advertise tools through discovery,
   only through configuration.
3. **Delegation is probed only when tool names are advertised.** A chat model
   that would delegate to unadvertised tools is not probed (honest `None`
   fact).
4. **Payload catalog tool names are defaults.** Attacks that reference a tool
   by name (`tool_abuse.negation` → `read_file`) fail honestly against targets
   with differently-named tools.
5. **MCP and multi-agent targets are unsupported.** `TargetKind` has no
   `mcp`/`multi_agent` values; attempting to construct them raises
   `ValueError` cleanly. No adapter exists.
6. **Ollama is supported through its OpenAI-compatible `/v1` surface**
   (`local_model` kind); the native `/api/chat` protocol is not implemented.
7. **Remediation and full attack-graph stages are not implemented.** The
   per-target pipeline covers registration → recon → surface → hypotheses →
   selection → execution → evidence → finding → capability graph
   (`DependencyGraph` gating) → replay/regression (`RegressionCase`).
   A remediation module and a true attack-graph layer do not exist in the
   codebase; the docs that describe them are design documents.

## Compatibility contract

- No target-specific code exists in `engine/`. Every adapter, probe, and
  payload is written against the generic model; the emulators in
  `engine/tests/targets/` are the only target-specific artifacts, and they are
  test fixtures.
- All outcomes are produced by real executions (live provenance); the
  `FindingsGateway` validates evidence chains and rejects mock evidence.
- Unsupported capabilities fail loudly and cleanly (`ConfigurationError`,
  `ValueError`, honest `UnsupportedOperation` probes) — never silently.