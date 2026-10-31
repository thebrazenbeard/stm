# STM — Bounded short-term memory for AI applications

STM is a dependency-free Python library for **session-scoped working context**. Applications can store attributed observations, retrieve relevant records, and assemble bounded context for a language model or other consumer. Optional components support a separately authorized SQLite conversation archive, retention supervision, local process gateways, and a proposed long-term-memory handoff contract.

STM is **model-independent**: it does not require a particular model, operating-system installation, cloud service, or memory provider. It does not authenticate a user, own an agent's identity, authorize tool effects, or train model weights.

**Current status:** Version 0.7.0, source-stage research/engineering candidate. The working-memory APIs and several optional governance components are implemented and tested. No complete signed-in host deployment, private long-term-memory writer, production deletion service, or independent end-to-end authorization system is qualified.

## Install and try it

Use Python 3.10 or newer. No runtime dependencies are declared in `pyproject.toml`.

```bash
git clone https://github.com/thebrazenbeard/stm.git
cd stm
python -m pip install -e .
python -m unittest discover -s tests -v
python examples/basic.py
```

The Git URL is a source-checkout example, **not** a claim that a package is published on PyPI. Examine code and privacy controls before using real conversation data.

### Session working memory

```python
from stm import STM

memory = STM()
session = memory.open_session(
    tenant_id="example-tenant",
    owner_id="person-1",
    agent_id="assistant-1",
    session_id="conversation-1",
)

item = session.append(
    "The build review is on Friday",
    role="user",
    source="conversation:turn-7",
    kind="observation",
)
print([record.content for record in session.retrieve("build review")])

context = session.assemble_context(
    "When is the build review?", token_budget=1024
)
print(context.text)

session.correct(
    item.id,
    "The build review is on Thursday",
    expected_version=1,
)
session.delete(item.id)
```

The application supplies scope identifiers; **matching identifiers do not authenticate the caller**. Context text is explicitly attributed, untrusted data, not a trusted system instruction. The default budget counter counts UTF-8 **bytes**, not model tokens; substitute a model-specific token counter and account for prompt-template overhead when necessary. Pinned records are included or `BudgetOverflow` is raised.

## Implemented capabilities and boundaries

| Component | What it provides | What it does not prove |
| --- | --- | --- |
| `STM` / `MemorySession` | Explicit tenant/owner/agent/session scopes; bounded in-process records; correction, TTL, deletion, lexical retrieval and context packing | Caller identity, factual correctness, or model behavior |
| Storage and checkpoints | In-memory defaults and opt-in checksummed JSON checkpoint/restore | Encrypted, tamper-proof, forensically erased storage |
| Retrieval and cache adapters | Deterministic lexical/recency ranking, injectable semantic retrieval and a prompt-prefix cache | Semantic accuracy, exact backend token counts, or inference KV-cache reuse |
| `ConversationArchive` | Opt-in, source-attributed SQLite historical turns with host-provided authorization callback | Automatic history access, current consent, trusted identity or production encryption |
| Retention wrappers / clock fence | Scoped expiration, supervised sweep primitives, rollback-resistant high-water clock checks, explicit maintenance receipts | An installed scheduler, complete journal/backup erasure or immunity to all clock attacks |
| HMAC broker and cleanup authority | Short-lived signed scope grants and separate limited maintenance capabilities | Host authentication, key custody, revocation or replay protection without trusted host components |
| Windows / Android / Linux gateways | Prototype local-process identity checks and narrow working-memory operations | Network device identity, Android platform attestation, cross-machine authentication or production service integration |
| `DeepMemoryHandoff` | Opt-in historical export protocol through an injected, governed destination and separately verified receipt | A connected private destination, automatic export or long-term memory promotion |

SQLite history is **not** created by the default `STM()` call. Archived material is historical evidence and is never automatically treated as a current instruction, preference, self-model, or authorization. The host must authenticate principals and apply consent/privacy decisions on every authorized archive operation. See [archive contract](docs/conversation_archive.md), [source implementation](src/stm/archive.py), and [archive example](examples/conversation_archive.py).

### Retention is a host obligation

The repository contains an **opt-in 30/45-day policy implementation**: a source turn may become eligible for separately consented export review after 30 days, while local source expiry remains at 45 days even when handoff is pending or fails. This is a specific policy profile, **not a default requirement for all STM adopters** and not an installed host scheduler.

The `DurableClockFence`, `SupervisedRetention`, and `run_guarded_once` primitives help a host detect some unsafe clock/sweep states and refuse to report incomplete work as successful. They cannot themselves supervise recurring execution, retire every backup, or prove physical erasure. Hosts must bind the same protected clock and complete consent/authority registry to reads, writes and sweeps; direct access to raw archives bypasses the governed wrapper.

See [30/45-day policy](docs/retention_30_45_v06.md), [durable fence qualification](docs/retention_clock_fence_v07.md), [one-shot host contract](docs/host_retention_one_shot_source.md), and the [synthetic one-shot demonstration](examples/host_retention_one_shot.py).

### Host-owned identity, consent and effects

STM is a memory component inside a larger trust boundary. A production embedding must independently provide:

1. Verified and non-reassignable caller, tenant, model/provider and session bindings. Caller-supplied strings, browser headers and loopback addresses do not establish identity.
2. Current, narrowly scoped consent and authorization for archive reads, writes, correction, deletion and any external export. Neither historical records nor HMAC signatures alone grant these effects.
3. Protected secrets/keys, replay and revocation records, storage permissions/encryption, supervised expiry, log/WAL/backup cleanup, and auditable failures.
4. A genuinely private long-term destination with deletion/correction/revocation controls and separate permission. The public `deepmemorystorage` GitHub repository is **not** a safe destination for private conversations.

Windows account-SID and Linux `SO_PEERCRED` checks are local process evidence with documented limits; the Android registration resolver is host-supplied, not an Android attestation implementation. Read [security review](docs/security_review.md), [known limitations](docs/limitations.md), [platform handoff research](docs/windows_android_deepmemory_handoff_v05.md), and [retention qualification](docs/privacy_retention_v04.md).

## Tests and examples

```bash
python -m unittest discover -s tests -v
python examples/basic.py
python examples/conversation_archive.py
python examples/authenticated_host_demo.py
python examples/handoff_review_mock.py
python examples/retention_window_3045.py
python examples/host_retention_one_shot.py
python benchmarks/bench_stm.py
python benchmarks/bench_archive.py --iterations 30
```

These are **source and synthetic-scenario checks**. They are not real personal-data processing, signed-in provider qualification, runtime authentication, neural learning, clinical memory restoration, or proof of complete retention enforcement. Reproducible benchmark fixtures and methodology are documented in [the review](docs/security_review.md); do not interpret synthetic benchmark improvements as general model quality.

Further design and qualification records: [architecture](docs/architecture.md), [research](docs/research.md), [v0.2 archive qualification](docs/v02_qualification.md), [v0.4 host-auth qualification](docs/v04_qualification.md), and [v0.5 handoff qualification](docs/v05_qualification.md). Historical Vera-specific host reports are retained in `docs/` as **case studies**, not prerequisites or current deployment claims.

## Licensing

The repository is publicly visible, but **no repository-wide redistribution license has been selected**. Public availability does not itself grant permission to redistribute, sublicense, or commercially reuse STM. Inspect rights and obtain permission before incorporation into another product.
