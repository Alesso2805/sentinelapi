# Architecture rules

Oct 22, 2026 · Sources: [SPEC.md](SPEC.md), [BACKLOG.md](BACKLOG.md), [CLAUDE.md](../CLAUDE.md), the README, the module docstrings and [the ADRs](adr/).

Each rule is one sentence that a test can prove or refute. A rule about "every" module, backend, setting or route is checked by a test that walks the whole list, so something new that breaks it fails without anyone adding a case. The tests do not exist yet: they are SEN-15. AR-16 to AR-18 were proposed rules until the product owner adopted them on 2026-10-22.

## Rules

| ID | Rule | Origin | How it is verified |
| --- | --- | --- | --- |
| AR-01 | Every module under `sentinelapi/domain` imports only the standard library and `sentinelapi.domain`. | README › Architecture ("never imports FastAPI, Redis, or SQLAlchemy"); `domain/entities.py` docstring; ADR-0001 | Pytest: parse every `.py` under `domain` with `ast` and assert each import is in `sys.stdlib_module_names` or starts with `sentinelapi.domain`. |
| AR-02 | Every module under `sentinelapi/detectors` imports only the standard library, `jwt` (PyJWT), `sentinelapi.domain`, `sentinelapi.storage.backend` and `sentinelapi.detectors`. | README › Architecture ("depends only on domain/ + storage protocol"); ADR-0001 | Pytest: the same `ast` walk with that allowlist. An allowlist, not a denylist, so a new I/O library fails too. |
| AR-03 | `sentinelapi.storage.backend` imports only the standard library. | `storage/backend.py` docstring ("the seam between logic and infra"); ADR-0001 | Pytest: `ast` walk of that module. |
| AR-04 | Inside `sentinelapi`, only `storage.redis_backend` imports `redis`, only `audit` imports `sqlalchemy` and `alembic`, and only `middleware` and `integration` import `starlette` or `fastapi`. | README › Architecture; SPEC › Architecture (module table) | import-linter `forbidden` contracts, one per third-party package, from every other module. |
| AR-05 | No module of `sentinelapi` imports `examples`. | SPEC › Architecture ("nothing in `sentinelapi` imports it") | import-linter `forbidden` contract. |
| AR-06 | Every module of `sentinelapi`, except `storage.redis_backend`, imports in an environment that has only the required dependencies. | SPEC › Non-functional requirements › Reproducibility; ADR-0008 | CI job: `uv sync --frozen --no-dev` with no extras, then import every module found by `pkgutil.walk_packages`. |
| AR-07 | Every implementation of `CounterBackend` passes the same contract suite: fixed windows started by the first hit, atomic increments under concurrency, `set_if_absent` true exactly once per key and TTL, and `reset` clearing both kinds of key. | README ("without a single line of detector code changing"); ADR-0002 | Pytest in `tests/contract/`: a fixture parametrized over every class in `sentinelapi.storage` that structurally implements the protocol, with Redis from CI's service, and an injectable clock. |
| AR-08 | No detector raises on attacker-controlled input: malformed or oversized tokens, usernames and paths produce an event or `None`. | SPEC › Non-functional requirements ("a false negative over blocking someone"); `jwt_replay.py` catches token errors on purpose | Pytest: each detector's public method fed a fixed corpus (empty, 1 MB, non-UTF-8, control characters, malformed JWTs), asserting the return type. |
| AR-09 | Every field of `SentinelSettings` appears in `.env.example` with its default. | README › Configuration ("see `.env.example`") | Pytest: iterate `SentinelSettings.model_fields` and parse `.env.example`. From SEN-37 the same test checks the README's configuration table. |
| AR-10 | With `SENTINEL_ENV=production`, the settings refuse a missing, example or short (under 32 bytes) JWT secret, a missing audit hash key, and the memory backend unless explicitly allowed. | SPEC › Non-functional requirements › Security; CLAUDE.md ("production refuses default secrets") | Pytest: build `SentinelSettings` for each bad case and expect a validation error. |
| AR-11 | The audit table's SQLAlchemy model and its Alembic history describe the same schema, and the history is reversible on Postgres. | SPEC › Data model › Rules; ADR-0006 | Integration test on Postgres: `upgrade head`, `alembic check` reports nothing, then `downgrade base` → `upgrade head` with no table left behind. |
| AR-12 | In the demo stack, the app's database role cannot UPDATE or DELETE rows of `sentinel_security_events`. | `audit/models.py` docstring ("append-only on purpose"); SPEC › Data model › Rules | Integration test on Postgres: connect as the app role and expect both statements to fail with a permission error. |
| AR-13 | No raw client address, username or token is written to the audit table or to the security log. | `detectors/fingerprint.py` docstring ("without becoming a raw trove of PII"); SPEC › Non-functional requirements › Privacy; ADR-0006 | Pytest: run each scenario with known addresses, usernames and tokens, then search every row and every captured log line for them. |
| AR-14 | Every route of the demo app declares a Pydantic response model, and every route except `/health`, `/ready`, `/auth/login`, `/auth/refresh`, the OpenAPI docs and the demo-mode routes requires authentication. | SPEC › Demo app API contract | Pytest: iterate `app.routes`; assert `response_model` is a `BaseModel` (or a list of one) and that the dependency tree has an auth dependency unless the path is in the public list. |
| AR-15 | The middleware never reads the request body. | README › Architecture ("parse response bodies, which is fragile"); `middleware.py` docstring | Pytest: wrap `receive` with a spy, send requests through the middleware to an app that does not read the body, and assert no `http.request` message was consumed. |
| AR-16 | `time.time`, `time.monotonic`, `datetime.datetime.now` and `datetime.datetime.utcnow` are called only in `sentinelapi/clock.py`; every other module receives a `Clock`. | Proposed rule, adopted 2026-10-22; ADR-0002 | Ruff `flake8-tidy-imports.banned-api`, with a per-file exception for `sentinelapi/clock.py` and the tests. |
| AR-17 | No public method of a detector takes a framework object: detectors receive domain types and plain values. | Proposed rule, adopted 2026-10-22; ADR-0001; ADR-0004 | Pytest: iterate the public methods of every class in `sentinelapi.detectors` and assert no parameter annotation comes from `starlette` or `fastapi`. |
| AR-18 | Inside `sentinelapi` and `examples`, only `sentinelapi/integration.py` constructs backends and detectors. | Proposed rule, adopted 2026-10-22; ADR-0007 | Pytest: `ast` walk for calls to every backend and detector class outside that module. |

## Promises that are not verifiable as written

They come from the README and the docstrings. They are not rules until they are made concrete; this is how I propose to do it.

| Promise | Why it is not verifiable, or not true | Proposal |
| --- | --- | --- |
| "Adaptive threat-detection" | Nothing adapts: every threshold is a fixed setting. | Drop "adaptive" from the tagline (SEN-37), unless a story makes something adapt; none is planned. |
| "Sliding-window rate limiting" | Redis counts in fixed windows; the memory backend extends its window on every hit. | Say "fixed-window" (ADR-0002, SEN-37). SEN-39 offers a sliding window as an option. |
| "Provably correct on its own" | Tests are not proofs. | Say "tested without any external service", which AR-01 to AR-03 and the unit tests back. |
| "Pure stdlib unittest, no dependencies at all" | `test_jwt_replay.py` needs PyJWT, and the detectors import it. | Say "no service needed": no framework, database or Redis (SEN-37). |
| "Thread-/task-safe" (`InMemoryBackend`) | `asyncio.Lock` serializes tasks of one event loop, not threads. | Say "safe across the tasks of one event loop" (SEN-16); AR-07's concurrency case checks it. |
| "Every blocking decision written to a queryable audit trail" | The middleware writes every event, blocking or not; brute-force events are written only because the demo's login calls `persist_event` itself. | From SEN-22 the installer wires one audit sink for every detector; from SEN-25 every verdict is counted, identical ones folded into one row. AR-13 and SEN-25's tests check what is written. |

## Why AR-16 to AR-18

| Rule | Why | State on 2026-10-22 |
| --- | --- | --- |
| AR-16, an injected clock (as in Willay) | Window, expiry and replay tests become exact instead of sleeping or patching modules; the audit's probes had to patch `time.monotonic`. | 4 places: `domain/entities.py` and `detectors/jwt_replay.py` (`time.time`), `storage/memory_backend.py` (`time.monotonic`), `audit/models.py` (`datetime.utcnow`). |
| AR-17, detectors receive identity | Keeps the detectors usable from any framework, and the proxy logic (SEN-19) in one place. | Holds: detectors receive a `RequestFingerprint`. |
| AR-18, one composition point | Integrators cannot wire a detector to a different backend by mistake. | No installer yet (SEN-22); the demo wires everything in `main.py`. |

## Tool (confirmed on 2026-10-22)

**import-linter + Pytest architecture tests + Alembic**, all run in CI (SEN-14), as proposed for VeriLedger:

- **import-linter** for the contracts between packages (AR-04, AR-05). It follows imports transitively, which a per-file check does not.
- **Pytest** in `tests/architecture/` for the rules that walk a list: the `ast` allowlists (AR-01 to AR-03), the settings (AR-09), the routes (AR-14) and the request body (AR-15). An allowlist needs code; import-linter's `forbidden` contracts only take a list of packages to forbid, so a new library would slip through.
- **Pytest** in `tests/contract/` for AR-07 and in `tests/unit/` for AR-08 and AR-10.
- **Alembic against a real Postgres** in `tests/integration/` for AR-11 and AR-12, and the audit scan of AR-13.
- **A CI job without dev dependencies** for AR-06.

Alternatives considered: only Pytest with `ast` (no new dependency, but transitive imports would need to be reimplemented), and PyTestArch (less used and slower). Neither checks more than the proposal.

## Which test covers which rule

| Test | Rules |
| --- | --- |
| `pyproject.toml` › `[tool.importlinter]` (`lint-imports`) | AR-04, AR-05 |
| `tests/architecture/test_imports.py` | AR-01, AR-02, AR-03 |
| CI job `import-without-extras` | AR-06 |
| `tests/contract/test_counter_backends.py` | AR-07 |
| `tests/unit/detectors/test_hostile_input.py` | AR-08 |
| `tests/architecture/test_settings_documented.py` | AR-09 |
| `tests/unit/test_settings.py` | AR-10 |
| `tests/integration/test_audit_migrations.py` | AR-11, AR-12 |
| `tests/integration/test_audit_privacy.py` | AR-13 |
| `tests/architecture/test_demo_routes.py` | AR-14 |
| `tests/architecture/test_middleware_body.py` | AR-15 |
| `pyproject.toml` › `[tool.ruff.lint.flake8-tidy-imports.banned-api]` | AR-16 |
| `tests/architecture/test_detectors.py` | AR-17 |
| `tests/architecture/test_composition.py` | AR-18 |

**Rules that will fail on the first run, on their own.** AR-07 (the memory backend's window), AR-10, AR-11, AR-12, AR-13, AR-14, AR-16 and AR-18. AR-06 fails today (greenlet) but passes once SEN-11, which comes first in Sprint 1, is merged. SEN-15 lands the tests with those rules marked `xfail` and the story that fixes each, so CI is green and the debt is visible; removing an `xfail` is part of the fixing story's DoD.
