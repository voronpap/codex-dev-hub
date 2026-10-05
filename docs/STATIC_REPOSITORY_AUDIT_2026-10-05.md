# Статичний аудит репозиторію DevFabric / codex-dev-hub

Дата зрізу: **2026-10-05**  
Режим: **read-only static review**  
Репозиторій: `voronpap/codex-dev-hub`

## A. Висновок

Аудит охопив поточну систему цілком: Project Brain, Context Builder, локальне й хмарне делегування, provider routing, ResourceController, ledger/accounting/outbox, MCP boundary, frozen benchmark harness, Stage 3G qualification, конфігурацію, CLI, deployment/evidence tooling та актуальну документацію.

Статично підтверджено, що значна частина базових fail-closed механізмів реалізована послідовно: Project Brain обмежує індексацію проєктом і Git-станом; Context Builder детерміновано формує обмежений пакет і повторно перевіряє provenance перед dispatch; cloud export зв'язує task/source/selected/released hashes; provider execution не має автоматичного retry/fallback після неоднозначного dispatch; unknown usage зберігається як liability; paid execution вимкнене; заяви про semantic quality, savings і delegation value залишаються `null` до benchmark evidence.

Водночас поточний зріз не можна вважати production-ready. Виявлено **3 підтверджені P1** та **8 підтверджених P2** дефектів. Найнебезпечніші першопричини:

1. Ledger не має незмінної application/account identity, тому зміна `state_root` створює новий облік без replay/liability/live-slot/one-shot grant history, а стороння SQLite-база може бути прийнята та змінена міграціями.
2. Stage 3G qualification receipt не зв'язує всю сукупність host-sensitive evidence; preflight, runtime isolation, ledger, evaluator і фактичний run можуть належати різним середовищам або artifacts.
3. B-arm може бути записаний як завершений після одного MCP-виклику навіть без валідного handoff/accounting observation.

P0-дефектів у прочитаному коді не підтверджено. Висновки є статичними: вони встановлюють наявність або відсутність простежуваних control/data paths, але не доводять runtime-працездатність середовища.

## B. Обсяг і джерела

### Git snapshot

| Поле | Значення |
|---|---|
| Branch | `feat/stage3g-approved-call` |
| HEAD | `052e202906ed90baf3ca3a9baf7b4ef50d8ac8b6` |
| Local `origin/main` | `da935f6cf9612b5ce8eea3b0ad6bc5694b51f96f` |
| Відносно `origin/main` | 46 commits ahead, 19 commits behind |
| Робоче дерево | має локальні зміни |

Локальні зміни, включені до аудиту, але відсутні у HEAD:

- `src/devhub/ollama.py`: дозволено версії `0.34.2` і `0.35.0` замість лише `0.34.2`;
- `tests/test_ollama.py`: додано synthetic test для version pin `0.35.0`.

Через divergence цей audit описує **саме активну branch разом із локальними змінами**, а не інтегрований стан `main`. Main-only зміни DevFabric public docs, demo, `UsageSummaryV1`/footer та role-architecture proposal у цьому checkout відсутні.

### Перевірені підсистеми

- entrypoints і конфігурація: `__main__.py`, `cli.py`, `config.py`, server modules;
- Project Brain: `brain.py`, `brain_store.py`, `brain_models.py`;
- Context Builder і provenance: `context.py`, `context_models.py`, `cloud_export.py`;
- delegation: `delegate.py`, `delegate_server.py`, local/cloud servers;
- routing/admission: `router.py`, `registry.py`, `resources.py`, `execution.py`, `controller.py`;
- providers: Ollama, Groq, Gemini та їх gates/permits;
- accounting: ledger, reservations, dispatch, settlement, events/outbox, quotas;
- frozen benchmark: protocol, fixtures, oracles, plan, launch, bridge, run, evaluator, review;
- Stage 3G qualification: preflight, isolation/effects boundary, runtime/evaluator build evidence, Candidate B patches/proofs;
- scripts, OCI/Docker-related artifacts, CI policy, package metadata;
- README, ADR, stage specs, security/principles/provider docs, catalog/research docs та machine-readable evidence.

Тести читалися лише як допоміжне свідчення контрактів. Їх наявність або історичний CI не використані як доказ runtime-поведінки.

### Основні джерела вимог

- `README.md`, `ROADMAP.md`, `ARCHITECTURE.md` за наявності в активній branch;
- [PRINCIPLES.md](PRINCIPLES.md), [SECURITY.md](SECURITY.md), [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md), [FREE_FIRST_ROUTING.md](FREE_FIRST_ROUTING.md);
- [V1_CONTRACTS.md](V1_CONTRACTS.md), [V1_TECHNICAL_PROPOSAL.md](V1_TECHNICAL_PROPOSAL.md), [V1_IMPLEMENTATION_PLAN.md](V1_IMPLEMENTATION_PLAN.md);
- [STAGE3A.md](STAGE3A.md)–[STAGE3G-C.md](STAGE3G-C.md) і Stage 3G protocol/admission/effects-boundary documents;
- ADR 0001–0010;
- frozen protocol/config/fixture/oracle/evidence JSON;
- source code й package/CI configuration.

Roadmap-only і design-only напрями не оцінювалися як дефекти чинного етапу: role runtime, Explorer/Researcher/Worker execution, Strategy Registry, Startup UX, AI Platform, optional compression, Session Observer, additional providers.

## C. Матриця відповідності

`IMPLEMENTED` нижче означає статично простежену реалізацію, а не виконану runtime verification.

| ID | Джерело | Вимога | Етап | Статус | Реалізація / доказ або прогалина |
|---|---|---|---|---|---|
| RQ-01 | ADR-0001, README | Codex лишається головним orchestrator | чинна | PARTIAL | Delegate/MCP path не замінює Codex, але production Codex host admission лишається patch/evidence artifact, а не інтегрованим shipping runtime. |
| RQ-02 | ADR-0003, STAGE3A | Project Brain project-scoped, Git-bound, provenance-aware | чинна | IMPLEMENTED | `brain.py`, `brain_store.py`: tracked/not-ignored filtering, root containment, Git/hash binding, source IDs. |
| RQ-03 | PROJECT_CONTEXT, STAGE3A | Не індексувати symlink/junction escape, binary/oversized/untracked files | чинна | IMPLEMENTED | Source intake має root/path/type/size checks і Git eligibility. |
| RQ-04 | STAGE3B, V1 contracts | Context Builder deterministic, bounded, deduplicated | чинна | IMPLEMENTED | `context.py`, `context_models.py`: fixed ordering, budgets, selected source records. |
| RQ-05 | STAGE3B/3F | Provenance повторно перевіряється перед dispatch/export | чинна | IMPLEMENTED | Local/cloud paths revalidate source identity/hash/package before provider send. |
| RQ-06 | SECURITY, ADR-0007 | Eligibility/privacy/paid policy fail closed | чинна | IMPLEMENTED | Unknown/ineligible resources deny; paid remains disabled; cloud export is explicit and bound. |
| RQ-07 | FREE_FIRST_ROUTING | FREE → LOCAL → PAID policy | чинна концепція | PARTIAL | Main Stage 3F flow selects a provider profile before Router; Router receives one exact resource, тому загальний cross-provider fallback order не є production orchestration path. |
| RQ-08 | STAGE3F | `devhub_delegate` is the unified bounded MCP boundary | чинна | IMPLEMENTED | `delegate_server.py` validates `DelegationRequest`, invokes existing runtime, returns structured handoff. |
| RQ-09 | STAGE3F | Retry=0 and no fallback after ambiguous dispatch | чинна | IMPLEMENTED | Provider adapters issue one request; dispatch is recorded before send; ambiguous outcome becomes unknown liability. |
| RQ-10 | ADR-0007, STAGE3F | Reservation → dispatch → settle/release is durable and authoritative | чинна | PARTIAL | Ledger flow exists, але startup recovery can be bypassed and ledger identity/reset protection is missing; див. AUD-001/AUD-005. |
| RQ-11 | STAGE3F | Unknown usage is not zero and blocks unsafe reuse | чинна | IMPLEMENTED | Unknown completion remains liability; settlement requires complete usage. |
| RQ-12 | SECURITY | Secrets excluded from DTO/evidence/log output | чинна | IMPLEMENTED | Provider credentials read at process boundary; DTOs/evidence avoid secret values; fixed endpoints are used. |
| RQ-13 | STAGE3E/3F | Cloud export binds exact approved task/context/source set | чинна | IMPLEMENTED | `cloud_export.py` seals task/source/selected/released identities before cloud execution. |
| RQ-14 | STAGE3G-A/B | Frozen benchmark uses 12 fixtures, 12 oracles, paired A/B, alternating order, fresh sessions | чинна, not run | IMPLEMENTED | Protocol/plan tooling defines 24 sessions and immutable fixture/oracle hashes. |
| RQ-15 | STAGE3G | Dry-run performs no real Codex/provider execution | чинна | IMPLEMENTED | Dry-run constructs/validates plan without launching executor/provider path. |
| RQ-16 | STAGE3G | `execution_ready` only after all qualification evidence is bound | чинна | CONTRADICTED | Receipt and runtime enforce only a subset of environment/artifact identity; див. AUD-002. |
| RQ-17 | STAGE3G | B arm must prove one successful reviewed delegation, not merely one call | чинна | CONTRADICTED | Completion can be accepted with `delegation_count=1` and no valid handoff; див. AUD-003. |
| RQ-18 | Stage 3G effects boundary | Guest cannot mutate repo/state/evidence and runtime is OCI/Linux-isolated | qualification | PARTIAL | Isolation tooling/evidence exists, але cross-host binding is incomplete and active Stage 3G-C remains open. |
| RQ-19 | Stage 3G router admission | A exposes zero tools; B only trusted `devhub_delegate`; origin/schema/generation are sealed | qualification | PARTIAL | Internal router/security matrix and production-equivalent handler evidence exist; actual shipping host activation/process proof remains incomplete. |
| RQ-20 | Stage 3G claims | No semantic/value/savings claim before frozen benchmark | чинна | IMPLEMENTED | `semantic_acceptance`, `quality_benchmark`, `delegation_value`, `savings` remain null. |
| RQ-21 | README/status docs | Stage 3G-C remains OPEN, `execution_ready=false`, benchmark not run | чинна | IMPLEMENTED | Evidence/status consistently keeps gate open; docs drift exists elsewhere. |
| RQ-22 | ADR-0010 / Issue #38 | Measured, known-zero, estimated and unknown telemetry remain distinct | merged on main, absent here | UNVERIFIABLE_STATIC | Active branch is behind main and does not contain current `UsageSummaryV1`; this checkout cannot substantiate merged implementation. |
| RQ-23 | Role architecture PR | Task/Role Router separate from Provider Router; role runtime deferred | design-only | INTENTIONALLY_DEFERRED | No runtime role routing found, which matches frozen Stage 3G sequencing. |
| RQ-24 | Startup/Control UX roadmap | `devhub up/status/doctor/down` unified control plane | future | INTENTIONALLY_DEFERRED | Current default CLI is status-oriented; startup CLI is correctly not treated as implemented. |
| RQ-25 | Security/distribution | Repository should have explicit licensing before external distribution | current distribution concern | MISSING | No `LICENSE` file found in audited branch. |

## D. Знахідки

### P1 — високий пріоритет

#### AUD-001 — Ledger не має незмінної application/account identity

- **Впевненість:** висока.
- **Пов'язані вимоги:** RQ-06, RQ-09, RQ-10, RQ-11.
- **Місця:** [`delegate.py`](../src/devhub/delegate.py#L123-L129), [`ledger.py`](../src/devhub/ledger.py#L80-L91), [`controller.py`](../src/devhub/controller.py#L60-L64).

`state_root` визначає шлях SQLite ledger, але сама база не містить незмінного application/account identity, який зв'язує її з DevFabric instance/project і забороняє непомітну заміну. Під час відкриття schema version/migrations приймаються як достатня ідентифікація бази.

**Мінімальний сценарій із коду:** оператор або launcher запускає той самий task із новим `state_root`. Створюється чиста база без replay row, unknown-liability state, live-slot state та one-shot cloud grant history. Альтернативно за очікуваним шляхом лежить інша SQLite-база: bootstrap/migration може створити у ній DevFabric tables без foreign-database rejection.

**Наслідок:** durable accounting перестає бути єдиною authority через зміну path; replay/unknown-usage/payment controls можуть бути скинуті без явної reset procedure; сторонній SQLite state може бути змінений.

**Напрям виправлення:** додати immutable ledger identity (`application_id`, schema family, project/account binding), перевіряти її до migrations, fail closed для non-empty foreign DB, захистити root від symlink/reparse substitution і зробити reset окремою явною операцією з audit evidence.

#### AUD-002 — Stage 3G qualification evidence можна скомпонувати з різних середовищ

- **Впевненість:** висока.
- **Пов'язані вимоги:** RQ-16, RQ-18, RQ-19.
- **Місця:** [`experiment_preflight.py`](../src/devhub/experiment_preflight.py#L92-L103), [`experiment_preflight.py`](../src/devhub/experiment_preflight.py#L292-L313), [`experiment_run.py`](../src/devhub/experiment_run.py#L147-L167), [`experiment_run.py`](../src/devhub/experiment_run.py#L237-L239).

Preflight receipt містить hashes середовища й artifacts, але `require_ready()` перевіряє лише підмножину: image/commit/protocol/plan/bootstrap identity. Runtime bindings для environment/isolation proof, ledger й actual evaluator можуть бути іншими, не будучи криптографічно/структурно пов'язаними з receipt.

**Мінімальний сценарій:** receipt створено на host A з isolation proof A та ledger A. Run на host B подає ті самі required high-level hashes, але інші environment manifest/isolation evidence/ledger/evaluator paths. Поточний acceptance path не встановлює їх повної тотожності.

**Наслідок:** `execution_ready` або run може спиратися на несумісну композицію CI, Windows і Linux/OCI evidence, що прямо суперечить single intended environment requirement.

**Напрям виправлення:** зробити qualification receipt єдиним immutable manifest усіх host-sensitive artifacts; runtime має приймати лише exact hashes/IDs із receipt, включно з environment, isolation, auth/egress, ledger identity, evaluator image/binary, runtime binary/config та Ollama identity.

#### AUD-003 — B-arm completion не вимагає валідного handoff/accounting observation

- **Впевненість:** висока.
- **Пов'язані вимоги:** RQ-17, RQ-20.
- **Місця:** [`experiment_launch.py`](../src/devhub/experiment_launch.py#L105-L133), [`experiment_launch.py`](../src/devhub/experiment_launch.py#L474-L508), [`experiment_bridge.py`](../src/devhub/experiment_bridge.py#L111-L121), [`experiment_run.py`](../src/devhub/experiment_run.py#L297-L316).

`DelegationObservation` вимагає лише `delegation_count == 1`. MCP error, malformed response або відсутній `structuredContent` можуть залишити `handoff=None`, але Codex final/exit path усе одно дозволяє записати session як completed.

**Мінімальний сценарій:** модель викликає `devhub_delegate` один раз; tool повертає error без валідного `DelegationResult`; Codex завершує відповідь. Bridge рахує один виклик, run приймає completion, хоча provider/accounting result не спостережений.

**Наслідок:** paired benchmark може порівнювати A з фактично невдалою B delegation і приписувати B результат, не доведений через reviewed execution boundary.

**Напрям виправлення:** B completion має fail closed без валідного schema-bound handoff, completed accounting transition, matching request/task/session identity, zero retry/fallback і підтвердженої validation metadata.

### P2 — середній пріоритет

#### AUD-004 — Private context/export/state artifacts створюються без explicit restrictive permissions і retention policy

- **Впевненість:** висока для permission behavior; runtime effective ACL залежить від ОС.
- **Пов'язані вимоги:** RQ-05, RQ-06, RQ-12, RQ-13.
- **Місця:** [`local.py`](../src/devhub/local.py#L72-L81), [`local.py`](../src/devhub/local.py#L167-L171), [`cloud.py`](../src/devhub/cloud.py#L301-L304), [`context_models.py`](../src/devhub/context_models.py#L70-L85).

Context packages можуть містити private source excerpts. Запис відбувається зі стандартними inherited permissions, без explicit restrictive mode/ACL, secure creation, lifecycle cleanup чи retention bound.

**Сценарій:** shared/misconfigured state directory успадковує читання ширшій групі; private package/export response лишається на диску після task completion.

**Наслідок:** витік source content поза intended process boundary.

**Напрям виправлення:** atomic create з restrictive permissions, state-root permission validation, no-follow/reparse checks, explicit retention/cleanup та redacted evidence separation.

#### AUD-005 — Startup recovery виконується після replay lookup і може бути пропущений

- **Впевненість:** висока.
- **Пов'язані вимоги:** RQ-10, RQ-11.
- **Місця:** [`delegate.py`](../src/devhub/delegate.py#L123-L142), [`local.py`](../src/devhub/local.py#L106), [`cloud.py`](../src/devhub/cloud.py#L122).

Delegate path спочатку виконує replay lookup, а recovery викликається пізніше всередині local/cloud runtime. Replay hit може повернутися без reconciliation pending/dispatched rows. Replay response також відображає stored result, а не обов'язково актуальний accounting state після crash recovery.

**Сценарій:** процес падає після dispatch; наступний process receives a replayable key and returns before startup recovery. Outstanding state лишається unreconciled.

**Наслідок:** live slots/liability/state можуть залишатися stale довше за заявлену startup recovery semantics.

**Напрям виправлення:** recovery один раз при runtime/bootstrap до будь-якого replay read; replay view формувати з authoritative current accounting state.

#### AUD-006 — Concurrent capability refresh може self-deny обидва requests і залишити reservation hold

- **Впевненість:** висока.
- **Пов'язані вимоги:** RQ-06, RQ-10.
- **Місця:** [`execution.py`](../src/devhub/execution.py#L11-L40), [`registry.py`](../src/devhub/registry.py#L54-L69), [`controller.py`](../src/devhub/controller.py#L294-L303).

Кожний refresh перезаписує registry revision. Request A резервує ресурс із revision A; request B refreshes registry to revision B; dispatch A rejects stale revision. Детермінований `Denied` на dispatch path не проходить узгоджений release у всіх paths.

**Сценарій:** два одночасні однакові requests проходять refresh/reserve interleaving. Перший стає stale через другий; другий може бути заблокований live slot першого.

**Наслідок:** обидві операції fail despite available provider, а hold залишається до recovery/expiry.

**Напрям виправлення:** stable capability snapshots або revision scoped per resource/config; every pre-send denial after reservation must atomically release; додати concurrency invariant around refresh-reserve-dispatch.

#### AUD-007 — Malformed Ollama metadata і filesystem errors виходять за structured handoff boundary

- **Впевненість:** висока.
- **Пов'язані вимоги:** RQ-08, RQ-09.
- **Місця:** [`ollama.py`](../src/devhub/ollama.py#L172-L204), [`local.py`](../src/devhub/local.py#L121-L128).

Ollama metadata parsing припускає dict-shaped model entries, non-null capabilities/model_info і string-compatible merge values. Частина exceptions виникає до/поза narrow adapter catch; filesystem writes також можуть escape як raw exception.

**Сценарій:** `/api/show` або `/api/tags` повертає syntactically valid JSON із `null`/wrong type; source package write отримує permission error.

**Наслідок:** MCP caller отримує transport/internal failure замість deterministic `DelegationResult` із classified reason; reservation/recovery semantics стають складнішими.

**Напрям виправлення:** validate provider JSON through strict models; widen orchestration boundary catch only to translate known integration/filesystem failures into typed fail-closed results while preserving unknown liability after dispatch.

#### AUD-008 — Benchmark executor capture необмежений, stopped containers не видаляються

- **Впевненість:** висока.
- **Пов'язані вимоги:** RQ-14, RQ-18.
- **Місця:** [`experiment_launch.py`](../src/devhub/experiment_launch.py#L293-L323), [`experiment_launch.py`](../src/devhub/experiment_launch.py#L450-L455), [`experiment_launch.py`](../src/devhub/experiment_launch.py#L471-L473), [`experiment_launch.py`](../src/devhub/experiment_launch.py#L509-L513).

Stdout/stderr are accumulated without a byte bound. Container lifecycle stops/kills but does not consistently `rm`, so repeated qualification can accumulate stopped containers and logs.

**Сценарій:** guest/tool emits large output until timeout; host buffers it, then leaves stopped container.

**Наслідок:** memory/disk exhaustion on qualification host and degraded isolation reliability.

**Напрям виправлення:** bounded/spooled capture with truncation metadata, strict output caps, `--rm` or finally-block removal by verified container ID.

#### AUD-009 — Actual B-arm Python runtime не повністю bound до declared implementation commit

- **Впевненість:** висока.
- **Пов'язані вимоги:** RQ-14, RQ-16, RQ-18.
- **Місця:** [`benchmark.py`](../src/devhub/benchmark.py#L185-L197), [`experiment.py`](../src/devhub/experiment.py#L193-L205), [`experiment_run.py`](../src/devhub/experiment_run.py#L282-L288).

Clean-commit verification binds лише selected benchmark/baseline/models files. Plan additionally depends on experiment modules, and child starts environment-dependent `sys.executable -m devhub.delegate_server`. Installed/imported package bytes are not comprehensively bound to implementation commit/artifact identity.

**Сценарій:** environment contains another editable/installed `devhub` or unbound experiment module change while selected clean files match commit.

**Наслідок:** declared implementation commit can differ from code actually executed in B arm.

**Напрям виправлення:** build/install one immutable wheel or source artifact from reviewed commit, hash it, run it by absolute interpreter/environment identity, and bind all launch/orchestration modules into plan/receipt.

#### AUD-010 — Local dirty change допускає Ollama 0.35.0 без qualification evidence

- **Впевненість:** висока.
- **Пов'язані вимоги:** RQ-09, RQ-16.
- **Місця:** [`ollama.py`](../src/devhub/ollama.py#L40), local uncommitted `tests/test_ollama.py`.

Frozen evidence/config у branch pins `0.34.2`; локальна зміна розширює accepted runtime до `0.35.0`. Доданий test підміняє лише `/api/version` string і не кваліфікує actual 0.35 API/schema/model behavior.

**Наслідок:** version gate може прийняти середовище, якого frozen runtime evidence не покриває.

**Напрям виправлення:** або відкотити dirty widening, або провести окремий reviewed compatibility qualification і versioned config/evidence update; synthetic version string не є достатнім.

#### AUD-011 — Failure після `docker create`, але до start, споживає benchmark attempt

- **Впевненість:** висока.
- **Пов'язані вимоги:** RQ-14, RQ-18.
- **Місця:** [`experiment_launch.py`](../src/devhub/experiment_launch.py#L428-L470).

Після успішного `docker create` session transitions to `task_exposed=true`; якщо наступний host step fails до фактичного container start/task read, attempt записується failed і не rerun.

**Сценарій:** create succeeds, artifact/inspect/start preparation fails before guest process reads task.

**Наслідок:** pre-exposure infrastructure failure помилково класифікується як consumed frozen attempt.

**Напрям виправлення:** transition `task_exposed` only at an observable irreversible exposure boundary; pre-start failures should retain a distinct non-exposed terminal state under reviewed rerun policy.

### Статичні ризики та відкриті питання

Ці пункти не класифіковані як підтверджені defects без runtime/environment evidence:

- CONNECT proxy перевіряє authority/public DNS, але source-level path не доводить binding TLS SNI/certificate до approved destination. Через trusted Codex model actual exploit path не встановлено.
- `asyncio.to_thread` cancellation не зупиняє underlying synchronous provider request; це може суперечити durable submit/poll/cancel design, але accepted Stage 3F sync design і post-dispatch unknown-liability handling зменшують ризик double-send.
- Event/reservation tables не мають явної purge/retention policy; можливий необмежений ріст, але operational workload і retention requirement не встановлені статично.

## E. Наскрізні розриви

1. **Provider choice vs Router.** Задекларовано FREE → LOCAL → PAID, але normal Stage 3F flow формує конкретний provider profile до Router. Router приймає exact resource candidate, а не вибирає серед повного eligible set. Це не silent paid fallback, але й не повний deterministic cross-provider routing layer.

2. **Outbox without consumer.** Durable outbox/events зберігаються, але normal production path не має простеженого consumer/ack/retention lifecycle. Це корисна audit trail, але не завершена event delivery subsystem.

3. **CLI vs delegation runtime.** Default `devhub` CLI лишається status-oriented; delegation запускається окремо через `python -m devhub.delegate_server`. Unified startup/control UX є roadmap, не current implementation.

4. **Candidate B proof vs shipping runtime.** Rust patch і evidence доводять окремі router/security/handler properties, але активний repository не містить shipping Codex runtime із завершеним trusted host activation path. Stage 3G-C OPEN є коректним.

5. **Qualification artifacts are not one authority.** Preflight, runtime bindings, evaluator і host evidence існують окремо, але не утворюють один end-to-end immutable chain.

6. **Branch integration gap.** Active PR branch не містить 19 main-side commits, тому merged DevFabric public docs, demo, Issue #38 usage footer і role architecture не можна аудитувати як частину цього checkout.

7. **Durable Brain scope.** File/chunk retrieval реалізовано; durable decisions/task summaries, описані ширше в public narrative, залишаються deferred і не є current storage behavior.

## F. Документація проти коду

- Активний README зупиняється біля ранніх Stage 3E descriptions і використовує старіший branding/status через branch divergence; він не є актуальною public front page main.
- `V1_CORE.md` містить твердження, що coding ще не почався, хоча реалізація значно просунута.
- `ROADMAP.md` лишає Stage 1 interop unchecked і містить encoding/mojibake artifacts.
- README/Project Brain narrative ширше говорить про decisions/task history, ніж фактична retrieval-oriented реалізація.
- Старий Stage 3G-C retry blocker суперечить пізнішому Protocol V2 status, де unsupported overrides вилучені, а `codex_internal_retries=null`.
- Production host admission document спочатку каже, що build-009 не авторизований, а пізніше — що авторизований і заблокований preflight. Хронологія зрозуміла з evidence, але документ не дає одного canonical current status.
- Accepted ADR-0005 називає `httpx`, тоді як adapters використовують stdlib `http.client`, а dependency відсутня у package metadata.
- Accepted six-tool durable submit/poll/cancel design не збігається з пізнішим synchronous one-shot Stage 3F path. Потрібне явне supersession ADR, а не дві одночасно «accepted» архітектури.
- Відсутність `LICENSE` блокує чітке зовнішнє reuse/distribution трактування.

## G. План виправлень

1. **Стабілізувати audited baseline.** Вирішити локальне Ollama 0.35 widening; синхронізувати/перебазувати Stage 3G branch на current main без переписування historical evidence; повторно зафіксувати audit snapshot.
2. **Закрити ledger identity first.** Додати immutable DB/application/project binding, foreign-DB rejection, root/reparse protections і explicit reset protocol. Це prerequisite для надійного accounting та intended-host qualification.
3. **Зробити Stage 3G evidence chain цілісним.** Один signed/hashed qualification manifest має bind host, runtime, isolation, auth/egress, Ollama, ledger, evaluator, protocol/config/plan та executable artifacts.
4. **Зробити B observation fail closed.** Вимагати valid handoff/accounting/validation identity before session completion.
5. **Виправити startup recovery та concurrent capability revision lifecycle.** Recovery до replay; atomic release on pre-send denial; stable snapshots.
6. **Захистити private artifacts.** Restrictive permissions, no-follow paths, retention/deletion і redacted evidence.
7. **Нормалізувати integration failures.** Strict provider response models і typed boundary results without converting post-dispatch ambiguity into safe failure.
8. **Укріпити benchmark executor.** Bounded output capture, container cleanup, correct pre-exposure state, immutable Python runtime artifact.
9. **Узгодити нормативні документи.** Позначити superseded ADR/designs, виправити stage status drift, додати license decision.
10. **Лише після цього** проводити нову intended-host qualification/review. Role runtime, new providers і benchmark execution не повинні випереджати Stage 3G-C closure.

## H. Обмеження

- Це статичний аудит active branch + двох local dirty files; він не є аудитом current `main` і не включає 19 main-only commits.
- Не виконувалися tests, application/server/container startup, builds, CI, benchmark, smoke/e2e, linter, formatter, type checker, migrations або project scripts.
- Не імпортувалися project modules і не здійснювалися provider/model/network calls через код проєкту.
- Історичні stdout/stderr/evidence читалися як записи, але не вважалися незалежним підтвердженням поточної runtime behavior.
- Vendor/pinned Codex source не перечитувався цілком; перевірено власні patches, assembly/proof tooling, source bindings і місця інтеграції.
- Runtime-dependent питання ОС/ACL, Docker daemon, real Ollama/Groq/Gemini API compatibility, TLS behavior, timing/races і actual Codex process visibility потребують окремої виконуваної перевірки.
- Через обсяг repository основний бюджет спрямовано на production/data/security paths; generated evidence blobs, historical duplicated logs і every test body не читалися построково.

**Тести та інші виконувані перевірки не запускалися. Файли репозиторію не змінювалися під час самого аудиту; цей Markdown-файл додано пізніше на окремий запит користувача.**
