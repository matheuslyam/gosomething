# QA universal core (niche / lang / framework agnostic)

Every rule is `IF → THEN`, verifiable with a file:line or link.
An adjective without evidence is not a finding.

## 1. Success criteria and scope alignment

- `AC-01` IF a behavior is expected THEN it is written as Gherkin
  (`Given/When/Then`) or an exact `IF → THEN` business rule. WHY: if QA
  does not know what "correct" is, there is nothing to test. Vague verbs
  (`fast`, `etc`, `...`, `vX`) in acceptance = FAIL.
- `AC-02` IF the feature claims to be done THEN the Definition of Done
  holds: automated tests green, docs updated, no `B/C` open, tree == disk,
  no placeholder in acceptance. WHY: DoD is the only production gate.
- `AC-03` IF something is out of scope THEN it is declared. WHY: silent
  scope is how regressions hide.

## 2. Scenario and risk mapping

- `SC-01` Happy path: the ideal flow the majority of users execute.
  Every output field has producer → consumer → test. WHY: untraced fields
  are untested fields.
- `SC-02` Alternative and exception flows: unexpected input, boundary
  values, invalid data, network timeout, mid-process cancellation, 0/1/N
  arity, ordering violations. WHY: v1-v7 defects clustered here (NArg,
  SingleLabel order, fallback predicate, `Canceled` vs timeout).
- `SC-03` Impact / regression: which current parts the feature touches
  and what must be re-tested. `Does not affect anything` without evidence
  = FAIL. WHY: undeclared impact breaks trust in the suite.

## 3. Environment and data matrix

- `EN-01` Test-data strategy: how data is generated, isolated and cleaned
  so one test cannot interfere with another (mocks, fixtures, `localhost`,
  dynamic ports). WHY: shared or fixed resources make tests flaky.
- `EN-02` Execution environment: where tests run and why it faithfully
  models production behavior. Toolchain and deps pinned with source + date,
  never `latest`/`vX`. WHY: unpinned envs are non-reproducible builds.

## 4. Defect management and lifecycle

- `DF-01` Severity is pre-defined, never debated per bug:
  `B` blocker (breaks build/contract) / `C` contract (wrong exit, schema,
  arity) / `G` grave logic/security (wrong mapping, leak, silent downgrade)
  / `M` medium (operator, normalization, pin detail). WHY: fixed severities
  remove subjective triage.
- `DF-02` Priority follows severity: `B/C/G` block `GO`; `M` blocks `GO`
  only when more than 2 are open, otherwise `WARN`. WHY: small issues must
  not veto progress, but accumulation must.
