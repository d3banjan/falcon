---
layout: page
title: Session Handoff 2026-05-01
---

{% include research_status.html %}

This is the launch handoff for the next Falcon session.

## Repository State

- Repo root: `/home/debanjan/fun/falcon`.
- Public remote: `git@github.com:d3banjan/falcon.git`.
- Branch: `master`.
- Latest pushed commit before this slice: `8db8ae3 Add source CVE fixtures and wrapper forwarding proof`.
- Worktree status at handoff: clean.
- The old parent-repo subtree workflow is no longer active for current work.

## Recent Commits

- `b2c94b1` — use Falcon branding for stubs while preserving compatibility names.
- `8db8ae3` — add source CVE fixtures and wrapper forwarding proof.
- `9e8259e` — add CVE wrapper policy slices.
- `3fd9357` — expand wrapper checker fixtures.
- `7401666` — document future semantic-policy backlog.
- `d63a9c1` — add TrustedBytes/TrustedPath diagnostic wrappers and Lean provenance model.
- `d33d1cf` — generalize Lean imported loaders as code-path specs instead of package-specific constructors.
- `8d0ec8d` — expand trusted-loader Lean model.
- `57141db` — add Embedchain wrapper coverage.

## Current Validation

- GitHub CI: passing on `master`.
- GitHub Pages: passing on `master`.
- GitHub Lean CI: passing on the provenance/model commits.
- Local targeted validation after branding cleanup:
  - `uv run pytest tests/cli tests/infra/test_pep561_install.py -q`: 42 passed.
  - `zsh -lc 'source ~/.zshrc; cd /home/debanjan/fun/falcon/docs; jekyll build'`: passed with existing minima Sass warnings.
  - `git diff --check`: clean.
- Full suite before branding cleanup:
  - `uv run pytest tests -q`: 99 passed, 3 xfailed.
  - `cd lean && lake build TaintedTypingFramework`: passed with the existing three `Soundness.lean` sorry warnings.

## Current Coverage Snapshot

- Triaged evidence set: 26 reviewed Python ecosystem pickle-backed CVE rows.
- Source-or-sink-family coverage: 24 / 26 (92%).
- Implemented-stub coverage: 16 / 26 (62%).
- OSV broad candidates: 221.
- First-pass OSV buckets:
  - catchable: 31
  - partial: 37
  - needs source confirmation: 49
  - out of scope: 73
  - duplicate: 10
  - malicious package: 14
  - false positive: 7

## Checker Matrix

Fixture: `tests/fixtures/fix_cve_downstream_wrappers.py`.

- mypy: 37 expected diagnostics: 35 unsafe-return assignments plus raw
  `joblib.load` / `torch.load` trusted-input errors.
- pyright: 37 expected errors.
- ty: 36 expected diagnostics: 34 unsafe assignments plus raw `joblib.load` /
  `torch.load` trusted-input errors; `ty` still resolves stdlib `marshal`
  before Falcon's overlay.

Fixture: `tests/fixtures/fix_cve_source_direct_pickle.py`.

- mypy: 15 expected diagnostics: 9 unsafe-return assignments plus 6 raw
  `pickle.loads` trusted-input errors.
- pyright: 15 expected errors.
- ty: 15 expected diagnostics.

Trusted provenance diagnostic fixture: `tests/fixtures/fix_trusted_provenance.py`.

- mypy: 4 expected errors.
- pyright: 4 expected errors.
- ty: 4 expected errors.

Real API trusted-input fixture: `tests/fixtures/fix_trusted_real_apis.py`.

- mypy: 3 raw-input errors and 3 unsafe-return assignment errors.
- pyright: 3 raw-input errors and 3 unsafe-return assignment errors.
- ty: 3 raw-input errors and 3 unsafe-return assignment errors.

## Lean State

Lean now models:

- post-return `Unsafe[Any]` quarantine;
- trusted loader preconditions;
- generic imported-loader code paths;
- untrusted ingress rejection;
- explicit promotion into `TrustedBytes`, `TrustedPath`, and trusted artifacts;
- load-time risk classification;
- replacement sound fragment excluding known counterexamples.
- wrapper-forwarding evidence into imported-loader specs;
- real API trusted-input policy for `pickle.loads`, `joblib.load`, and
  `torch.load`.

Known Lean caveat:

- `Soundness.lean` still contains three historical `sorry`s whose current theorem statements are false as written. Do not try to close them directly. Treat `SoundFragment.lean` as the honest theorem path unless the old statements are rewritten with stronger invariants.

## Compatibility Names

Public branding should say Falcon or Falcon stubs.

Preserve these compatibility identifiers unless doing a deliberate breaking rename:

- package name: `pickle-stubs-secure`;
- import path: `pickle_stubs_secure`;
- CLI: `pickle-secure`;
- config key: `[tool.pickle_secure]`;
- packaged stub tree: `pickle-stubs/`.

## Recommended Next Launch Slices

Completed in the current follow-up slice:

- Implemented the first AST semantic-policy rule in `pickle-secure audit`.
  - Detects class-body `safe = False`.
  - Detects class-body `remote_exec = True`.
  - Detects `super().__init__(safe=False)`.
  - Detects direct constructor calls with unsafe literal config.
  - Emits category `unsafe-config` and maps to `checker-rule-needed`.
- Added fixtures/tests for the semantic-policy rule.
- Added a small Lean backend-evidence model.
  - Models `StubEvidence`, `ASTEvidence`, and `AppTypeEvidence`.
  - Proves each evidence source can justify the same Falcon taint result.
  - Proves backend evidence does not declassify `Unsafe[Any]`.
- Added deeper checker fixtures for alternate method spellings already stubbed:
  Kedro `get` / `load`, LlamaIndex `load` / `loads`, python-socketio callback
  handling, and smolagents `loads`.
- Added stable diagnostic wrapper stubs for vLLM PyTorch weight iterators,
  InvokeAI model-loading helpers, and Horovod cloudpickle decoding.
- Kept scikit-learn/joblib, Upsonic, ai-flow, Fugue, and route/file-only rows
  in source-confirmation/source-only status where stable current import paths
  or public APIs are not confirmed.
- Added the conditional-config Lean policy model for `allow_pickle=True`,
  `safe=False`, `remote_exec=True`, and `trust_remote_code=True`.
- Added source-shaped direct-pickle checker fixtures for ms-swift, Tendenci,
  pdfminer.six, LeRobot, SGLang scheduler/encoder/replay paths,
  manga-image-translator, and PLY.
- Added the Lean wrapper-forwarding proof family that turns wrapper evidence
  into an imported-loader spec and `Unsafe[Any]` taint.
- Added first real API trusted-input gates:
  - `pickle.loads` now requires `TrustedBytes`.
  - `joblib.load` now requires `TrustedPath`.
  - `torch.load` now requires `TrustedPath`.
  - All three still return `Unsafe[Any]`.
- Added `tests/fixtures/fix_trusted_real_apis.py` and checker-matrix coverage
  for raw-input rejection plus returned-value quarantine.
- Extended `pickle-secure audit` to list trusted-input promotions in JSON and
  human output separately from cast escapes.
- Added the Lean `RealAPIPolicy.lean` bridge from those enforced stubs to the
  generic imported-loader/provenance model.

Next:

1. Extend trusted-input gates to the next stable APIs, likely
   `cloudpickle.loads`, `dill.load(s)`, pandas `read_pickle`, and selected
   wrapper APIs whose public surfaces are stable.

2. Continue OSV candidate normalization and source confirmation for rows that
   can become stable consumer stubs.

## Launch Remaining Work

- Decide whether to keep the compatibility PyPI/package/CLI names for launch or perform a coordinated rename.
- Run one final full local suite before a launch tag:
  - `uv run pytest tests -q`
  - `uv run pytest tests/checker_matrix -q`
  - `cd lean && lake build TaintedTypingFramework`
  - `zsh -lc 'source ~/.zshrc; cd /home/debanjan/fun/falcon/docs; jekyll build'`
- Verify GitHub CI, Lean CI, and Pages after the final commit.
- Keep docs honest: Falcon currently proves returned-value quarantine and has a diagnostic trusted-input mechanism; broad load-time prevention requires per-API trusted-input adoption.
