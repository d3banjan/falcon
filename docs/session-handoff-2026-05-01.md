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
- Latest pushed commit: `b2c94b1 Use Falcon branding for stubs`.
- Worktree status at handoff: clean.
- The old parent-repo subtree workflow is no longer active for current work.

## Recent Commits

- `b2c94b1` — use Falcon branding for stubs while preserving compatibility names.
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

- mypy: 24 expected unsafe assignment errors.
- pyright: 24 expected unsafe assignment errors.
- ty: 23 expected unsafe assignment errors; `ty` still resolves stdlib `marshal` before Falcon's overlay.

Trusted provenance diagnostic fixture: `tests/fixtures/fix_trusted_provenance.py`.

- mypy: 4 expected errors.
- pyright: 4 expected errors.
- ty: 4 expected errors.

## Lean State

Lean now models:

- post-return `Unsafe[Any]` quarantine;
- trusted loader preconditions;
- generic imported-loader code paths;
- untrusted ingress rejection;
- explicit promotion into `TrustedBytes`, `TrustedPath`, and trusted artifacts;
- load-time risk classification;
- replacement sound fragment excluding known counterexamples.

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

1. Implement the first AST semantic-policy rule in `pickle-secure audit`.
   - Detect class-body `safe = False`.
   - Detect class-body `remote_exec = True`.
   - Detect `super().__init__(safe=False)`.
   - Detect direct constructor calls with unsafe literal config.
   - Emit category `unsafe-config` and map to `checker-rule-needed`.

2. Add fixtures/tests for the semantic-policy rule.
   - Keep fixture files small and single-purpose.
   - Prefer one rule family per test file.

3. Add a small Lean backend-evidence model.
   - Model `StubEvidence`, `ASTEvidence`, and `AppTypeEvidence`.
   - Prove each evidence source can justify the same Falcon taint result.
   - Prove backend evidence does not declassify `Unsafe[Any]`.

4. Continue CVE wrapper precision after the semantic-policy prototype.
   - Deeper fixtures for Kedro `get` / `load`, LlamaIndex `load` / `loads`, python-socketio callback handling, and smolagents `loads`.
   - Stable wrapper stubs for vLLM, InvokeAI, Horovod, and source-confirmed YAML/cloudpickle rows.

5. Keep source-confirmation rows separate from implemented coverage.
   - scikit-learn/joblib wrappers, Upsonic, ai-flow, and route/file-only rows need stable import paths before production claims.

## Launch Remaining Work

- Decide whether to keep the compatibility PyPI/package/CLI names for launch or perform a coordinated rename.
- Run one final full local suite before a launch tag:
  - `uv run pytest tests -q`
  - `uv run pytest tests/checker_matrix -q`
  - `cd lean && lake build TaintedTypingFramework`
  - `zsh -lc 'source ~/.zshrc; cd /home/debanjan/fun/falcon/docs; jekyll build'`
- Verify GitHub CI, Lean CI, and Pages after the final commit.
- Keep docs honest: Falcon currently proves returned-value quarantine and has a diagnostic trusted-input mechanism; broad load-time prevention requires per-API trusted-input adoption.
