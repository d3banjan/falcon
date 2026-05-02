---
layout: page
title: Session Handoff 2026-05-02
---

{% include research_status.html %}

## Repo State

- Repo: `/home/debanjan/fun/falcon`
- Branch: `master`
- Remote: `git@github.com:d3banjan/falcon.git`
- Worktree at handoff: launch-facing docs updated for the current trusted-input state
- Latest pushed commit: `f1c1c2f` — `Streamline pages around current state`
- Previous code/policy commit: `2dd047c` — `Extend trusted gates to stable loaders`

## Remote Checks

Latest pushed docs commit `f1c1c2f`:

- GitHub CI: success
- GitHub Pages: success

Previous code/policy commit `2dd047c`:

- GitHub CI: success
- GitHub Lean CI: success
- GitHub Pages: success

No Lean files changed in `f1c1c2f`, so the latest Lean validation remains the
successful `2dd047c` run.

## Current State

Falcon now presents its Pages site as a current-state snapshot rather than a
change log:

- Homepage states the current claim, current enforced gates, coverage numbers,
  minimal example, and non-claims.
- Header navigation is streamlined to:
  - `Current Coverage`
  - `Architecture`
  - `Formal Method`
  - `CVEs and CWEs`
  - `Evidence Appendix`
- `mvp-results.md` is off the header and reframed as an operational snapshot.
- `cve-triage.md` is now titled `Evidence Appendix`.
- `coverage-analysis.md` is now titled `Current Coverage`.

The accurate public claim is:

- broad returned-value quarantine for modeled dangerous deserialization sources;
- selected real API call-time gates;
- no broad load-time RCE prevention claim across arbitrary third-party APIs.

## Current Trusted-Input Gates

Core and sink-family loader gates currently enforced in stubs:

- `pickle.loads` requires `TrustedBytes` and returns `Unsafe[Any]`
- `cloudpickle.loads` requires `TrustedBytes` and returns `Unsafe[Any]`
- `cloudpickle.load` requires `TrustedBinaryIO` and returns `Unsafe[Any]`
- `dill.loads` requires `TrustedBytes` and returns `Unsafe[Any]`
- `dill.load` requires `TrustedBinaryIO` and returns `Unsafe[Any]`
- `joblib.load` requires `TrustedPath` and returns `Unsafe[Any]`
- `pandas.read_pickle` requires `TrustedPath` and returns `Unsafe[Any]`
- `pandas.io.pickle.read_pickle` requires `TrustedPath` and returns `Unsafe[Any]`
- `torch.load` requires `TrustedPath` and returns `Unsafe[Any]`

Selected wrapper gates currently enforced in both compatibility packages where
applicable:

- LangChain community FAISS:
  - `langchain_community.vectorstores.faiss.FAISS.deserialize_from_bytes`
    requires `TrustedBytes` and returns `Unsafe[Any]`
  - `langchain_community.vectorstores.faiss.FAISS.load_local` requires
    `TrustedPath` and returns `Unsafe[Self]`
- Legacy LangChain FAISS:
  - `langchain.vectorstores.faiss.FAISS.deserialize_from_bytes` requires
    `TrustedBytes` and returns `Unsafe[Any]`
  - `langchain.vectorstores.faiss.FAISS.load_local` requires `TrustedPath` and
    returns `Unsafe[Self]`
- Pipecat `pipecat.serializers.livekit.LivekitFrameSerializer.deserialize`
  requires `TrustedBytes` and returns `Unsafe[Any]`
- torch_musa `torch_musa.utils.compare_tool.compare_for_single_op` and
  `nan_inf_track_for_single_op` require `TrustedPath` and return `Unsafe[Any]`

`numpy.load(..., allow_pickle=True)` is modeled as a conditional unsafe-return
source, not a trusted-input precondition.
LlamaIndex `llama_index.core.workflow.JsonPickleSerializer.deserialize` is modeled as a
returned-value quarantine wrapper, not a trusted-input gate.

## Local Validation From Latest Work

Docs/site streamlining slice:

- `git diff --check`: passed
- `uv run ruff check src/pickle_stubs_secure tests docs`: passed
- `zsh -lc 'source ~/.zshrc && cd /home/debanjan/fun/falcon/docs && jekyll build'`: passed
  - Existing zsh/zoxide read-only noise remains.
  - Existing minima Sass deprecation warnings remain.

Trusted-loader slice before that:

- `uv run pytest tests -q`: `112 passed, 3 xfailed`
- `cd lean && lake build TaintedTypingFramework`: passed
  - Existing `Soundness.lean` sorry warnings remain.
- JSONL parse for `cve_db/libraries/serialization-sinks.jsonl`: passed
- ruff targeted checks: passed
- `tests/fixtures/fix_trusted_real_apis.py` validates raw-input rejection,
  trusted-input acceptance, and preserved `Unsafe[...]` returns for
  `pickle.loads`, cloudpickle, dill, joblib, pandas, torch, FAISS, and Pipecat
  gates.
- `tests/fixtures/fix_cve_downstream_wrappers.py` validates the torch_musa
  compare utility gates: raw `str` / `Path` inputs are rejected,
  `TrustedPath` is accepted, and returns remain `Unsafe[...]`.

## Recommended Next Slice

Keep extending trusted-input gates only where there is stable public API/import
evidence. The FAISS, Pipecat, and torch_musa gates are already part of the
current trusted-input state and should not be described as future work.

Likely next work:

- keep OSV candidate normalization moving and promote only confirmed public
  surfaces into wrapper stubs;
- source-confirm the remaining route/file-only rows before claiming wrapper
  coverage;
- preserve compatibility package and CLI names: `pickle-stubs-secure` and
  `pickle-secure`.

## Important Caveats

- Keep the docs honest: selected API call-time gating plus broad returned-value
  quarantine, not broad RCE prevention.
- Do not move source-confirmation-only rows into implemented wrapper coverage
  without stable public API/import evidence.
- `ty` still has known stdlib overlay precedence behavior for `marshal`.
- The generated `docs/_site/` output is built by GitHub Pages; local source docs
  are the primary edit target.
