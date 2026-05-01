---
layout: page
title: Formal Method
---

{% include research_status.html %}

Falcon uses formal methods to discipline a practical engineering workflow.

The basic question is:

> What has to be true for a vulnerable value to become a trusted application value?

Falcon starts with a small Lean model:

- sources: APIs that produce unsafe values, such as `pickle.loads`;
- sinks: places where application code expects trusted typed values;
- traces: evaluation evidence showing how values moved;
- casts: explicit trust assertions.

The Lean story is intentionally modest. It shows that, in a sound fragment, unsafe values cannot reach trusted sinks without an explicit escape. In production, the typechecker run is the executable check of that discipline: if unsafe values are used without an explicit trust boundary, CI fails.

This is a **post-return model**. It keeps returned objects quarantined (`Unsafe`)
and does not prove that dangerous loaders are safe to execute on attacker input.

It is not a proof that CPython, mypy, pyright, or every third-party package is sound. It is a formal backing for the methodology: mark unsafe sources, prevent silent flow into trusted sinks, audit every escape.

## Branches that fit type-checking

Some CWE families are type-shaped:

- CWE-502 deserialization sources;
- command execution wrappers with unsafe flags;
- path or bytes trust boundaries when represented by `TrustedPath` / `TrustedBytes`;
- injection sinks when sanitizers have explicit types.

These can be modeled as "untrusted value reaches trusted sink unless a proof-like API intervenes."

## Trusted-input theorem extension

The first practical extension is now a precondition theorem for loader call sites:

- dangerous load primitives require trusted sources (`TrustedBytes` and
  `TrustedPath`) before execution;
- trusted-source admission still produces `Unsafe[Any]` until an explicit
  validation step restores a concrete type;
- load-time execution risk is classified separately from returned-value
  quarantine, because code can execute before any value is returned.

The remaining theorem backlog is to connect those call-site preconditions to a
full ingress-provenance lattice for network, RPC, queue, socket, and remote
artifact sources. This lines up with CWE-502 rows that describe code execution
during `load(s)` and with the remaining `Soundness.lean` placeholders tracked
in `proofs/` and `lean/README.md`.

## Branches outside this proof

Auth bypass, deployment policy, SSRF routing policy, race conditions, crypto misuse, and most business-logic bugs do not reduce cleanly to `Unsafe[T]` quarantine. Those need other methods.
