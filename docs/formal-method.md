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

The base theorem is a **post-return model**. It keeps returned objects
quarantined (`Unsafe`) and does not by itself prove that dangerous loaders are
safe to execute on attacker input.

It is not a proof that CPython, mypy, pyright, or every third-party package is sound. It is a formal backing for the methodology: mark unsafe sources, prevent silent flow into trusted sinks, audit every escape.

## Branches that fit type-checking

Some CWE families are type-shaped:

- CWE-502 deserialization sources;
- command execution wrappers with unsafe flags;
- path, bytes, or binary-stream trust boundaries when represented by
  `TrustedPath`, `TrustedBytes`, or `TrustedBinaryIO`;
- injection sinks when sanitizers have explicit types.

These can be modeled as "untrusted value reaches trusted sink unless a proof-like API intervenes."

## Trusted-input theorem extension

The first practical extension is now a precondition theorem for loader call sites:

- selected dangerous load primitives require trusted sources (`TrustedBytes`,
  `TrustedBinaryIO`, and `TrustedPath`) before execution;
- imported package APIs are modeled generically as code-path specifications with
  an input kind and load-time-risk flag, not as a new theorem for every library;
- promotion APIs can turn reviewed ingress into `TrustedBytes`, `TrustedPath`,
  `TrustedBinaryIO`, or trusted artifacts;
- trusted-source admission still produces `Unsafe[Any]` until an explicit
  validation step restores a concrete type;
- network, RPC, queue, socket, and remote artifact ingress sources are modeled
  as untrusted and cannot directly satisfy trusted loader preconditions;
- load-time execution risk is classified separately from returned-value
  quarantine, because code can execute before any value is returned.

The remaining engineering backlog is to connect this theorem shape to more
real package APIs. The remaining Lean backlog is the older
`Soundness.lean` placeholder set, whose current statements have documented
counterexamples and need stronger invariants before the `sorry`s can be closed.

## Branches outside this proof

Auth bypass, deployment policy, SSRF routing policy, race conditions, crypto misuse, and most business-logic bugs do not reduce cleanly to `Unsafe[T]` quarantine. Those need other methods.
