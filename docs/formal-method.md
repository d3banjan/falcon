---
layout: page
title: Formal Method
---

# Formal Method

Falcon uses formal methods to discipline a practical engineering workflow.

The basic question is:

> What has to be true for a vulnerable value to become a trusted application value?

Falcon starts with a small Lean model:

- sources: APIs that produce unsafe values, such as `pickle.loads`;
- sinks: places where application code expects trusted typed values;
- traces: evaluation evidence showing how values moved;
- casts: explicit trust assertions.

The Lean story is intentionally modest. It shows that, in a sound fragment, unsafe values cannot reach trusted sinks without an explicit escape. In production, the typechecker run is the executable check of that discipline: if unsafe values are used without an explicit trust boundary, CI fails.

It is not a proof that CPython, mypy, pyright, or every third-party package is sound. It is a formal backing for the methodology: mark unsafe sources, prevent silent flow into trusted sinks, audit every escape.

## Branches that fit type-checking

Some CWE families are type-shaped:

- CWE-502 deserialization sources;
- command execution wrappers with unsafe flags;
- path or bytes trust boundaries when represented by `TrustedPath` / `TrustedBytes`;
- injection sinks when sanitizers have explicit types.

These can be modeled as "untrusted value reaches trusted sink unless a proof-like API intervenes."

## Branches outside this proof

Auth bypass, deployment policy, SSRF routing policy, race conditions, crypto misuse, and most business-logic bugs do not reduce cleanly to `Unsafe[T]` quarantine. Those need other methods.
