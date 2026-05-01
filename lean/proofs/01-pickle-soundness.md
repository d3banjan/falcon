# Prose walkthroughs of the Lean proofs

## 01 — Pickle Soundness (Theorem 1)

**Statement**: In the Tier-1 fragment, if an expression `e` is typed at a
concrete type and contains no `cast` subterm, then evaluation cannot
produce a tainted (vulnerable) value.

**Intuition**: The only way to introduce taint is `loads`. The type rule
for `loads` produces `Unsafe[Any]`. The only way to get from `Unsafe[Any]`
to a concrete type is `cast`. Therefore, without `cast`, taint can never
reach a concrete-typed sink.

**Proof strategy**: Structural induction on the `Typed` derivation.

- Constants are never tainted.
- Variables look up their type in Γ; if Γ is well-formed, variables at
  concrete type are not tainted.
- `loads` produces `Unsafe[Any]`; but the theorem assumes the overall
  type is concrete, so this case is impossible (contradiction).
- `cast` is ruled out by the `NoCast` proviso.
- Application: the function must be a lambda at concrete type; by the
  induction hypothesis its body evaluates to an untainted value.

This is a **post-return** theorem: it proves that once a loader already returned
an object, typed flows from that object into a trusted sink must cross an
explicit `cast`.

## 02 — Cast is the Only Escape (Theorem 2)

**Statement**: If a well-typed expression at concrete type contains
`loads b` as a subterm, then it must also contain a `cast τ (loads b)`
somewhere.

**Intuition**: `loads` alone can never appear at a concrete type. The
only typing rule that changes an `Unsafe` type into a concrete type is
`T_cast`. Therefore any well-typed program that uses `loads` and still
has a concrete type must have used `cast` to bridge the gap.

**Proof strategy**: Structural induction on the expression, using the
fact that `Typed` is syntax-directed.

## Provenance-backed trusted-input extension

The next proof layer is not a stronger variant of these two theorems, but a
separate obligation about **when** dangerous loaders may run.

`TrustedInputs.lean` and `LoadTime.lean` now implement the first version of
this theorem shape:

- `TrustedBytes` and `TrustedPath` are explicit preconditions on dangerous
  deserialiser call sites.
- Loader families such as `pickle`, `cloudpickle`, unsafe YAML, `torch`, `dill`,
  `joblib`, `marshal`, pandas pickle helpers, skops, Embedchain, and Horovod can
  be called only when their input has the expected trusted type.
- Accepted dangerous-loader calls still return `Unsafe[Any]`.
- Load-time risk is classified separately from the returned `Unsafe[Any]` type.

Remaining backlog: connect load-time effects to ingress provenance, because code
may execute before any value is returned.

This prevents an unsound model expansion: even trusted input does not let the
current theorem conclude “safe execution,” only “explicitly quarantined output.”
Concrete examples that should be documented as accepted scope are:

- a loader called on a user-provided path that is first normalized and checked
  into `TrustedPath`;
- a loader called on payload bytes that passed a validator and are represented as
  `TrustedBytes`;

and concrete counterexamples to reject in this phase are:

- raw network bytes passed directly to `pickle.load`;
- unvalidated message payloads passed to unsafe `yaml.load` or checkpoint
  loaders.

Related cleanup work is still visible in source as proof placeholders:
`eval_closure_noloads_body`, `typed_concrete_no_loads`, and `cast_only_escape`
in `Soundness.lean`.

## 03 — Counter-examples

Each counter-example is a concrete `Expr` that breaks Theorem 1 when a
single language feature is added.

### Any-absorption

Adding a top type `any` with subtyping `any <: τ` for all `τ` means
`loads b` can be typed as `any` and then implicitly used as `bytes`.
This corresponds to `disallow_any_explicit` in mypy strict mode.

### getattr

`getattr(pickle, "loads")` evaluates to the `loads` function but is
typed `Any`. Without a cast, it can be invoked and the result used at
concrete type. This motivates ruff rule S307 (ban `getattr` on unsafe
modules).

### Monkey-patch

`pickle.loads = identity` changes the runtime semantics so that `loads`
returns untainted bytes, while the type system still thinks it returns
`Unsafe`. This is a **soundness break in the other direction**: the type
system is too pessimistic. It does not create vulnerability, but it shows
that runtime mutation invalidates static types.

### kwargs Any

`def f(**kwargs): return kwargs["x"]` forwards untyped data. If `x` is
tainted bytes, the return type is inferred as `Any` (or `Unsafe` in our
model), but callers may cast implicitly. This motivates
`Unpack[TypedDict]`.
