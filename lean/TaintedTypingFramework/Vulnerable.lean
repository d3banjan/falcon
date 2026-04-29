import TaintedTypingFramework.Syntax

/-!
# Vulnerable.lean — Vulnerability predicate V(v)

A value is "vulnerable" (exhibits the bad behavior) when a tainted
attacker-controlled value reaches a sink without having been sanitized.

For CWE-502 (Deserialization) the sink is "any concrete-typed use."
-/

namespace TaintedTypingFramework

/-- A value is tainted at the top level. -/
def isTainted (v : Value) : Prop :=
  ∃ w, v = Value.tainted w

/-- The vulnerability predicate for CWE-502.
    `Vulnerable v` holds when `v` is a tainted value that has reached a sink. -/
def Vulnerable (v : Value) : Prop :=
  isTainted v

end TaintedTypingFramework
