/-!
# Syntax.lean — Expression AST for a tiny Python fragment

The Tier-1 language fragment contains:
- constants (unit, bytes, int, concrete records)
- variables
- lambda abstraction + application
- `pickle.loads`
- `typing.cast`

NO `getattr`, NO `eval`, NO `Any` in the sound fragment.
-/

namespace TaintedTypingFramework

mutual

inductive Ty : Type
  | unit   : Ty
  | bytes  : Ty
  | int    : Ty
  | concrete (name : String) : Ty
  | unsafe_  (τ : Ty) : Ty
  | arrow (dom : Ty) (cod : Ty) : Ty

inductive Value : Type
  | vunit  : Value
  | vbytes (b : String) : Value
  | vint   (n : Int) : Value
  | vconcrete (name : String) (payload : Value) : Value
  | tainted (v : Value) : Value
  | vclosure (env : List (String × Value)) (x : String) (τ : Ty) (body : Expr) : Value

inductive Expr : Type
  | const  : Value → Expr
  | var    : String → Expr
  | app    : Expr → Expr → Expr
  | lam    : String → Ty → Expr → Expr
  | loads  : Expr → Expr
  | cast   : Ty → Expr → Expr

end

/-- Substitute variable `x` with expression `e'` inside `e`.
    (Naïve substitution — sufficient for this model.) -/
def Expr.subst (e : Expr) (x : String) (e' : Expr) : Expr :=
  match e with
  | const v      => const v
  | var y        => if x = y then e' else var y
  | app f a      => app (f.subst x e') (a.subst x e')
  | lam y τ body => if x = y then lam y τ body else lam y τ (body.subst x e')
  | loads b      => loads (b.subst x e')
  | cast τ e1    => cast τ (e1.subst x e')

end TaintedTypingFramework
