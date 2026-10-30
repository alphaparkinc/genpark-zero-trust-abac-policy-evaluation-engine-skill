# genpark-zero-trust-abac-policy-evaluation-engine-skill

Zero-trust attribute-based access control (ABAC) policy evaluator, dynamic context rule arbiter, and authorization decision engine.

100% Python Standard Library implementation with zero external dependencies.

## Key Capabilities

- **Attribute-Based Policy Model (ABAC)**: Evaluates access dynamically across multidimensional Subject, Resource, Action, and Environmental context attributes.
- **Default-Deny Security Baseline**: Strictly rejects unauthorized requests unless an explicit `PERMIT` policy evaluates to True.
- **Explicit Deny Override Rule**: Guarantees that any matched `DENY` policy unconditionally supersedes any conflicting permits.
- **Rich Operator Grammar**: Supports equality (`==`, `!=`), numerical inequalities (`>=`, `<=`, `>`, `<`), set membership (`in`), and string containment (`contains`).

## Architecture

```
[Access Request: Subject, Resource, Action, Environment]
                          │
                          ▼
┌───────────────────────────────────────────────────────┐
│                 ZeroTrustABACEngine                   │
│  - Target Action & Resource Type Filter               │
│  - Dynamic Dot-Notation Attribute Path Resolver       │
│  - Multi-Condition Evaluation Operator Grammar        │
│  - Deny-Overrides Decision Arbiter (PERMIT / DENY)    │
└───────────────────────────────────────────────────────┘
          │                                  │
  (Permit Matched)                  (Deny / Unmatched)
          ▼                                  ▼
[PERMIT: Authorized Context]        [DENY: Diagnostic Reason]
```

## MCP Server Integration

Run standard MCP stdio server:
```bash
python mcp_server.py
```

Exposed Tools:
- `add_policy`: Registers an ABAC policy rule with effect (PERMIT/DENY), targets, and dynamic attribute conditions.
- `evaluate_access`: Evaluates access request against policies using subject, resource, action, and environment context.

## Quickstart (Python API)

```python
from client import ZeroTrustABACEngine

engine = ZeroTrustABACEngine()
engine.add_policy({
    "id": "admin_permit",
    "effect": "PERMIT",
    "target": {"action": "write"},
    "conditions": [{"attribute": "subject.role", "op": "==", "value": "admin"}],
})
decision = engine.evaluate({"role": "admin"}, {"id": "res_1"}, "write")
print("Decision:", decision["decision"])
```

---

## GenPark Ecosystem

- **Official Website**: [https://www.genpark.ai](https://www.genpark.ai)
- **LinkedIn Page**: [https://www.linkedin.com/company/92955550](https://www.linkedin.com/company/92955550)
