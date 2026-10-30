"""Zero-Trust Attribute-Based Access Control (ABAC) Policy Engine.
100% Python Standard Library.
"""

from typing import Dict, Any, List, Optional


class ZeroTrustABACEngine:
    """Attribute-Based Access Control (ABAC) policy evaluation engine.
    Evaluates dynamic subject, resource, action, and contextual environment attributes
    against declarative rules to yield PERMIT or DENY decisions."""

    def __init__(self, policies: Optional[List[Dict[str, Any]]] = None):
        # List of policy rules:
        # {
        #   'id': 'policy_1',
        #   'effect': 'PERMIT' | 'DENY',
        #   'target': {'action': 'read', 'resource_type': 'document'},
        #   'conditions': [
        #       {'attribute': 'subject.clearance_level', 'op': '>=', 'value': 3},
        #       {'attribute': 'environment.is_vpn', 'op': '==', 'value': True}
        #   ]
        # }
        self.policies: List[Dict[str, Any]] = policies or []

    def add_policy(self, policy: Dict[str, Any]):
        """Registers a new ABAC policy rule."""
        self.policies.append(policy)

    @classmethod
    def _get_nested_attr(cls, context: Dict[str, Any], attr_path: str) -> Any:
        parts = attr_path.split(".")
        curr = context
        for p in parts:
            if not isinstance(curr, dict) or p not in curr:
                return None
            curr = curr[p]
        return curr

    @classmethod
    def _eval_condition(cls, cond: Dict[str, Any], context: Dict[str, Any]) -> bool:
        attr_val = cls._get_nested_attr(context, cond["attribute"])
        op = cond["op"]
        expected_val = cond["value"]

        if attr_val is None:
            return False

        if op == "==":
            return attr_val == expected_val
        elif op == "!=":
            return attr_val != expected_val
        elif op == ">=":
            return attr_val >= expected_val
        elif op == "<=":
            return attr_val <= expected_val
        elif op == ">":
            return attr_val > expected_val
        elif op == "<":
            return attr_val < expected_val
        elif op == "in":
            return attr_val in expected_val
        elif op == "contains":
            return expected_val in attr_val
        return False

    def evaluate(
        self,
        subject: Dict[str, Any],
        resource: Dict[str, Any],
        action: str,
        environment: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Evaluates access request against rules using default-deny with explicit deny overrides."""
        full_context = {
            "subject": subject,
            "resource": resource,
            "action": action,
            "environment": environment or {},
        }

        matched_permits = []
        matched_denies = []

        for p in self.policies:
            target = p.get("target", {})
            # Check target action match
            if "action" in target and target["action"] != action and target["action"] != "*":
                continue
            if "resource_type" in target and target["resource_type"] != resource.get("type") and target["resource_type"] != "*":
                continue

            # Check all conditions in policy
            conditions = p.get("conditions", [])
            all_conditions_met = all(self._eval_condition(c, full_context) for c in conditions)

            if all_conditions_met:
                if p["effect"].upper() == "DENY":
                    matched_denies.append(p)
                else:
                    matched_permits.append(p)

        # Deny overrides rule
        if matched_denies:
            return {
                "decision": "DENY",
                "reason": f"Explicit DENY policy matched: '{matched_denies[0].get('id', 'unnamed')}'",
                "matched_deny_policies": [p.get("id") for p in matched_denies],
                "matched_permit_policies": [p.get("id") for p in matched_permits],
            }

        if matched_permits:
            return {
                "decision": "PERMIT",
                "reason": f"Access granted by policy: '{matched_permits[0].get('id', 'unnamed')}'",
                "matched_deny_policies": [],
                "matched_permit_policies": [p.get("id") for p in matched_permits],
            }

        return {
            "decision": "DENY",
            "reason": "Default Deny: No explicit PERMIT policy matched target and conditions.",
            "matched_deny_policies": [],
            "matched_permit_policies": [],
        }
