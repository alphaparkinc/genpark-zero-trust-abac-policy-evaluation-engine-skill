"""MCP server for Zero-Trust ABAC Policy Evaluation Engine."""
import sys
import json
from client import ZeroTrustABACEngine

_engine = ZeroTrustABACEngine()


def handle_request(req):
    method = req.get("method")
    if method == "tools/list":
        return {
            "tools": [
                {
                    "name": "add_policy",
                    "description": "Registers an ABAC policy rule with effect (PERMIT/DENY), targets, and dynamic attribute conditions",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "policy": {"type": "object"},
                        },
                        "required": ["policy"],
                    },
                },
                {
                    "name": "evaluate_access",
                    "description": "Evaluates access request against policies using subject, resource, action, and environment context",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "subject": {"type": "object"},
                            "resource": {"type": "object"},
                            "action": {"type": "string"},
                            "environment": {"type": "object"},
                        },
                        "required": ["subject", "resource", "action"],
                    },
                },
            ]
        }
    elif method == "tools/call":
        params = req.get("params", {})
        tool_name = params.get("name")
        args = params.get("arguments", {})
        if tool_name == "add_policy":
            _engine.add_policy(args.get("policy", {}))
            return {"content": [{"type": "text", "text": json.dumps({"status": "policy_added"})}]}
        elif tool_name == "evaluate_access":
            res = _engine.evaluate(
                subject=args.get("subject", {}),
                resource=args.get("resource", {}),
                action=args.get("action", ""),
                environment=args.get("environment"),
            )
            return {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]}
    return {"error": "Method not found"}


if __name__ == "__main__":
    for line in sys.stdin:
        if line.strip():
            print(json.dumps(handle_request(json.loads(line))))
            sys.stdout.flush()
