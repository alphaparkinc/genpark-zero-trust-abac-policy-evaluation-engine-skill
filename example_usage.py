"""Example usage for Zero-Trust ABAC Policy Evaluation Engine."""
from client import ZeroTrustABACEngine


def main():
    engine = ZeroTrustABACEngine()

    # Rule 1: Medical doctors can read patient records if in the same department
    engine.add_policy({
        "id": "doctor_patient_read_policy",
        "effect": "PERMIT",
        "target": {"action": "read", "resource_type": "patient_record"},
        "conditions": [
            {"attribute": "subject.role", "op": "==", "value": "doctor"},
            {"attribute": "subject.department", "op": "==", "value": "oncology"},
            {"attribute": "resource.department", "op": "==", "value": "oncology"},
            {"attribute": "environment.is_vpn_or_hospital_lan", "op": "==", "value": True},
        ],
    })

    # Rule 2: Explicit Deny for suspended accounts
    engine.add_policy({
        "id": "deny_suspended_users",
        "effect": "DENY",
        "target": {"action": "*", "resource_type": "*"},
        "conditions": [
            {"attribute": "subject.is_suspended", "op": "==", "value": True},
        ],
    })

    print("=== 1. Valid Doctor Request (LAN + Same Dept) ===")
    decision_pass = engine.evaluate(
        subject={"user_id": "dr_alice", "role": "doctor", "department": "oncology", "is_suspended": False},
        resource={"id": "rec_992", "type": "patient_record", "department": "oncology"},
        action="read",
        environment={"is_vpn_or_hospital_lan": True},
    )
    print("Decision:", decision_pass["decision"])
    print("Reason:", decision_pass["reason"])

    print("\n=== 2. Doctor Request Blocked (Different Dept) ===")
    decision_diff_dept = engine.evaluate(
        subject={"user_id": "dr_bob", "role": "doctor", "department": "pediatrics", "is_suspended": False},
        resource={"id": "rec_992", "type": "patient_record", "department": "oncology"},
        action="read",
        environment={"is_vpn_or_hospital_lan": True},
    )
    print("Decision:", decision_diff_dept["decision"])
    print("Reason:", decision_diff_dept["reason"])

    print("\n=== 3. Suspended Doctor Request (Explicit Deny Override) ===")
    decision_deny = engine.evaluate(
        subject={"user_id": "dr_eve", "role": "doctor", "department": "oncology", "is_suspended": True},
        resource={"id": "rec_992", "type": "patient_record", "department": "oncology"},
        action="read",
        environment={"is_vpn_or_hospital_lan": True},
    )
    print("Decision:", decision_deny["decision"])
    print("Reason:", decision_deny["reason"])


if __name__ == "__main__":
    main()
