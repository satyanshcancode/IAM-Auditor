"""Graph-based Attack-Path Correlation Engine (Phase 2).

Builds node/edge graphs of IAM principals, permissions, and roles to identify
chained multi-step privilege escalation paths with bounded traversal.
"""

from typing import Any

from aws.policy_evaluator import PolicyEvaluator
from iam_audit.core.models import AttackPath, AttackPathStep


class AttackPathGraph:
    """Graph correlation engine for IAM entities and permissions."""

    def __init__(self) -> None:
        self.nodes: set[str] = set()
        self.edges: list[dict[str, Any]] = []

    def add_node(self, node_id: str) -> None:
        self.nodes.add(node_id)

    def add_edge(
        self, source: str, target: str, action_or_edge: str, evidence: str
    ) -> None:
        self.nodes.add(source)
        self.nodes.add(target)
        self.edges.append(
            {
                "source": source,
                "target": target,
                "action": action_or_edge,
                "evidence": evidence,
            }
        )

    def find_attack_paths(
        self, max_depth: int = 4
    ) -> list[AttackPath]:
        """Find chained escalation attack paths from initiating principals to privileged targets."""
        paths: list[AttackPath] = []
        path_counter = 1

        # Identify admin/target nodes
        admin_targets = {
            edge["source"]
            for edge in self.edges
            if edge["action"] == "IS_ADMINISTRATOR"
        }

        # Identify initiating user/principal nodes
        initiators = {
            edge["source"]
            for edge in self.edges
            if edge["action"].startswith("CAN_") or edge["action"].startswith("HAS_")
        } - admin_targets

        for init_node in sorted(initiators):
            for target_node in sorted(admin_targets):
                if init_node == target_node:
                    continue

                visited: set[str] = {init_node}
                current_steps: list[dict[str, Any]] = []

                self._dfs_path(
                    current_node=init_node,
                    target_node=target_node,
                    visited=visited,
                    steps=current_steps,
                    paths_found=paths,
                    path_counter=path_counter,
                    max_depth=max_depth,
                )

        return paths

    def _dfs_path(
        self,
        current_node: str,
        target_node: str,
        visited: set[str],
        steps: list[dict[str, Any]],
        paths_found: list[AttackPath],
        path_counter: int,
        max_depth: int,
    ) -> None:
        if len(steps) >= max_depth:
            return

        out_edges = [e for e in self.edges if e["source"] == current_node]

        for edge in out_edges:
            nxt = edge["target"]
            if nxt in visited:
                continue

            step_info = {
                "source": current_node,
                "action": edge["action"],
                "target": nxt,
                "evidence": edge["evidence"],
            }
            steps.append(step_info)
            visited.add(nxt)

            if nxt == target_node:
                # Path found! Construct AttackPath model
                path_steps = [
                    AttackPathStep(
                        step_number=idx + 1,
                        source_entity=s["source"],
                        action_or_edge=s["action"],
                        target_entity=s["target"],
                        evidence=s["evidence"],
                    )
                    for idx, s in enumerate(steps)
                ]

                paths_found.append(
                    AttackPath(
                        path_id=f"ATTACK-PATH-{len(paths_found) + 1:03}",
                        title=f"Privilege Escalation Path: {current_node} -> {target_node}",
                        initiating_principal=steps[0]["source"],
                        target_principal_or_resource=target_node,
                        steps=path_steps,
                        confidence="CONFIRMED" if len(path_steps) <= 2 else "POTENTIAL_PATH",
                        severity="CRITICAL",
                        risk_summary=f"Principal '{steps[0]['source']}' can escalate privileges to '{target_node}' in {len(path_steps)} step(s).",
                        remediation="Revoke initiating permissions or add permission boundary restrictions.",
                    )
                )
            else:
                self._dfs_path(
                    current_node=nxt,
                    target_node=target_node,
                    visited=visited,
                    steps=steps,
                    paths_found=paths_found,
                    path_counter=path_counter,
                    max_depth=max_depth,
                )

            steps.pop()
            visited.remove(nxt)


def build_attack_path_graph(
    users: list[dict[str, Any]],
    roles: list[dict[str, Any]],
    user_analyses: dict[str, Any],
    role_analyses: dict[str, Any],
) -> list[AttackPath]:
    """Construct attack graph and discover multi-step privilege escalation paths."""
    graph = AttackPathGraph()

    # 1. Add node attributes for admin users/roles
    for username, analysis in user_analyses.items():
        if analysis and any(a == "*" for a in analysis.get("effective_actions", set())):
            graph.add_edge(username, "AdministratorAccess", "IS_ADMINISTRATOR", "User grants AdministratorAccess (*)")

    for role_name, analysis in role_analyses.items():
        if analysis and any(a == "*" for a in analysis.get("effective_actions", set())):
            graph.add_edge(role_name, "AdministratorAccess", "IS_ADMINISTRATOR", "Role grants AdministratorAccess (*)")

    # 2. Add edges for users with escalation capabilities
    for user in users:
        username = user["UserName"]
        analysis = user_analyses.get(username)
        if not analysis:
            continue

        evaluator = PolicyEvaluator(analysis.get("policies", []))

        # Direct policy attachment escalation
        if evaluator.has_permission("iam:AttachUserPolicy") or evaluator.has_permission("iam:PutUserPolicy"):
            graph.add_edge(
                username,
                "AdministratorAccess",
                "CAN_ATTACH_ADMIN_POLICY",
                f"User '{username}' can attach policies to self",
            )

        # PassRole to compute service
        if evaluator.has_permission("iam:PassRole"):
            has_lambda = evaluator.has_permission("lambda:CreateFunction") or evaluator.has_permission("lambda:UpdateFunctionCode")
            has_ec2 = evaluator.has_permission("ec2:RunInstances")
            if has_lambda or has_ec2:
                # Connect user to all admin roles via PassRole
                for role_name, r_analysis in role_analyses.items():
                    if r_analysis and any(a == "*" for a in r_analysis.get("effective_actions", set())):
                        service_name = "Lambda" if has_lambda else "EC2"
                        graph.add_edge(
                            username,
                            role_name,
                            f"CAN_PASS_ROLE_TO_{service_name.upper()}",
                            f"User '{username}' can pass role '{role_name}' to {service_name}",
                        )

        # AssumeRole capability
        if evaluator.has_permission("sts:AssumeRole"):
            for role in roles:
                role_name = role["RoleName"]
                r_analysis = role_analyses.get(role_name, {})
                if r_analysis and any(a == "*" for a in r_analysis.get("effective_actions", set())):
                    graph.add_edge(
                        username,
                        role_name,
                        "CAN_ASSUME_ROLE",
                        f"User '{username}' has sts:AssumeRole permission for role '{role_name}'",
                    )

    # Traverse graph for attack paths
    return graph.find_attack_paths(max_depth=4)
