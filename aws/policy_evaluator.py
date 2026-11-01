"""Statement-level IAM policy evaluator engine (Phase 2 & Phase 4).

Preserves policy structure, statement effects, Action/NotAction, Resource/NotResource,
conditions, explicit deny precedence, permissions boundaries, and session policies for threat detection.
"""

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Any


def action_matches(pattern: str, action: str) -> bool:
    """Return True if action string matches pattern (case-insensitive fnmatch)."""
    return fnmatchcase(action.lower(), pattern.lower())


def resource_matches(pattern: str, resource: str) -> bool:
    """Return True if resource string matches pattern (case-insensitive fnmatch)."""
    if pattern == "*" or resource == "*":
        return True
    return fnmatchcase(resource.lower(), pattern.lower())


def normalize_to_list(value: Any) -> list[str]:
    """Ensure value is returned as a list of strings."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def substitute_policy_variables(pattern: str, context: dict[str, Any] | None) -> tuple[str, str, bool]:
    """Substitute ${variable} in pattern using context dictionary.

    Returns (exact_pattern: str, wildcard_pattern: str, all_resolved: bool).
    """
    if "${" not in pattern:
        return pattern, pattern, True

    import re

    all_resolved = True

    def replace_exact(match: re.Match[str]) -> str:
        nonlocal all_resolved
        var_name = match.group(1)
        if context:
            for ctx_key, ctx_val in context.items():
                if ctx_key.lower() == var_name.lower():
                    return str(ctx_val)
        all_resolved = False
        return match.group(0)

    def replace_wildcard(match: re.Match[str]) -> str:
        var_name = match.group(1)
        if context:
            for ctx_key, ctx_val in context.items():
                if ctx_key.lower() == var_name.lower():
                    return str(ctx_val)
        return "*"

    exact_res = re.sub(r"\$\{([^}]+)\}", replace_exact, pattern)
    wildcard_res = re.sub(r"\$\{([^}]+)\}", replace_wildcard, pattern)
    return exact_res, wildcard_res, all_resolved


def evaluate_condition_operator(operator: str, cond_dict: dict[str, Any], context: dict[str, Any]) -> bool:
    """Evaluate a single IAM condition block against context dictionary.

    Supports ForAllValues: and ForAnyValue: condition set operators,
    IfExists modifier, and multivalued request context keys.
    """
    op_str = operator
    set_quantifier = None
    if ":" in op_str:
        prefix, rest = op_str.split(":", 1)
        if prefix.lower() in ("forallvalues", "foranyvalue"):
            set_quantifier = prefix.lower()
            op_str = rest

    is_if_exists = op_str.endswith("IfExists")
    base_op = op_str[:-8] if is_if_exists else op_str
    op_lower = base_op.lower()

    for key, expected_raw in cond_dict.items():
        actual_val = None
        key_found = False
        for ctx_key, ctx_val in context.items():
            if ctx_key.lower() == key.lower():
                actual_val = ctx_val
                key_found = True
                break

        if not key_found:
            if is_if_exists or set_quantifier == "forallvalues":
                continue
            return False

        expected_list = normalize_to_list(expected_raw)
        actual_list = normalize_to_list(actual_val)

        if not actual_list:
            if set_quantifier == "forallvalues" or is_if_exists:
                continue
            return False

        if set_quantifier == "forallvalues":
            for act in actual_list:
                act_matched = False
                for exp in expected_list:
                    if op_lower == "stringequals" and act == exp or op_lower == "stringnotequals" and act != exp or op_lower == "stringlike" and fnmatchcase(act, exp) or op_lower == "stringnotlike" and not fnmatchcase(act, exp) or op_lower in ("arnlike", "arnequals") and fnmatchcase(act, exp):
                        act_matched = True
                        break
                if not act_matched:
                    return False
            continue

        if op_lower == "stringequals":
            if not any(act == exp for act in actual_list for exp in expected_list):
                return False
        elif op_lower == "stringnotequals":
            if any(act == exp for act in actual_list for exp in expected_list):
                return False
        elif op_lower == "stringlike":
            if not any(fnmatchcase(act, exp) for act in actual_list for exp in expected_list):
                return False
        elif op_lower == "stringnotlike":
            if any(fnmatchcase(act, exp) for act in actual_list for exp in expected_list):
                return False
        elif op_lower == "numericequals":
            try:
                if not any(float(act) == float(exp) for act in actual_list for exp in expected_list):
                    return False
            except ValueError:
                return False
        elif op_lower == "numericnotequals":
            try:
                if any(float(act) == float(exp) for act in actual_list for exp in expected_list):
                    return False
            except ValueError:
                return False
        elif op_lower == "numericlessthan":
            try:
                if not any(float(act) < float(exp) for act in actual_list for exp in expected_list):
                    return False
            except ValueError:
                return False
        elif op_lower == "numericlessthanequals":
            try:
                if not any(float(act) <= float(exp) for act in actual_list for exp in expected_list):
                    return False
            except ValueError:
                return False
        elif op_lower == "numericgreaterthan":
            try:
                if not any(float(act) > float(exp) for act in actual_list for exp in expected_list):
                    return False
            except ValueError:
                return False
        elif op_lower == "numericgreaterthanequals":
            try:
                if not any(float(act) >= float(exp) for act in actual_list for exp in expected_list):
                    return False
            except ValueError:
                return False
        elif op_lower == "bool":
            expected_bool = any(str(exp).lower() == "true" for exp in expected_list)
            actual_bool = any(str(act).lower() == "true" for act in actual_list)
            if actual_bool != expected_bool:
                return False
        elif op_lower == "null":
            expected_null = any(str(exp).lower() == "true" for exp in expected_list)
            is_null = (actual_val is None)
            if is_null != expected_null:
                return False
        elif op_lower == "ipaddress":
            matched = False
            for exp in expected_list:
                for act in actual_list:
                    try:
                        import ipaddress
                        net = ipaddress.ip_network(exp, strict=False)
                        ip = ipaddress.ip_address(act)
                        if ip in net:
                            matched = True
                            break
                    except Exception:
                        if fnmatchcase(act, exp):
                            matched = True
                            break
                if matched:
                    break
            if not matched:
                return False
        elif op_lower == "notipaddress":
            for exp in expected_list:
                for act in actual_list:
                    try:
                        import ipaddress
                        net = ipaddress.ip_network(exp, strict=False)
                        ip = ipaddress.ip_address(act)
                        if ip in net:
                            return False
                    except Exception:
                        if fnmatchcase(act, exp):
                            return False
        elif op_lower in ("arnlike", "arnequals"):
            if not any(fnmatchcase(act, exp) for act in actual_list for exp in expected_list):
                return False
        elif op_lower in ("arnnotlike", "arnnotequals") and any(fnmatchcase(act, exp) for act in actual_list for exp in expected_list):
            return False

    return True


@dataclass
class ParsedStatement:
    """Represents a single parsed IAM policy statement."""

    effect: str
    actions: list[str] = field(default_factory=list)
    not_actions: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    not_resources: list[str] = field(default_factory=list)
    conditions: dict[str, Any] = field(default_factory=dict)
    source_policy_name: str = "Unknown"
    source_owner: str = "Unknown"
    scope: str = "User"  # User, Group, Role, TrustPolicy
    policy_type: str = "inline"  # inline or managed

    @property
    def has_conditions(self) -> bool:
        return len(self.conditions) > 0

    @property
    def is_resource_constrained(self) -> bool:
        if not self.resources and not self.not_resources:
            return False
        return not (len(self.resources) == 1 and self.resources[0] == "*")

    def matches_action(
        self, target_action: str, context: dict[str, Any] | None = None
    ) -> tuple[bool, bool]:
        """Check if target_action matches statement actions. Returns (matches: bool, vars_resolved: bool)."""
        if not self.actions and not self.not_actions:
            return False, True

        vars_resolved = True
        if self.actions:
            matched = False
            for pat in self.actions:
                exact_pat, wild_pat, res = substitute_policy_variables(pat, context)
                if not res:
                    vars_resolved = False
                test_pat = exact_pat if res else wild_pat
                if action_matches(test_pat, target_action):
                    matched = True
            if not matched:
                return False, vars_resolved

        if self.not_actions:
            for pat in self.not_actions:
                exact_pat, wild_pat, res = substitute_policy_variables(pat, context)
                if not res:
                    vars_resolved = False
                test_pat = exact_pat if res else wild_pat
                if action_matches(test_pat, target_action):
                    return False, vars_resolved

        return True, vars_resolved

    def matches_resource(
        self, target_resource: str, context: dict[str, Any] | None = None
    ) -> tuple[bool, bool]:
        """Check if target_resource matches statement resources. Returns (matches: bool, vars_resolved: bool)."""
        if not self.resources and not self.not_resources:
            return False, True

        vars_resolved = True
        if self.resources:
            matched = False
            for pat in self.resources:
                exact_pat, wild_pat, res = substitute_policy_variables(pat, context)
                if not res:
                    vars_resolved = False
                test_pat = exact_pat if res else wild_pat
                if resource_matches(test_pat, target_resource):
                    matched = True
            if not matched:
                return False, vars_resolved

        if self.not_resources:
            for pat in self.not_resources:
                exact_pat, wild_pat, res = substitute_policy_variables(pat, context)
                if not res:
                    vars_resolved = False
                test_pat = exact_pat if res else wild_pat
                if resource_matches(test_pat, target_resource):
                    return False, vars_resolved

        return True, vars_resolved

    def matches_conditions(self, context: dict[str, Any] | None) -> tuple[bool, bool]:
        """Evaluate conditions against context. Returns (matches: bool, evaluated: bool)."""
        if not self.conditions:
            return True, True
        if context is None:
            return True, False

        for op, cond_dict in self.conditions.items():
            if isinstance(cond_dict, dict) and not evaluate_condition_operator(op, cond_dict, context):
                return False, True
        return True, True


@dataclass
class EvaluationResult:
    """Result of evaluating an action against parsed statements."""

    action: str
    resource: str
    allowed: bool
    decision: str  # allowed, explicitDeny, implicitDeny, indeterminate
    matching_allow_statements: list[ParsedStatement] = field(default_factory=list)
    matching_deny_statements: list[ParsedStatement] = field(default_factory=list)
    is_condition_constrained: bool = False
    is_resource_constrained: bool = False
    is_indeterminate: bool = False
    limitation_note: str = ""


class PolicyEvaluator:
    """Statement-level policy evaluator for an IAM entity."""

    def __init__(
        self,
        policy_sources: list[dict[str, Any]] | None = None,
        permissions_boundary_sources: list[dict[str, Any]] | None = None,
        session_policy_sources: list[dict[str, Any]] | None = None,
    ) -> None:
        self.statements: list[ParsedStatement] = []
        self.boundary_evaluator: PolicyEvaluator | None = None
        self.session_evaluator: PolicyEvaluator | None = None

        if policy_sources:
            self.add_policy_sources(policy_sources)
        if permissions_boundary_sources:
            self.boundary_evaluator = PolicyEvaluator(permissions_boundary_sources)
        if session_policy_sources:
            self.session_evaluator = PolicyEvaluator(session_policy_sources)

    def add_policy_sources(self, policy_sources: list[dict[str, Any]]) -> None:
        """Parse and add statement objects from policy sources list."""
        for source in policy_sources:
            policy_name = source.get("name", "Unknown")
            owner = source.get("owner", "Unknown")
            scope = source.get("scope", "User")
            pol_type = source.get("type", "inline")
            doc = source.get("document", {})

            stmt_list = doc.get("Statement", [])
            if isinstance(stmt_list, dict):
                stmt_list = [stmt_list]
            elif not isinstance(stmt_list, list):
                stmt_list = []

            for stmt in stmt_list:
                if not isinstance(stmt, dict):
                    continue
                parsed = ParsedStatement(
                    effect=stmt.get("Effect", "Allow"),
                    actions=normalize_to_list(stmt.get("Action")),
                    not_actions=normalize_to_list(stmt.get("NotAction")),
                    resources=normalize_to_list(stmt.get("Resource")),
                    not_resources=normalize_to_list(stmt.get("NotResource")),
                    conditions=stmt.get("Condition", {}) if isinstance(stmt.get("Condition"), dict) else {},
                    source_policy_name=policy_name,
                    source_owner=owner,
                    scope=scope,
                    policy_type=pol_type,
                )
                self.statements.append(parsed)

    def evaluate_action(
        self, action: str, resource: str = "*", context: dict[str, Any] | None = None
    ) -> EvaluationResult:
        """Evaluate an action against statements with explicit deny precedence and boundaries."""
        matching_allows: list[ParsedStatement] = []
        matching_denies: list[ParsedStatement] = []
        has_unresolved_vars = False

        for stmt in self.statements:
            act_match, act_resolved = stmt.matches_action(action, context)
            res_match, res_resolved = stmt.matches_resource(resource, context)

            if not act_resolved or not res_resolved:
                has_unresolved_vars = True

            if act_match and res_match:
                cond_matches, evaluated = stmt.matches_conditions(context)
                if cond_matches:
                    if stmt.effect == "Deny":
                        matching_denies.append(stmt)
                    elif stmt.effect == "Allow":
                        matching_allows.append(stmt)

        if matching_denies:
            return EvaluationResult(
                action=action,
                resource=resource,
                allowed=False,
                decision="explicitDeny",
                matching_allow_statements=matching_allows,
                matching_deny_statements=matching_denies,
            )

        if matching_allows:
            is_cond = any(s.has_conditions for s in matching_allows)
            is_res = any(s.is_resource_constrained for s in matching_allows)

            decision = "allowed"
            is_indet = False
            limitation = ""

            if has_unresolved_vars:
                decision = "indeterminate"
                is_indet = True
                limitation = "Policy contains unresolved policy variables in Action or Resource patterns"

            result = EvaluationResult(
                action=action,
                resource=resource,
                allowed=True,
                decision=decision,
                matching_allow_statements=matching_allows,
                matching_deny_statements=matching_denies,
                is_condition_constrained=is_cond,
                is_resource_constrained=is_res,
                is_indeterminate=is_indet,
                limitation_note=limitation,
            )

            # Enforce Permissions Boundary if attached
            if self.boundary_evaluator:
                bound_res = self.boundary_evaluator.evaluate_action(action, resource, context)
                if not bound_res.allowed:
                    result.allowed = False
                    result.decision = bound_res.decision
                    result.limitation_note = "Restricted by Permissions Boundary policy"

            # Enforce Session Policy if attached
            if result.allowed and self.session_evaluator:
                sess_res = self.session_evaluator.evaluate_action(action, resource, context)
                if not sess_res.allowed:
                    result.allowed = False
                    result.decision = sess_res.decision
                    result.limitation_note = "Restricted by Session Policy"

            return result

        return EvaluationResult(
            action=action,
            resource=resource,
            allowed=False,
            decision="implicitDeny",
        )

    def has_permission(self, action: str, resource: str = "*") -> bool:
        """Return True if action is allowed for resource."""
        res = self.evaluate_action(action, resource)
        return res.allowed

    def get_allowed_actions(self) -> set[str]:
        """Return all distinct explicitly allowed actions across statements (excluding denied)."""
        all_actions: set[str] = set()
        for stmt in self.statements:
            if stmt.effect == "Allow":
                all_actions.update(stmt.actions)

        filtered: set[str] = set()
        for act in all_actions:
            if self.has_permission(act):
                filtered.add(act)
        return filtered

