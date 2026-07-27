"""Safe predicate evaluation.

Rules are structured trees rather than expression strings. Nothing here calls
``eval`` or ``exec``, so a rules file cannot execute code. The tree form also
means a rule can be serialised into the API and rendered back to a human as
readable text, which is what lets the UI show a rule's own definition next to
the findings it produced.

Grammar:

    leaf        {field: <name>, op: <operator>, value: <literal>}
    conjunction {all: [<node>, ...]}
    disjunction {any: [<node>, ...]}
    negation    {not: <node>}
"""

from __future__ import annotations

import re
from typing import Any

OPERATORS = (
    "eq", "equals", "ne", "not_equals", "in", "not_in",
    "gt", "gte", "lt", "lte",
    "matches", "contains", "contains_any", "contains_all",
    "exists", "missing", "truthy", "falsy", "count_gte",
)


class PredicateError(ValueError):
    """Raised when a rule's condition is structurally invalid."""


def _as_number(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _truthy(value: Any) -> bool:
    """Empty string, empty list, zero, and None are all false.

    `0` counts as false so a `count`-style field with no matches does not
    accidentally satisfy a truthy check.
    """
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip() not in ("", "none", "unknown")
    if isinstance(value, (list, tuple, dict, set)):
        return len(value) > 0
    return bool(value)


def evaluate(node: Any, record: dict) -> bool:
    if node is None:
        return False
    if not isinstance(node, dict):
        raise PredicateError(f"condition must be a mapping, got {type(node).__name__}")

    if "all" in node:
        children = node["all"]
        if not isinstance(children, list):
            raise PredicateError("`all` must be a list")
        return all(evaluate(child, record) for child in children)

    if "any" in node:
        children = node["any"]
        if not isinstance(children, list):
            raise PredicateError("`any` must be a list")
        return any(evaluate(child, record) for child in children)

    if "not" in node:
        return not evaluate(node["not"], record)

    if "field" not in node:
        raise PredicateError(f"leaf condition needs a `field`: {node!r}")

    field = node["field"]
    op = node.get("op", "truthy")
    if op not in OPERATORS:
        raise PredicateError(f"unknown operator {op!r} (field {field!r})")

    actual = record.get(field)
    expected = node.get("value")

    if op in ("truthy",):
        return _truthy(actual)
    if op in ("falsy",):
        return not _truthy(actual)
    if op == "exists":
        return actual is not None and actual != "" and actual != []
    if op == "missing":
        return actual is None or actual == "" or actual == []

    if op in ("eq", "equals"):
        return _compare_equal(actual, expected)
    if op in ("ne", "not_equals"):
        return not _compare_equal(actual, expected)

    if op == "in":
        return any(_compare_equal(actual, item) for item in _as_list(expected))
    if op == "not_in":
        return not any(_compare_equal(actual, item) for item in _as_list(expected))

    if op in ("gt", "gte", "lt", "lte"):
        left, right = _as_number(actual), _as_number(expected)
        if left is None or right is None:
            return False
        return {
            "gt": left > right,
            "gte": left >= right,
            "lt": left < right,
            "lte": left <= right,
        }[op]

    if op == "matches":
        if not isinstance(expected, str):
            raise PredicateError(f"`matches` needs a string pattern (field {field!r})")
        try:
            return bool(re.search(expected, str(actual or ""), re.I))
        except re.error as exc:
            raise PredicateError(f"bad regex for {field!r}: {exc}") from exc

    if op == "contains":
        return str(expected).lower() in str(actual or "").lower()

    if op in ("contains_any", "contains_all"):
        haystack = {str(item).lower() for item in _as_list(actual)}
        needles = [str(item).lower() for item in _as_list(expected)]
        if not needles:
            return False
        if op == "contains_any":
            return any(needle in haystack for needle in needles)
        return all(needle in haystack for needle in needles)

    if op == "count_gte":
        threshold = _as_number(expected) or 0
        return len(_as_list(actual)) >= threshold

    raise PredicateError(f"unhandled operator {op!r}")


def _compare_equal(actual: Any, expected: Any) -> bool:
    """Compare tolerantly across the string/bool/int boundary.

    SQLite stores booleans as 0/1 and YAML gives real booleans, so a rule
    written as `value: true` must still match a stored `1`.
    """
    if isinstance(actual, bool) or isinstance(expected, bool):
        return _truthy(actual) == _truthy(expected)
    if actual is None:
        return expected is None
    left, right = _as_number(actual), _as_number(expected)
    if left is not None and right is not None:
        return left == right
    return str(actual).strip().lower() == str(expected).strip().lower()


def validate(node: Any, known_fields: set[str] | None = None,
             path: str = "when") -> list[str]:
    """Structurally check a condition. Returns a list of problems."""
    problems: list[str] = []

    if not isinstance(node, dict):
        return [f"{path}: must be a mapping, got {type(node).__name__}"]

    for key in ("all", "any"):
        if key in node:
            children = node[key]
            if not isinstance(children, list) or not children:
                problems.append(f"{path}.{key}: must be a non-empty list")
            else:
                for index, child in enumerate(children):
                    problems.extend(validate(child, known_fields, f"{path}.{key}[{index}]"))
            return problems

    if "not" in node:
        return validate(node["not"], known_fields, f"{path}.not")

    if "field" not in node:
        return [f"{path}: leaf condition needs a `field`"]

    field = node["field"]
    op = node.get("op", "truthy")
    if op not in OPERATORS:
        problems.append(f"{path}: unknown operator {op!r}")
    if known_fields is not None and field not in known_fields:
        problems.append(f"{path}: unknown field {field!r}")
    if op in ("eq", "equals", "ne", "not_equals", "in", "not_in", "gt", "gte",
              "lt", "lte", "matches", "contains", "contains_any", "contains_all",
              "count_gte") and "value" not in node:
        problems.append(f"{path}: operator {op!r} requires a `value`")
    if op == "matches" and isinstance(node.get("value"), str):
        try:
            re.compile(node["value"])
        except re.error as exc:
            problems.append(f"{path}: invalid regex — {exc}")

    return problems


def describe(node: Any) -> str:
    """Render a condition as readable English, for the Methodology view."""
    if not isinstance(node, dict):
        return str(node)

    if "all" in node:
        return " and ".join(f"({describe(child)})" for child in node["all"])
    if "any" in node:
        return " or ".join(f"({describe(child)})" for child in node["any"])
    if "not" in node:
        return f"not ({describe(node['not'])})"

    field = node.get("field", "?")
    op = node.get("op", "truthy")
    value = node.get("value")
    label = field.replace("_", " ")

    phrases = {
        "truthy": f"{label} is set",
        "falsy": f"{label} is not set",
        "exists": f"{label} has a value",
        "missing": f"{label} has no value",
        "eq": f"{label} is {value!r}",
        "equals": f"{label} is {value!r}",
        "ne": f"{label} is not {value!r}",
        "not_equals": f"{label} is not {value!r}",
        "in": f"{label} is one of {value}",
        "not_in": f"{label} is none of {value}",
        "gt": f"{label} is greater than {value}",
        "gte": f"{label} is at least {value}",
        "lt": f"{label} is less than {value}",
        "lte": f"{label} is at most {value}",
        "matches": f"{label} matches /{value}/",
        "contains": f"{label} contains {value!r}",
        "contains_any": f"{label} includes any of {value}",
        "contains_all": f"{label} includes all of {value}",
        "count_gte": f"{label} has at least {value} entries",
    }
    return phrases.get(op, f"{label} {op} {value!r}")
