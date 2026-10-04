"""Generate the client-side response-envelope contract from the committed OpenAPI document.

The HTTP client validates success responses against the derived rules to prevent divergence.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).parents[1]
OPENAPI_DOCUMENT = REPOSITORY_ROOT / "protocol" / "openapi.yaml"
TARGET_MODULE = REPOSITORY_ROOT / "src" / "lets" / "_response_contract.py"

HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete"})
MAX_LINE_LENGTH = 100

MODULE_TEMPLATE = '''"""Generated client-side response-envelope rules; do not edit by hand.

Regenerate with scripts/generate_response_contract.py after modifying protocol/openapi.yaml.
"""

from __future__ import annotations

import json
from typing import Any, Final

_CONTRACT_JSON: Final[str] = """\\
{body}"""

RESPONSE_CONTRACT: Final[dict[str, dict[str, Any]]] = json.loads(_CONTRACT_JSON)
'''


def _resolve_schema(
    schema: dict[str, Any], components: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    reference = schema.get("$ref")
    if not isinstance(reference, str):
        return schema
    name = reference.rsplit("/", 1)[-1]
    resolved = components.get(name)
    if not isinstance(resolved, dict):
        raise ValueError(f"openapi document references unknown schema {name!r}")
    return resolved


def _admits_null(
    property_schema: dict[str, Any],
    components: dict[str, dict[str, Any]],
    seen: frozenset[str],
) -> bool:
    reference = property_schema.get("$ref")
    if isinstance(reference, str):
        name = reference.rsplit("/", 1)[-1]
        if name in seen:
            return True
        resolved = components.get(name)
        if not isinstance(resolved, dict):
            return True
        return _admits_null(resolved, components, seen | {name})
    alternatives: list[Any] | None = None
    for keyword in ("oneOf", "anyOf"):
        candidates = property_schema.get(keyword)
        if isinstance(candidates, list):
            alternatives = candidates
            break
    if alternatives is not None:
        return any(
            isinstance(option, dict) and _admits_null(option, components, seen)
            for option in alternatives
        )
    if "const" in property_schema:
        return property_schema["const"] is None
    declared = property_schema.get("type")
    if declared is None:
        return True
    types = declared if isinstance(declared, list) else [declared]
    return "null" in types


def _required_non_null(
    schema: dict[str, Any],
    required: list[str],
    components: dict[str, dict[str, Any]],
) -> list[str]:
    properties = schema.get("properties", {})
    return [
        name
        for name in required
        if not _admits_null(properties.get(name, {}), components, frozenset())
    ]


def _object_variant(
    schema: dict[str, Any], components: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    root_type = schema.get("type")
    if root_type != "object":
        raise ValueError(f"response schema variant has unsupported root type {root_type!r}")
    required = list(schema.get("required", []))
    not_schema = schema.get("not", {})
    excluded = (
        list(not_schema.get("required", []))
        if isinstance(not_schema, dict) and isinstance(not_schema.get("required"), list)
        else []
    )
    return {
        "consts": {
            name: property_schema["const"]
            for name, property_schema in schema.get("properties", {}).items()
            if isinstance(property_schema, dict) and "const" in property_schema
        },
        "excluded": excluded,
        "required": required,
        "required_non_null": _required_non_null(schema, required, components),
    }


def _response_variants(
    schema: dict[str, Any], components: dict[str, dict[str, Any]]
) -> tuple[str, list[dict[str, Any]]]:
    resolved = _resolve_schema(schema, components)
    alternatives = resolved.get("oneOf")
    if isinstance(alternatives, list):
        variants = [
            _object_variant(_resolve_schema(option, components), components)
            for option in alternatives
            if isinstance(option, dict)
        ]
        if not variants:
            raise ValueError("oneOf response schema declares no usable variants")
        return "object", variants
    root = resolved.get("type", "")
    if root == "object":
        return "object", [_object_variant(resolved, components)]
    if root == "array":
        return "array", []
    raise ValueError(f"response schema has unsupported root type {root!r}")


def build_rules(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    components = document.get("components", {}).get("schemas", {})
    rules: dict[str, dict[str, Any]] = {}
    for path, path_item in document.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            statuses: list[int] = []
            root = ""
            variants: list[dict[str, Any]] = []
            for code, response in operation.get("responses", {}).items():
                if not isinstance(code, str) or not code.startswith("2"):
                    continue
                media = response.get("content", {}).get("application/json", {})
                schema = media.get("schema")
                if not isinstance(schema, dict):
                    raise ValueError(f"{method.upper()} {path} {code} has no JSON schema")
                if statuses:
                    raise ValueError(f"{method.upper()} {path} documents several success codes")
                statuses.append(int(code))
                root, variants = _response_variants(schema, components)
            if not statuses:
                continue
            rules[f"{method.upper()} {path}"] = {
                "statuses": statuses,
                "root": root,
                "variants": variants,
            }
    if not rules:
        raise ValueError("openapi document declares no JSON success responses")
    return rules


def render_module(rules: dict[str, dict[str, Any]]) -> str:
    body = json.dumps(rules, indent=2, sort_keys=True, ensure_ascii=False)
    module = MODULE_TEMPLATE.replace("{body}", body)
    oversized = [
        number
        for number, line in enumerate(module.splitlines(), start=1)
        if len(line) > MAX_LINE_LENGTH
    ]
    if oversized:
        raise ValueError(
            f"rendered module exceeds the {MAX_LINE_LENGTH}-column lint budget on lines {oversized}"
        )
    return module


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Generate the client-side response-envelope contract from the "
            "committed OpenAPI document."
        )
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare the generated text against the committed module without writing",
    )
    arguments = parser.parse_args(argv)
    document = json.loads(OPENAPI_DOCUMENT.read_text(encoding="utf-8"))
    rendered = render_module(build_rules(document))
    if arguments.check:
        committed = TARGET_MODULE.read_text(encoding="utf-8")
        if committed == rendered:
            print(f"{TARGET_MODULE.name} is up to date with {OPENAPI_DOCUMENT.name}")
            return 0
        print(
            f"{TARGET_MODULE.name} is stale; regenerate with "
            "`uv run python scripts/generate_response_contract.py`",
            file=sys.stderr,
        )
        return 1
    TARGET_MODULE.write_text(rendered, encoding="utf-8", newline="\n")
    print(f"wrote {TARGET_MODULE.relative_to(REPOSITORY_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
