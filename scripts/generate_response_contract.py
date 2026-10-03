"""Generate the client-side response-envelope contract from the committed OpenAPI document.

The HTTP client validates every success response against the committed API contract before
handing a typed mapping to the caller. To avoid a hand-written schema that can silently
diverge from ``protocol/openapi.yaml``, this script derives the per-endpoint rules (allowed
success status codes, JSON root type, and per-variant required fields, non-nullable required
fields, and constant discriminator fields) from the committed document and renders them into
``src/lets/_response_contract.py``.

Usage::

    uv run python scripts/generate_response_contract.py           # regenerate
    uv run python scripts/generate_response_contract.py --check   # verify only, exit 1 if stale

The script is stdlib-only and imports nothing from the package, so it also runs in CI
sandboxes and in the sentinel unit test.
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

MODULE_TEMPLATE = '''"""Generated client-side response-envelope rules. DO NOT EDIT BY HAND.

Regenerate with ``uv run python scripts/generate_response_contract.py`` after changing the
committed API contract in ``protocol/openapi.yaml``. The rules are embedded as JSON so the
module text is stable under formatting tools and the client can import it without the
server extras.
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


def _required_non_null(schema: dict[str, Any], required: list[str]) -> list[str]:
    """Required fields whose documented type does not admit JSON null."""
    properties = schema.get("properties", {})
    non_null: list[str] = []
    for name in required:
        property_schema = properties.get(name)
        if not isinstance(property_schema, dict) or "$ref" in property_schema:
            non_null.append(name)
            continue
        declared = property_schema.get("type")
        types = declared if isinstance(declared, list) else [declared]
        if "null" not in types:
            non_null.append(name)
    return non_null


def _object_variant(schema: dict[str, Any]) -> dict[str, Any]:
    root_type = schema.get("type")
    if root_type != "object":
        raise ValueError(f"response schema variant has unsupported root type {root_type!r}")
    required = list(schema.get("required", []))
    return {
        "required": required,
        "required_non_null": _required_non_null(schema, required),
        "consts": {
            name: property_schema["const"]
            for name, property_schema in schema.get("properties", {}).items()
            if isinstance(property_schema, dict) and "const" in property_schema
        },
    }


def _response_variants(
    schema: dict[str, Any], components: dict[str, dict[str, Any]]
) -> tuple[str, list[dict[str, Any]]]:
    """Return the JSON root type and the documented envelope variants for one response."""
    resolved = _resolve_schema(schema, components)
    alternatives = resolved.get("oneOf")
    if isinstance(alternatives, list):
        variants = [
            _object_variant(_resolve_schema(option, components))
            for option in alternatives
            if isinstance(option, dict)
        ]
        if not variants:
            raise ValueError("oneOf response schema declares no usable variants")
        return "object", variants
    root = resolved.get("type", "")
    if root == "object":
        return "object", [_object_variant(resolved)]
    if root == "array":
        return "array", []
    raise ValueError(f"response schema has unsupported root type {root!r}")


def build_rules(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Derive the response rules keyed by ``"METHOD /path-template"`` from an OpenAPI document."""
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
    """Render the deterministic module text for the given rules."""
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
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
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
