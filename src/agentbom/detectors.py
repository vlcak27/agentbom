"""Plugin-style detectors for AgentBOM v0.1."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
import re
from pathlib import PurePosixPath
import tomllib
from typing import Protocol


PROVIDERS = {
    "openai": ("openai", "OPENAI_API_KEY"),
    "anthropic": ("anthropic", "ANTHROPIC_API_KEY"),
    "gemini": ("gemini", "google.generativeai", "GEMINI_API_KEY", "GOOGLE_API_KEY"),
}

MODELS = (
    "gemini-2.0-flash",
    "gemini-1.5-pro",
    "claude-3-sonnet",
    "claude-3-haiku",
    "claude-3-opus",
    "mistral-large",
    "gemini-pro",
    "claude-3",
    "gpt-4.1",
    "gpt-4o",
    "gpt-4",
    "gpt-5",
    "llama3",
)

FRAMEWORKS = {
    "langchain": ("langchain",),
    "llamaindex": ("llama_index", "llamaindex"),
    "crewai": ("crewai",),
    "autogen": ("autogen", "pyautogen"),
    "semantic_kernel": ("semantic_kernel", "semantic-kernel"),
}
DEPENDENCY_CATEGORIES = {
    "ai_framework": {
        "autogen",
        "crewai",
        "langchain",
        "langchain-community",
        "langgraph",
        "llama-index",
        "llama_index",
        "pyautogen",
        "semantic-kernel",
        "semantic_kernel",
    },
    "mcp": {
        "mcp",
        "fastmcp",
        "modelcontextprotocol",
    },
    "sandbox_runtime": {
        "docker",
        "e2b",
        "firecracker",
        "modal",
        "nsjail",
        "podman",
        "pyodide",
        "restrictedpython",
        "wasmtime",
    },
}

CAPABILITIES = {
    "shell": ("subprocess", "os.system", "shell=True"),
    "code_execution": ("eval(", "exec("),
    "network": ("requests.", "httpx.", "aiohttp", "urllib.request"),
    "database": ("sqlite3", "psycopg", "sqlalchemy", "pymongo"),
    "cloud": ("boto3", "google.cloud", "azure."),
    "mcp_tool_invocation": ("call_tool", "invoke_tool", "mcp.client", "mcp.client_session"),
}
CAPABILITY_REGEXES = {
    "autonomous_execution": (
        r"\bwhile\s+true\s*:",
        r"\bwhile\s*\(\s*true\s*\)",
        r"\bfor\s*\(\s*;\s*;\s*\)",
        r"\bmax_iterations\b",
        r"\bauto_run\b",
        r"\bcontinuous_mode\b",
        r"\bself\.(?:run|execute)\s*\(",
        r"\bagent\.(?:run|execute)\s*\(",
    ),
}

MCP_CONFIG_NAMES = {"mcp.json", "claude_desktop_config.json"}
PROMPT_NAMES = {"AGENTS.md", "CLAUDE.md"}
POLICY_NAMES = {"policy.md", "policies.md", "security.md", "permissions.md"}
GENERIC_SECRET_NAMES = {"API_KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "PRIVATE_KEY"}
SECRET_NAME_RE = re.compile(
    r"\b[A-Z][A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|PRIVATE_KEY)[A-Z0-9_]*\b"
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:api[_-]?key|token|secret|password|credential|private[_-]?key)[A-Z0-9_]*)\b\s*[:=]"
)


@dataclass(frozen=True)
class DetectionContext:
    """File data passed to detectors."""

    relpath: str
    text: str | None = None
    tree: ast.AST | None = None

    @property
    def lower_text(self) -> str:
        return "" if self.text is None else self.text.lower()

    @property
    def is_python(self) -> bool:
        return PurePosixPath(self.relpath).suffix.lower() == ".py"


@dataclass
class DetectionResult:
    """Findings returned by a detector."""

    findings: dict[str, list[dict[str, str]]] = field(default_factory=dict)
    has_policy: bool = False


class Detector(Protocol):
    """Interface implemented by all built-in and external detectors."""

    name: str

    def detect(self, context: DetectionContext) -> DetectionResult:
        """Return findings for one file."""


class PromptDetector:
    name = "prompt"

    def detect(self, context: DetectionContext) -> DetectionResult:
        path = PurePosixPath(context.relpath)
        filename = path.name
        if filename in PROMPT_NAMES:
            return _result("prompts", _prompt_finding(context.relpath))
        if filename.endswith((".prompt.yaml", ".prompt.yml")):
            return _result("prompts", _prompt_finding(context.relpath))
        if len(path.parts) >= 2 and path.parts[-2] == "prompts" and filename.endswith(".md"):
            return _result("prompts", _prompt_finding(context.relpath))
        return DetectionResult()


class McpConfigDetector:
    name = "mcp_config"

    def detect(self, context: DetectionContext) -> DetectionResult:
        filename = PurePosixPath(context.relpath).name
        if filename in MCP_CONFIG_NAMES:
            return _result(
                "mcp_servers",
                {
                    "name": filename,
                    "path": context.relpath,
                    "confidence": confidence_for_path(context.relpath),
                },
            )
        return DetectionResult()


class PolicyDetector:
    name = "policy"

    def detect(self, context: DetectionContext) -> DetectionResult:
        filename = PurePosixPath(context.relpath).name.lower()
        return DetectionResult(has_policy=filename in POLICY_NAMES)


class DependencyDetector:
    name = "dependency"

    def detect(self, context: DetectionContext) -> DetectionResult:
        if context.text is None:
            return DetectionResult()

        filename = PurePosixPath(context.relpath).name
        if filename == "pyproject.toml":
            dependencies = _parse_pyproject_dependencies(context.text)
        elif filename == "requirements.txt":
            dependencies = _parse_requirements_dependencies(context.text)
        else:
            return DetectionResult()

        findings = []
        for dependency in dependencies:
            category = _dependency_category(dependency)
            if category is None:
                continue
            _append_unique(
                findings,
                {
                    "name": dependency,
                    "category": category,
                    "path": context.relpath,
                    "confidence": confidence_for_path(context.relpath),
                },
            )
        return DetectionResult({"dependencies": findings})


class ModelDetector:
    name = "model"

    def detect(self, context: DetectionContext) -> DetectionResult:
        if context.text is None or not can_detect_model(context.relpath):
            return DetectionResult()

        findings = []
        confidence = confidence_for_path(context.relpath)
        for model in MODELS:
            pattern = re.compile(
                rf"(?<![A-Za-z0-9_.-]){re.escape(model)}(?![A-Za-z0-9_.-])",
                re.IGNORECASE,
            )
            match = pattern.search(context.text)
            if match:
                findings.append(
                    {
                        "type": "model",
                        "name": model,
                        "source_file": context.relpath,
                        "confidence": confidence,
                        "evidence": match.group(0),
                    }
                )
        return DetectionResult({"models": findings})


class ProviderDetector:
    name = "provider"

    def detect(self, context: DetectionContext) -> DetectionResult:
        if context.text is None or not can_detect_provider_or_framework(context.relpath):
            return DetectionResult()
        if context.is_python and context.tree is not None:
            return DetectionResult({"providers": _detect_python_providers(context)})
        return DetectionResult(
            {"providers": _detect_patterns(PROVIDERS, context.lower_text, context.relpath)}
        )


class FrameworkDetector:
    name = "framework"

    def detect(self, context: DetectionContext) -> DetectionResult:
        if context.text is None or not can_detect_provider_or_framework(context.relpath):
            return DetectionResult()
        return DetectionResult(
            {"frameworks": _detect_patterns(FRAMEWORKS, context.lower_text, context.relpath)}
        )


class CapabilityDetector:
    name = "capability"

    def detect(self, context: DetectionContext) -> DetectionResult:
        if context.text is None:
            return DetectionResult()
        if context.is_python and context.tree is not None:
            return DetectionResult({"capabilities": _detect_python_capabilities(context)})

        findings = _detect_patterns(CAPABILITIES, context.lower_text, context.relpath)
        confidence = confidence_for_path(context.relpath)
        for name, patterns in CAPABILITY_REGEXES.items():
            if any(re.search(pattern, context.text, re.IGNORECASE) for pattern in patterns):
                _append_unique(
                    findings,
                    {"name": name, "path": context.relpath, "confidence": confidence},
                )
        return DetectionResult({"capabilities": findings})


class SecretDetector:
    name = "secret"

    def detect(self, context: DetectionContext) -> DetectionResult:
        if context.text is None:
            return DetectionResult()

        raw_names = set(SECRET_NAME_RE.findall(context.text))
        raw_names.update(match.group(1) for match in SECRET_ASSIGNMENT_RE.finditer(context.text))
        names = {
            name
            for raw_name in raw_names
            if (name := normalize_secret_name(raw_name, context.text)) is not None
        }
        confidence = confidence_for_path(context.relpath)
        findings = [
            {"name": name, "path": context.relpath, "confidence": confidence}
            for name in sorted(names)
        ]
        return DetectionResult({"secret_references": findings})


BUILTIN_DETECTORS: tuple[Detector, ...] = (
    PromptDetector(),
    McpConfigDetector(),
    PolicyDetector(),
    DependencyDetector(),
    ModelDetector(),
    ProviderDetector(),
    FrameworkDetector(),
    CapabilityDetector(),
    SecretDetector(),
)


def detect_in_file(
    relpath: str, text: str | None, detectors: tuple[Detector, ...] = BUILTIN_DETECTORS
) -> DetectionResult:
    """Run detector plugins for one file."""
    combined = DetectionResult()
    context = DetectionContext(relpath=relpath, text=text, tree=_parse_python_ast(relpath, text))
    for detector in detectors:
        result = detector.detect(context)
        combined.has_policy = combined.has_policy or result.has_policy
        for key, items in result.findings.items():
            combined.findings.setdefault(key, [])
            for item in items:
                _append_unique(combined.findings[key], item)
    return combined


def detect_in_text(text: str, relpath: str) -> dict[str, list[dict[str, str]]]:
    """Compatibility wrapper for text-based detections."""
    result = detect_in_file(
        relpath,
        text,
        (
            ModelDetector(),
            ProviderDetector(),
            FrameworkDetector(),
            CapabilityDetector(),
            SecretDetector(),
        ),
    )
    return {
        "models": result.findings.get("models", []),
        "providers": result.findings.get("providers", []),
        "frameworks": result.findings.get("frameworks", []),
        "capabilities": result.findings.get("capabilities", []),
        "secret_references": result.findings.get("secret_references", []),
    }


def detect_mcp_config(relpath: str) -> dict[str, str] | None:
    findings = McpConfigDetector().detect(DetectionContext(relpath)).findings
    return _first(findings.get("mcp_servers", []))


def detect_prompt_file(relpath: str) -> dict[str, str] | None:
    findings = PromptDetector().detect(DetectionContext(relpath)).findings
    return _first(findings.get("prompts", []))


def is_policy_file(relpath: str) -> bool:
    return PolicyDetector().detect(DetectionContext(relpath)).has_policy


def detect_secret_references(text: str, relpath: str) -> list[dict[str, str]]:
    findings = SecretDetector().detect(DetectionContext(relpath, text)).findings
    return findings.get("secret_references", [])


def detect_capabilities(text: str, lower_text: str, relpath: str) -> list[dict[str, str]]:
    del lower_text
    findings = CapabilityDetector().detect(DetectionContext(relpath, text)).findings
    return findings.get("capabilities", [])


def detect_models(text: str, relpath: str) -> list[dict[str, str]]:
    findings = ModelDetector().detect(DetectionContext(relpath, text)).findings
    return findings.get("models", [])


def normalize_secret_name(name: str, text: str) -> str | None:
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper()
    if normalized in GENERIC_SECRET_NAMES:
        provider = provider_context(text)
        if provider is None:
            return None
        return f"{provider}_{normalized}"
    return normalized


def provider_context(text: str) -> str | None:
    lower = text.lower()
    providers = {
        name.upper()
        for name, patterns in PROVIDERS.items()
        if any(pattern.lower() in lower for pattern in patterns)
    }
    if len(providers) == 1:
        return next(iter(providers))
    return None


def can_detect_model(relpath: str) -> bool:
    suffix = PurePosixPath(relpath).suffix.lower()
    return suffix in {".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml"}


def can_detect_provider_or_framework(relpath: str) -> bool:
    suffix = PurePosixPath(relpath).suffix.lower()
    return suffix in {".py", ".ts", ".js", ".json", ".yaml", ".yml", ".toml"}


def confidence_for_path(relpath: str) -> str:
    suffix = PurePosixPath(relpath).suffix.lower()
    if suffix in {".py", ".ts", ".js"}:
        return "high"
    if suffix in {".json", ".yaml", ".yml", ".toml"}:
        return "medium"
    return "low"


def _prompt_finding(relpath: str) -> dict[str, str]:
    return {"path": relpath, "type": "prompt", "confidence": confidence_for_path(relpath)}


def _result(key: str, item: dict[str, str]) -> DetectionResult:
    return DetectionResult({key: [item]})


def _first(items: list[dict[str, str]]) -> dict[str, str] | None:
    if not items:
        return None
    return items[0]


def _detect_patterns(
    definitions: dict[str, tuple[str, ...]], lower_text: str, relpath: str
) -> list[dict[str, str]]:
    findings = []
    confidence = confidence_for_path(relpath)
    for name, patterns in definitions.items():
        for pattern in patterns:
            if pattern.lower() in lower_text:
                findings.append({"name": name, "path": relpath, "confidence": confidence})
                break
    return findings


def _append_unique(items: list[dict[str, str]], item: dict[str, str]) -> None:
    if item not in items:
        items.append(item)


def _parse_pyproject_dependencies(text: str) -> list[str]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []

    dependencies: list[str] = []
    project = data.get("project", {})
    if isinstance(project, dict):
        _extend_dependency_names(dependencies, project.get("dependencies", []))
        optional = project.get("optional-dependencies", {})
        if isinstance(optional, dict):
            for values in optional.values():
                _extend_dependency_names(dependencies, values)

    poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data.get("tool"), dict) else {}
    if isinstance(poetry, dict):
        poetry_dependencies = poetry.get("dependencies", {})
        if isinstance(poetry_dependencies, dict):
            for name in poetry_dependencies:
                if name.lower() != "python":
                    _append_name(dependencies, name)
        poetry_groups = poetry.get("group", {})
        if isinstance(poetry_groups, dict):
            for group in poetry_groups.values():
                if not isinstance(group, dict):
                    continue
                group_dependencies = group.get("dependencies", {})
                if isinstance(group_dependencies, dict):
                    for name in group_dependencies:
                        _append_name(dependencies, name)

    return dependencies


def _parse_requirements_dependencies(text: str) -> list[str]:
    dependencies: list[str] = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http://", "https://")):
            continue
        name = _dependency_name(line)
        if name:
            _append_name(dependencies, name)
    return dependencies


def _extend_dependency_names(dependencies: list[str], values: object) -> None:
    if not isinstance(values, list):
        return
    for value in values:
        if not isinstance(value, str):
            continue
        name = _dependency_name(value)
        if name:
            _append_name(dependencies, name)


def _dependency_name(value: str) -> str:
    name = re.split(r"\s*(?:\[|==|!=|~=|>=|<=|>|<|;)\s*", value, maxsplit=1)[0].strip()
    return name.lower().replace("_", "-")


def _dependency_category(name: str) -> str | None:
    normalized = name.lower().replace("_", "-")
    for category, names in DEPENDENCY_CATEGORIES.items():
        normalized_names = {item.replace("_", "-") for item in names}
        if normalized in normalized_names:
            return category
    return None


def _append_name(items: list[str], item: str) -> None:
    normalized = item.lower().replace("_", "-")
    if normalized and normalized not in items:
        items.append(normalized)


def _parse_python_ast(relpath: str, text: str | None) -> ast.AST | None:
    if text is None or PurePosixPath(relpath).suffix.lower() != ".py":
        return None
    try:
        return ast.parse(text)
    except SyntaxError:
        return None


def _detect_python_providers(context: DetectionContext) -> list[dict[str, str]]:
    imports = _python_imports(context.tree)
    names = _python_names_and_strings(context.tree)
    findings = []
    for provider, modules in {
        "openai": ("openai",),
        "anthropic": ("anthropic",),
        "gemini": ("google.generativeai",),
    }.items():
        if any(_module_matches(imported, modules) for imported in imports) or any(
            pattern in names for pattern in PROVIDERS[provider]
        ):
            findings.append(
                {
                    "name": provider,
                    "path": context.relpath,
                    "confidence": confidence_for_path(context.relpath),
                }
            )
    return findings


def _detect_python_capabilities(context: DetectionContext) -> list[dict[str, str]]:
    imports = _python_imports(context.tree)
    calls = _python_calls(context.tree)
    findings: list[dict[str, str]] = []
    confidence = confidence_for_path(context.relpath)

    if any(imported == "subprocess" or imported.startswith("subprocess.") for imported in imports):
        _append_unique(findings, {"name": "shell", "path": context.relpath, "confidence": confidence})
    if any(
        call
        in {
            "subprocess.run",
            "subprocess.Popen",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
        }
        for call in calls
    ):
        _append_unique(findings, {"name": "shell", "path": context.relpath, "confidence": confidence})
    if "os.system" in calls:
        _append_unique(findings, {"name": "shell", "path": context.relpath, "confidence": confidence})
    if any(call in {"eval", "exec", "builtins.eval", "builtins.exec"} for call in calls):
        _append_unique(
            findings,
            {"name": "code_execution", "path": context.relpath, "confidence": confidence},
        )
    if _has_python_network_access(imports, calls):
        _append_unique(findings, {"name": "network", "path": context.relpath, "confidence": confidence})
    if _has_python_mcp_tool_invocation(imports, calls):
        _append_unique(
            findings,
            {"name": "mcp_tool_invocation", "path": context.relpath, "confidence": confidence},
        )
    if any(_module_matches(imported, ("boto3", "google.cloud", "azure")) for imported in imports):
        _append_unique(findings, {"name": "cloud", "path": context.relpath, "confidence": confidence})
    if any(_module_matches(imported, ("sqlite3", "psycopg", "sqlalchemy", "pymongo")) for imported in imports):
        _append_unique(
            findings,
            {"name": "database", "path": context.relpath, "confidence": confidence},
        )

    for name, patterns in CAPABILITY_REGEXES.items():
        if context.text is not None and any(
            re.search(pattern, context.text, re.IGNORECASE) for pattern in patterns
        ):
            _append_unique(findings, {"name": name, "path": context.relpath, "confidence": confidence})
    return findings


def _python_imports(tree: ast.AST | None) -> set[str]:
    imports: set[str] = set()
    if tree is None:
        return imports
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
            for alias in node.names:
                imports.add(f"{node.module}.{alias.name}")
    return imports


def _python_calls(tree: ast.AST | None) -> set[str]:
    calls: set[str] = set()
    if tree is None:
        return calls
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            if name is not None:
                calls.add(name)
    return calls


def _python_names_and_strings(tree: ast.AST | None) -> set[str]:
    values: set[str] = set()
    if tree is None:
        return values
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            values.add(node.id)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            values.add(node.value)
    return values


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        if parent is None:
            return node.attr
        return f"{parent}.{node.attr}"
    return None


def _module_matches(imported: str, modules: tuple[str, ...]) -> bool:
    return any(imported == module or imported.startswith(f"{module}.") for module in modules)


def _has_python_network_access(imports: set[str], calls: set[str]) -> bool:
    if any(_module_matches(imported, ("requests", "httpx", "aiohttp", "urllib.request")) for imported in imports):
        return True
    return any(
        call.startswith(("requests.", "httpx.", "aiohttp.", "urllib.request."))
        for call in calls
    )


def _has_python_mcp_tool_invocation(imports: set[str], calls: set[str]) -> bool:
    has_mcp_import = any(_module_matches(imported, ("mcp",)) for imported in imports)
    if has_mcp_import and any(call.endswith((".call_tool", ".invoke_tool")) for call in calls):
        return True
    return any("mcp" in call.lower() and call.endswith((".call_tool", ".invoke_tool")) for call in calls)
