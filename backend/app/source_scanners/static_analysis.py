import re


SECRET_RULES = (
    {
        "id": "private-key",
        "title": "Private encryption key in source files",
        "pattern": re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
        ),
        "severity": "Critical",
        "confidence": "High",
        "fix": (
            "Remove the key from the repository, revoke or rotate it, "
            "and load the replacement from an approved secret store."
        ),
    },
    {
        "id": "aws-access-key",
        "title": "Possible AWS access key in source files",
        "pattern": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        "severity": "Critical",
        "confidence": "High",
        "fix": (
            "Disable and rotate the key, then use an IAM role or "
            "approved secret store instead of a hardcoded credential."
        ),
    },
    {
        "id": "github-token",
        "title": "Possible GitHub access token in source files",
        "pattern": re.compile(
            r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,255}\b"
        ),
        "severity": "Critical",
        "confidence": "High",
        "fix": (
            "Revoke and rotate the token, remove it from Git history, "
            "and load credentials from a protected secret store."
        ),
    },
    {
        "id": "literal-secret",
        "title": "Possible hardcoded password or secret",
        "pattern": re.compile(
            r"(?i)\b(password|passwd|api[_-]?key|secret|token)\b"
            r"\s*[:=]\s*['\"]([^'\"\r\n]{8,})['\"]"
        ),
        "severity": "High",
        "confidence": "Medium",
        "fix": (
            "Confirm whether this is a real credential. If it is, rotate "
            "it and load it from an environment variable or secret store."
        ),
    },
)

CODE_RULES = (
    {
        "id": "python-shell-true",
        "extensions": {".py"},
        "title": "Shell command execution enabled",
        "pattern": re.compile(r"\bshell\s*=\s*True\b"),
        "severity": "High",
        "confidence": "High",
        "explanation": (
            "The backend enables operating-system shell interpretation. "
            "Untrusted input could turn this into command injection."
        ),
        "fix": (
            "Use an argument list with shell disabled and strictly "
            "validate any value that can be influenced by a user."
        ),
    },
    {
        "id": "python-debug-mode",
        "extensions": {".py"},
        "title": "Application debug mode may be enabled",
        "pattern": re.compile(r"\bdebug\s*=\s*True\b"),
        "severity": "High",
        "confidence": "Medium",
        "explanation": (
            "Production debug pages can expose source code, environment "
            "details, or an interactive debugger."
        ),
        "fix": (
            "Disable debug mode in production and control it through a "
            "secure environment-specific configuration."
        ),
    },
    {
        "id": "dynamic-eval",
        "extensions": {".py", ".js", ".jsx", ".ts", ".tsx"},
        "title": "Dynamic code evaluation observed",
        "pattern": re.compile(r"(?<![A-Za-z0-9_])eval\s*\("),
        "severity": "High",
        "confidence": "Medium",
        "explanation": (
            "Dynamic evaluation can execute attacker-controlled text as "
            "code when its input is not fully trusted."
        ),
        "fix": (
            "Replace dynamic evaluation with explicit parsing and an "
            "allowlist of supported operations."
        ),
    },
    {
        "id": "javascript-inner-html",
        "extensions": {".js", ".jsx", ".ts", ".tsx"},
        "title": "HTML is inserted directly into the page",
        "pattern": re.compile(r"\.innerHTML\s*="),
        "severity": "Medium",
        "confidence": "Medium",
        "explanation": (
            "Direct HTML insertion can create cross-site scripting when "
            "the value contains untrusted data."
        ),
        "fix": (
            "Prefer textContent or safe framework rendering. If HTML is "
            "required, sanitize it with a maintained allowlist-based tool."
        ),
    },
)

DEPENDENCY_FILES = {
    "requirements.txt": "Python requirements",
    "poetry.lock": "Python Poetry lockfile",
    "pipfile": "Python Pipfile",
    "package.json": "Node.js package manifest",
    "package-lock.json": "Node.js lockfile",
    "yarn.lock": "Yarn lockfile",
    "pom.xml": "Java Maven manifest",
    "gemfile": "Ruby Gemfile",
}


def line_number(content, offset):
    return content.count("\n", 0, offset) + 1


def finding(rule, path, match, *, secret=False):
    result = {
        "rule_id": rule["id"],
        "title": rule["title"],
        "severity": rule["severity"],
        "confidence": rule["confidence"],
        "path": path,
        "line": line_number(match.string, match.start()),
        "fix": rule["fix"],
        "secret_redacted": secret,
    }

    if secret:
        result["explanation"] = (
            "WebShield found text shaped like a credential. The value "
            "was deliberately removed from this report."
        )
        result["evidence"] = "[REDACTED POSSIBLE SECRET]"
    else:
        result["explanation"] = rule["explanation"]
        result["evidence"] = match.group(0)[:120]

    return result


def analyze_source_files(files):
    findings = []
    manifests = []

    for item in files:
        content = item["content"]
        extension = item["extension"]
        name = item["name"].lower()

        if name in DEPENDENCY_FILES:
            manifests.append({
                "path": item["path"],
                "type": DEPENDENCY_FILES[name],
            })

        for rule in SECRET_RULES:
            for match in rule["pattern"].finditer(content):
                findings.append(
                    finding(rule, item["path"], match, secret=True)
                )

        for rule in CODE_RULES:
            if extension not in rule["extensions"]:
                continue

            for match in rule["pattern"].finditer(content):
                findings.append(finding(rule, item["path"], match))

    return {
        "findings": findings,
        "dependency_manifests": manifests,
    }
