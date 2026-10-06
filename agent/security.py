import re


SUSPICIOUS_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"ignore\s+all\s+instructions",
    r"forget\s+previous\s+instructions",
    r"system\s+message",
    r"reveal\s+.*(secret|private|confidential)",
    r"read\s+the\s+file\s+private",
]


def detect_prompt_injection(content: str) -> bool:
    """
    Detect common indirect prompt injection patterns.
    """

    content_lower = content.lower()

    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, content_lower):
            return True

    return False


def sanitize_mcp_content(content: str) -> str:
    """
    Treat MCP content as untrusted data.
    """

    if detect_prompt_injection(content):
        return (
            "[SECURITY WARNING]\n"
            "Potential prompt injection detected in MCP content.\n"
            "The content has been blocked because it contains "
            "instruction-like text."
        )

    return content
