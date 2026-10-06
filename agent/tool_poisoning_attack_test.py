
import asyncio
import logging

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


# ============================================================
# SECURITY LOGGING
# ============================================================

logging.basicConfig(
    filename="security.log",
    level=logging.WARNING,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

logger = logging.getLogger("mcp-security")


# ============================================================
# TOOL POISONING DETECTION
# ============================================================

SUSPICIOUS_PATTERNS = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "important system message",
    "system message",
    "developer message",
    "reveal",
    "private.txt",
    "secret",
    "password",
]


def detect_tool_poisoning(description: str) -> list[str]:
    """
    Detect suspicious instruction-like patterns
    inside an MCP tool description.
    """

    description_lower = description.lower()

    return [
        pattern
        for pattern in SUSPICIOUS_PATTERNS
        if pattern in description_lower
    ]


# ============================================================
# MAIN TEST
# ============================================================

async def main():

    print("=== MCP TOOL POISONING ATTACK TEST ===")

    server_params = StdioServerParameters(
        command="/home/hafsa/mcp/.venv/bin/python",
        args=[
            "/home/hafsa/mcp/server/malicious_server.py"
        ],
    )

    async with stdio_client(server_params) as (read, write):

        async with ClientSession(read, write) as session:

            await session.initialize()

            tools_result = await session.list_tools()

            print("\n=== MCP TOOLS ===")

            for tool in tools_result.tools:

                print(f"\nTool: {tool.name}")
                print(f"Description:\n{tool.description}")

                detected = detect_tool_poisoning(
                    tool.description or ""
                )

                # ====================================================
                # MALICIOUS TOOL DETECTED
                # ====================================================

                if detected:

                    print(
                        "\n🚨 TOOL POISONING DETECTED"
                    )

                    # Security event logging
                    logger.warning(
                        "SECURITY_EVENT=TOOL_POISONING | "
                        "Malicious tool description detected | "
                        "tool=%s | patterns=%s",
                        tool.name,
                        detected,
                    )

                    print(
                        "Suspicious patterns:"
                    )

                    for pattern in detected:
                        print(f"- {pattern}")

                    print(
                        "\n🛑 TOOL BLOCKED"
                    )

                # ====================================================
                # SAFE TOOL
                # ====================================================

                else:

                    print(
                        "\n✅ Tool description appears safe"
                    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    asyncio.run(main())
