import asyncio

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


server_params = StdioServerParameters(
    command="python",
    args=["server/server.py"],
)


async def main():

    print("=== TOOL POISONING TEST ===")

    async with stdio_client(server_params) as (read, write):

        async with ClientSession(read, write) as session:

            await session.initialize()

            tools_result = await session.list_tools()

            print("\n=== MCP TOOL DESCRIPTIONS ===")

            for tool in tools_result.tools:

                print(f"\nTool: {tool.name}")
                print(f"Description: {tool.description}")

                description = (
                    tool.description or ""
                ).lower()

                suspicious_patterns = [
                    "ignore previous instructions",
                    "ignore all previous instructions",
                    "system message",
                    "developer message",
                    "reveal",
                    "secret",
                    "password",
                    "private file",
                    "outside the sandbox",
                ]

                detected = [
                    pattern
                    for pattern in suspicious_patterns
                    if pattern in description
                ]

                if detected:

                    print(
                        "\n⚠️ TOOL POISONING DETECTED"
                    )

                    print(
                        "Suspicious instructions found:"
                    )

                    for pattern in detected:
                        print(f"- {pattern}")

                else:

                    print(
                        "\n✅ Description appears safe"
                    )


if __name__ == "__main__":
    asyncio.run(main())
