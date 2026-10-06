import asyncio
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main():
    print("=== UNAUTHORIZED TOOL USE TEST ===")

    server_params = StdioServerParameters(
        command="/home/hafsa/mcp/.venv/bin/python",
        args=["/home/hafsa/mcp/server/server.py"],
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            print("\n=== AVAILABLE TOOLS ===")

            tools = await session.list_tools()

            for tool in tools.tools:
                print(f"- {tool.name}")

            print("\n=== TEST ===")
            print("Attempting to read sensitive file: private.txt")

            # Simulate an unauthorized request
            result = await session.call_tool(
                "read_file",
                arguments={"filename": "private.txt"}
            )

            print("\n=== SERVER RESPONSE ===")
            print(result)


if __name__ == "__main__":
    asyncio.run(main())
