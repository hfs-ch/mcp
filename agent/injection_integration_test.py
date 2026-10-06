import asyncio

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from security import sanitize_mcp_content


server_params = StdioServerParameters(
    command="python",
    args=["server/server.py"],
)


async def main():

    print("=== MCP PROMPT INJECTION INTEGRATION TEST ===")

    async with stdio_client(server_params) as (read, write):

        async with ClientSession(read, write) as session:

            await session.initialize()

            result = await session.call_tool(
                "read_file",
                arguments={
                    "filename": "malicious.txt"
                }
            )

            content = result.structured_content.get("result", "")

            print("\n=== ORIGINAL MCP CONTENT ===")
            print(content)

            safe_content = sanitize_mcp_content(content)

            print("\n=== SECURITY FILTER RESULT ===")
            print(safe_content)


if __name__ == "__main__":
    asyncio.run(main())
