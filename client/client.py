import asyncio

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


server_params = StdioServerParameters(
    command="python",
    args=["server/server.py"],
)


async def main():

    async with stdio_client(server_params) as (read, write):

        async with ClientSession(read, write) as session:

            await session.initialize()

            tools_result = await session.list_tools()

            print("\n=== MCP Tools ===")

            for tool in tools_result.tools:
                print(f"- {tool.name}: {tool.description}")

            # Test list_files
            result = await session.call_tool(
                "list_files",
                arguments={}
            )

            print("\n=== list_files Result ===")
            print(result)

            # Test read_file
            result = await session.call_tool(
                "read_file",
                arguments={
                    "filename": "project.txt"
                }
            )

            print("\n=== read_file Result ===")
            print(result)


if __name__ == "__main__":
    asyncio.run(main())