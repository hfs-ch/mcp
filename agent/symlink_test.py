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

            print("=== SYMLINK ESCAPE SECURITY TEST ===")

            result = await session.call_tool(
                "read_file",
                arguments={
                    "filename": "secret_link.txt"
                }
            )

            print("\n=== SERVER RESPONSE ===")
            print(result)


if __name__ == "__main__":
    asyncio.run(main())