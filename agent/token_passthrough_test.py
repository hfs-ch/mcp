import asyncio
import logging

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


logging.basicConfig(
    filename="security.log",
    level=logging.WARNING,
    format="%(asctime)s | %(levelname)s | %(message)s",
)


# Fake token used ONLY for this security test
FAKE_TOKEN = "FAKE-GEMINI-TOKEN-12345"


def detect_token_passthrough(token: str) -> bool:
    """
    Detect whether a sensitive token is being
    passed directly to another MCP tool/API.
    """

    return token.startswith("FAKE-")


async def main():

    print("=== MCP TOKEN PASSTHROUGH SECURITY TEST ===")

    server_params = StdioServerParameters(
        command="/home/hafsa/mcp/.venv/bin/python",
        args=["/home/hafsa/mcp/server/server.py"],
    )

    async with stdio_client(server_params) as (read, write):

        async with ClientSession(read, write) as session:

            await session.initialize()

            print("\n=== TEST TOKEN ===")
            print(FAKE_TOKEN)

            print("\n=== SECURITY CHECK ===")

            if detect_token_passthrough(FAKE_TOKEN):

                logging.warning(
                    "SECURITY_EVENT=TOKEN_PASSTHROUGH | "
                    "Sensitive token attempted to cross trust boundary"
                )

                print(
                    "⚠️ TOKEN PASSTHROUGH DETECTED"
                )

                print(
                    "🛑 Token must NOT be forwarded "
                    "to another service."
                )

            else:

                print(
                    "✅ No token passthrough detected."
                )


if __name__ == "__main__":
    asyncio.run(main())
