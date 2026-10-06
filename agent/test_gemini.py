import os

from dotenv import load_dotenv
from google import genai


# Load environment variables from .env
load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    raise RuntimeError(
        "GEMINI_API_KEY is not defined in the .env file."
    )


# Create Gemini client
client = genai.Client(api_key=api_key)


# Send a simple request to Gemini
response = client.models.generate_content(
    model="gemini-3.6-flash",
    contents="Explain MCP in one simple sentence."
)


# Display Gemini response
print("\n=== Gemini Response ===")
print(response.text)