# MCP Security Agent

This project is a local AI security lab built around the Model Context Protocol (MCP). It demonstrates how an agent can talk to a protected sandbox, call authorized tools, and enforce security boundaries before exposing data to a Gemini-based model.

## Goals

- test prompt-injection resistance
- validate path traversal prevention
- enforce per-user file and tool policies
- demonstrate secure tool calling through MCP
- provide a local web interface to interact with the agent

## Architecture

- Frontend: React + Vite UI in `frontend/`
- API: FastAPI backend in `api/main.py`
- MCP server: secure sandbox tools in `server/server.py`
- Agent: Gemini + MCP-compatible orchestration in `agent/agent.py`
- Security tests: `tests/test_security_policy.py`

## Features

- login flow with simple bearer-token authentication
- per-user permissions for tools and files
- sandboxed file access with extension validation and path checks
- protected file blocking
- secure chat endpoint and SSE stream mode
- logout and session expiry handling

## Local startup

1. Activate the virtual environment:

   ```bash
   cd /home/hafsa/mcp
   source .venv/bin/activate
   ```

2. Start the API:

   ```bash
   python -m uvicorn api.main:app --host 127.0.0.1 --port 8001 --reload
   ```

3. Start the frontend:

   ```bash
   cd frontend
   npm install
   npm run dev
   ```

4. Open the app in the browser on the Vite local URL.

## Default test users

- normal_user / secret123
- admin / admin123

## Security notes

This project is intended for security research and controlled local testing. The sandbox is intentionally limited, and all tool access is restricted by policy and path validation.

## Validation

Run the backend tests:

```bash
cd /home/hafsa/mcp
source .venv/bin/activate
python -m pytest -q tests/test_security_policy.py
```

Build the frontend:

```bash
cd /home/hafsa/mcp/frontend
npm run build
```
