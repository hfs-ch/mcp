```python
# ============================================================
# MCP SECURITY POLICY
# ============================================================

USERS = {
    "normal_user": {
        "tools": {
            "list_files",
            "read_file",
        },
        "files": {
            "project.txt",
            "test.txt",
            "documents/document.txt",
        },
    },

    "admin": {
        "tools": {
            "list_files",
            "read_file",
        },
        "files": {
            "project.txt",
            "test.txt",
            "documents/document.txt",
            "private.txt",
        },
    },
}


def is_tool_authorized(
    username: str,
    tool_name: str,
) -> bool:

    user = USERS.get(username)

    if not user:
        return False

    return tool_name in user["tools"]


def is_file_authorized(
    username: str,
    filename: str,
) -> bool:

    user = USERS.get(username)

    if not user:
        return False

    return filename in user["files"]
```
