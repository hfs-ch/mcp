import logging


logging.basicConfig(
    filename="security.log",
    level=logging.WARNING,
    format="%(asctime)s | %(levelname)s | %(message)s",
)


# ============================================================
# SIMULATED USERS
# ============================================================

USER_PERMISSIONS = {
    "normal_user": {
        "project.txt",
        "test.txt",
    }
}


# ============================================================
# SIMULATED MCP SERVER PERMISSIONS
# ============================================================

SERVER_PERMISSIONS = {
    "project.txt",
    "test.txt",
    "private.txt",
}


# ============================================================
# CONFUSED DEPUTY TEST
# ============================================================

def main():

    print("=== CONFUSED DEPUTY SECURITY TEST ===")

    user = "normal_user"
    requested_file = "private.txt"

    print(f"\nUser: {user}")
    print(f"Requested resource: {requested_file}")

    user_allowed = requested_file in USER_PERMISSIONS[user]

    server_allowed = requested_file in SERVER_PERMISSIONS

    print("\n=== PERMISSION ANALYSIS ===")

    print(
        f"User permission: "
        f"{'ALLOWED' if user_allowed else 'DENIED'}"
    )

    print(
        f"Server permission: "
        f"{'ALLOWED' if server_allowed else 'DENIED'}"
    )

    # --------------------------------------------------------
    # CONFUSED DEPUTY
    # --------------------------------------------------------

    if not user_allowed and server_allowed:

        logging.warning(
            "SECURITY_EVENT=CONFUSED_DEPUTY | "
            "Server has broader privileges than user | "
            "user=%s resource=%s",
            user,
            requested_file,
        )

        print(
            "\n⚠️ CONFUSED DEPUTY CONDITION DETECTED"
        )

        print(
            "The server has permission to access "
            "the resource, but the user does not."
        )

        print(
            "\n🛑 SECURITY POLICY:"
        )

        print(
            "The server MUST NOT use its own "
            "privileges to satisfy this request."
        )

    else:

        print(
            "\n✅ No confused deputy condition detected."
        )


if __name__ == "__main__":
    main()
