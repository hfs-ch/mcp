import re
from pathlib import Path


LOG_FILE = Path("security.log")


def check_event(event_name: str) -> bool:
    if not LOG_FILE.exists():
        return False

    content = LOG_FILE.read_text(encoding="utf-8")
    return f"SECURITY_EVENT={event_name}" in content


def print_result(name: str, passed: bool):
    status = "PASS" if passed else "FAIL"
    symbol = "✅" if passed else "❌"
    print(f"{symbol} {name:<25} : {status}")


def main():
    print("=" * 50)
    print("       MCP END-TO-END SECURITY TEST")
    print("=" * 50)

    print("\n=== SECURITY EVENTS DETECTED IN LOG ===\n")

    tests = {
        "PATH_TRAVERSAL": check_event("PATH_TRAVERSAL"),
        "PROMPT_INJECTION": check_event("PROMPT_INJECTION"),
        "UNAUTHORIZED_FILE": check_event("UNAUTHORIZED_FILE"),
        "TOOL_POISONING": check_event("TOOL_POISONING"),
        "TOKEN_PASSTHROUGH": check_event("TOKEN_PASSTHROUGH"),
        "CONFUSED_DEPUTY": check_event("CONFUSED_DEPUTY"),
    }

    for event, result in tests.items():
        print_result(event, result)

    print("\n" + "=" * 50)

    passed = sum(tests.values())
    total = len(tests)

    print(f"Security controls detected: {passed}/{total}")

    if passed == total:
        print("\n🛡️ OVERALL RESULT: PASS")
        print("Defense-in-depth security controls are active.")
    else:
        print("\n⚠️ OVERALL RESULT: INCOMPLETE")
        print("Some security events were not found in the log.")

    print("=" * 50)


if __name__ == "__main__":
    main()
