#!/usr/bin/env python3
"""Zepp login-only diagnostic. No activity upload, device binding, or token persistence."""
import os
import sys

# Load only the Zepp authentication helper, not main.py or any step-posting routine.
from util.zepp_helper import login_access_token


def suspicious_wrapped(value):
    return len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'")


def main():
    username = os.environ.get("USER", "")
    password = os.environ.get("PWD", "")

    # Report booleans only. Never print credentials, their lengths, response URLs or tokens.
    checks = {
        "username_present": bool(username),
        "password_present": bool(password),
        "email_format": username.count("@") == 1 and "." in username.rsplit("@", 1)[-1],
        "username_surrounding_whitespace": username != username.strip(),
        "password_surrounding_whitespace": password != password.strip(),
        "username_has_newline": "\r" in username or "\n" in username,
        "password_has_newline": "\r" in password or "\n" in password,
        "username_wrapped_in_quotes": suspicious_wrapped(username),
        "password_wrapped_in_quotes": suspicious_wrapped(password),
    }
    for name, result in checks.items():
        print("INPUT_CHECK %s=%s" % (name, str(result).lower()), flush=True)

    suspicious = (
        not checks["username_present"]
        or not checks["password_present"]
        or not checks["email_format"]
        or any(checks[name] for name in (
            "username_surrounding_whitespace",
            "password_surrounding_whitespace",
            "username_has_newline",
            "password_has_newline",
            "username_wrapped_in_quotes",
            "password_wrapped_in_quotes",
        ))
    )
    if suspicious:
        print("RESULT=INPUT_FORMAT_REVIEW_NEEDED; login request skipped", flush=True)
        return 2

    if os.environ.get("PERFORM_LOGIN", "false").lower() != "true":
        print("RESULT=FORMAT_CHECK_ONLY; no network authentication attempted", flush=True)
        return 0

    # Exactly one Zepp login call. A successful access token is immediately discarded.
    # This module does NOT call grant_login_tokens, get_user_device_id,
    # post_fake_brand_data, or persist_user_tokens.
    print("LOGIN_ATTEMPT=ONE_AUTH_REQUEST_ONLY", flush=True)
    try:
        token, error_message = login_access_token(username, password)
    except Exception as exc:
        print("RESULT=AUTH_EXCEPTION_%s" % type(exc).__name__, flush=True)
        return 1

    if token is not None:
        del token
        print("RESULT=ACCESS_TOKEN_GRANTED_NOT_STORED", flush=True)
        return 0

    # Never print raw redirect URLs or server messages: they can contain secrets.
    if error_message and error_message.startswith("获取accessToken失败"):
        if "401" in error_message:
            kind = "ZEPP_REDIRECT_REJECTED_401"
        else:
            kind = "ZEPP_REDIRECT_REJECTED_OTHER"
    elif error_message and error_message.startswith("登录异常，status:"):
        code = error_message.rsplit(":", 1)[-1].strip()
        kind = "HTTP_STATUS_" + code if code.isdigit() else "HTTP_STATUS_UNEXPECTED"
    elif error_message and error_message.startswith("获取accessToken异常"):
        kind = "AUTH_REDIRECT_PARSE_ERROR"
    else:
        kind = "AUTH_FAILURE_UNCLASSIFIED"
    print("RESULT=" + kind, flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())
