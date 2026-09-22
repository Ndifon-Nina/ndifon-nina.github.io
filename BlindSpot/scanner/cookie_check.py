from http.cookies import SimpleCookie


def check_cookies(url, homepage_response):
    """
    Do cookies set by the site have Secure, HttpOnly, and SameSite attributes?
    Parsed straight from the raw Set-Cookie headers with SimpleCookie, which
    reads these flags more reliably than a cookie jar does.
    """
    set_cookie_headers = homepage_response.raw.headers.getlist("Set-Cookie")
    if not set_cookie_headers:
        return []

    flagged = []
    for header in set_cookie_headers:
        cookie = SimpleCookie()
        cookie.load(header)
        for morsel in cookie.values():
            missing = []
            if not morsel["secure"]:
                missing.append("Secure")
            if not morsel["httponly"]:
                missing.append("HttpOnly")
            if not morsel["samesite"]:
                missing.append("SameSite")
            if missing:
                flagged.append((morsel.key, missing))

    if not flagged:
        return []

    names = ", ".join(f"{name} (missing {', '.join(m)})" for name, m in flagged)
    return [{
        "check_type": "cookies",
        "severity": "MEDIUM",
        "title": "Cookies missing security attributes",
        "description": f"These cookies are missing recommended attributes: {names}. "
                        "Cookies without them are easier to steal or misuse via network "
                        "interception or cross-site scripting.",
        "recommendation": "Set Secure, HttpOnly, and SameSite on every cookie that doesn't "
                           "need to be read by JavaScript.",
    }]
