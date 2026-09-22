import requests

TIMEOUT = 8

LEAK_WORDS = [
    "traceback",
    "mysql",
    "postgresql",
    "sqlstate",
    "stack trace",
    "filenotfoundexception",
    "internal error details",
]


def check_error_leakage(url, homepage_response=None):
    """
    Request a made-up page that shouldn't exist, and check whether the error
    response leaks technical details (stack traces, database engine names,
    file paths) that could help an attacker map out the site's internals.
    """
    probe_url = url.rstrip("/") + "/doesnotexist_blindspot_probe_123456"
    try:
        response = requests.get(probe_url, timeout=TIMEOUT)
    except requests.exceptions.RequestException:
        return []

    text = response.text.lower()
    found = [word for word in LEAK_WORDS if word in text]
    if not found:
        return []

    return [{
        "check_type": "leakage",
        "severity": "LOW",
        "title": "Error pages may reveal technical details",
        "description": "A non-existent page returned a response containing technical terms ("
                        + ", ".join(found) + "). This can give an attacker clues about the "
                        "site's internals (database engine, file paths, framework).",
        "recommendation": "Use friendly, generic error pages in production that never show "
                           "stack traces or database error details to visitors.",
    }]
