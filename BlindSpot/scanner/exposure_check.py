import requests

TIMEOUT = 8

SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/backup.zip",
    "/backup/",
    "/test/",
    "/debug/",
    "/config.php.bak",
    "/.DS_Store",
]

DIRECTORY_INDICATORS = ["index of /", "directory listing for"]


def check_exposure(url, homepage_response):
    """
    Probe a list of commonly-forgotten paths. Some sites return their normal
    homepage (or a friendly custom 404) for every path you try — comparing
    against the real homepage text avoids flagging those as false positives.
    """
    findings = []
    base = url.rstrip("/")
    homepage_text = homepage_response.text.lower()

    for path in SENSITIVE_PATHS:
        try:
            probe = requests.get(base + path, timeout=TIMEOUT, allow_redirects=False)
        except requests.exceptions.RequestException:
            continue

        if probe.status_code != 200 or not probe.content:
            continue

        page_text = probe.text.lower()

        # A page identical to the homepage means the server just serves the
        # same content for every URL (common with single-page apps) — not a
        # real exposure.
        if page_text == homepage_text:
            continue

        if any(indicator in page_text for indicator in DIRECTORY_INDICATORS):
            findings.append({
                "check_type": "directory",
                "severity": "MEDIUM",
                "title": f"Directory listing enabled at {path}",
                "description": f"BlindSpot found what looks like a raw file listing at '{path}'. "
                                "This can expose files that were never meant to be browsed directly.",
                "recommendation": f"Disable directory listing/autoindex for '{path}' in your web "
                                   "server configuration.",
            })
            continue

        severity = "HIGH" if path in ("/.env", "/.git/config", "/backup.zip", "/config.php.bak") else "MEDIUM"
        findings.append({
            "check_type": "exposure",
            "severity": severity,
            "title": f"Possible exposed resource: {path}",
            "description": f"'{base}{path}' returned a 200 OK response with real content. "
                            "This may reveal sensitive files, configuration, or backups.",
            "recommendation": f"Confirm whether '{path}' should be publicly accessible. If not, "
                               "remove it or block access at the server/config level.",
        })

    return findings
