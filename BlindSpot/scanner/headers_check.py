GOOD_HEADERS = {
    "Content-Security-Policy": "HIGH",
    "Strict-Transport-Security": "MEDIUM",
    "X-Frame-Options": "MEDIUM",
    "X-Content-Type-Options": "LOW",
    "Referrer-Policy": "LOW",
}


def check_headers(url, homepage_response):
    """Which important security headers is the site missing?"""
    present = {h.lower() for h in homepage_response.headers.keys()}
    missing = [h for h in GOOD_HEADERS if h.lower() not in present]

    if not missing:
        return []

    # One finding per missing header, so each shows its own severity and advice.
    findings = []
    for header in missing:
        findings.append({
            "check_type": "headers",
            "severity": GOOD_HEADERS[header],
            "title": f"Missing header: {header}",
            "description": f"The response did not include the '{header}' header, which helps "
                            "protect visitors from common attacks like clickjacking or script injection.",
            "recommendation": f"Configure your server or framework to send the '{header}' header "
                               "on every response.",
        })
    return findings
