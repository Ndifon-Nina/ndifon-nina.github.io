import requests


def check_https(url, homepage_response=None):
    """Is the site using HTTPS at all?"""
    if url.startswith("https://"):
        return []
    return [{
        "check_type": "https",
        "severity": "HIGH",
        "title": "Website does not use HTTPS",
        "description": "The website is served over plain HTTP. Data sent between visitors "
                        "and the site (passwords, forms, cookies) is not encrypted and could "
                        "be read by anyone in between.",
        "recommendation": "Install an SSL/TLS certificate and redirect all HTTP traffic to HTTPS.",
    }]
