DIRECTORY_INDICATORS = ["index of /", "directory listing for"]


def check_directory_listing(url, homepage_response):
    """Does the homepage itself look like a raw, auto-generated file listing?"""
    page_text = homepage_response.text.lower()

    if any(indicator in page_text for indicator in DIRECTORY_INDICATORS):
        return [{
            "check_type": "directory",
            "severity": "MEDIUM",
            "title": "Directory listing may be enabled on the homepage",
            "description": "The homepage content looks like an auto-generated file listing, "
                            "which can expose files that were never meant to be browsed directly.",
            "recommendation": "Disable directory listing/autoindex in your web server configuration.",
        }]
    return []
