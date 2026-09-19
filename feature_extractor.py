# ==========================================
# PHISHING WEBSITE FEATURE EXTRACTOR
# Final deployment: 15 features
# ==========================================

import ipaddress
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup


SHORTENER_DOMAINS = {
    "bit.ly", "goo.gl", "shorte.st", "go2l.ink", "x.co", "ow.ly",
    "t.co", "tinyurl.com", "tr.im", "is.gd", "tiny.cc", "lnkd.in",
    "adf.ly", "cutt.us", "cutt.ly", "v.gd", "po.st", "j.mp"
}


def extract_features(url):
    """Extract the same 15 features expected by the saved model."""

    raw_url = url.strip()

    # Add a scheme only for parsing/requesting a URL that has none.
    request_url = raw_url
    if not request_url.startswith(("http://", "https://")):
        request_url = "http://" + request_url

    parsed = urlparse(request_url)
    hostname = parsed.hostname or ""
    hostname_lower = hostname.lower()

    features = {}

    # 1. UsingIP
    try:
        ipaddress.ip_address(hostname)
        features["UsingIP"] = -1
    except ValueError:
        features["UsingIP"] = 1

    # 2. LongURL
    length = len(raw_url)
    if length < 54:
        features["LongURL"] = 1
    elif length <= 75:
        features["LongURL"] = 0
    else:
        features["LongURL"] = -1

    # 3. ShortURL
    features["ShortURL"] = -1 if any(
        domain in raw_url.lower() for domain in SHORTENER_DOMAINS
    ) else 1

    # 4. Symbol@
    features["Symbol@"] = -1 if "@" in raw_url else 1

    # 5. Redirecting//
    features["Redirecting//"] = -1 if raw_url.rfind("//") > 6 else 1

    # 6. PrefixSuffix-
    features["PrefixSuffix-"] = -1 if "-" in hostname else 1

    # 7. SubDomains
    # This follows the common dataset rule based on dots in the URL.
    dot_count = raw_url.count(".")
    if dot_count == 1:
        features["SubDomains"] = 1
    elif dot_count == 2:
        features["SubDomains"] = 0
    else:
        features["SubDomains"] = -1

    # 8. HTTPS
    # Do not add HTTPS before calculating this feature.
    features["HTTPS"] = 1 if raw_url.lower().startswith("https://") else -1

    # 9. NonStdPort
    try:
        features["NonStdPort"] = -1 if parsed.port is not None else 1
    except ValueError:
        features["NonStdPort"] = -1

    # 10. HTTPSDomainURL
    features["HTTPSDomainURL"] = -1 if "https" in hostname_lower else 1

    # Fetch the page for the HTML-based features.
    response = None
    soup = None

    request_candidates = [request_url]
    if not raw_url.lower().startswith(("http://", "https://")):
        request_candidates.append("https://" + raw_url)

    for candidate in request_candidates:
        try:
            response = requests.get(
                candidate,
                timeout=5,
                headers={"User-Agent": "Mozilla/5.0"},
                allow_redirects=True
            )
            soup = BeautifulSoup(response.text, "html.parser")
            break
        except requests.RequestException:
            continue

    # When the page cannot be retrieved, use the dataset's suspicious/error
    # fallback for the HTML-dependent features rather than inventing values.
    if soup is None:
        features["Favicon"] = -1
        features["RequestURL"] = -1
        features["AnchorURL"] = -1
        features["ServerFormHandler"] = -1
        features["IframeRedirection"] = -1
        return features

    base_url = response.url
    base_hostname = urlparse(base_url).hostname or hostname

    # 11. Favicon
    favicon_value = -1
    for link in soup.find_all("link", href=True):
        rel = " ".join(link.get("rel", [])).lower()
        href = link.get("href", "")

        if "icon" in rel:
            icon_url = urljoin(base_url, href)
            icon_host = urlparse(icon_url).hostname

            if icon_host == base_hostname or href.count(".") == 1:
                favicon_value = 1
                break

    features["Favicon"] = favicon_value

    # 12. RequestURL
    resources = []
    for tag_name, attribute in [
        ("img", "src"),
        ("audio", "src"),
        ("embed", "src"),
        ("iframe", "src")
    ]:
        for element in soup.find_all(tag_name, **{attribute: True}):
            resources.append(element.get(attribute))

    if not resources:
        features["RequestURL"] = 0
    else:
        success = 0

        for resource in resources:
            resource_url = urljoin(base_url, resource)
            resource_host = urlparse(resource_url).hostname
            dots = resource.count(".")

            if (
                (resource_host and resource_host == base_hostname)
                or dots == 1
            ):
                success += 1

        percentage = (success / len(resources)) * 100

        if percentage < 22:
            features["RequestURL"] = 1
        elif percentage < 61:
            features["RequestURL"] = 0
        else:
            features["RequestURL"] = -1

    # 13. AnchorURL
    anchors = soup.find_all("a", href=True)

    if not anchors:
        features["AnchorURL"] = -1
    else:
        unsafe = 0

        for anchor in anchors:
            href = anchor.get("href", "")

            if (
                "#" in href
                or "javascript" in href.lower()
                or "mailto" in href.lower()
                or base_hostname not in href
            ):
                unsafe += 1

        percentage = (unsafe / len(anchors)) * 100

        if percentage < 31:
            features["AnchorURL"] = 1
        elif percentage < 67:
            features["AnchorURL"] = 0
        else:
            features["AnchorURL"] = -1

    # 14. ServerFormHandler
    forms = soup.find_all("form", action=True)

    if not forms:
        features["ServerFormHandler"] = 1
    else:
        form_value = 1

        for form in forms:
            action = form.get("action", "")

            if action == "" or action.lower() == "about:blank":
                form_value = -1
                break

            if base_hostname not in action and base_url not in action:
                form_value = 0

        features["ServerFormHandler"] = form_value

    # 15. IframeRedirection
    features["IframeRedirection"] = (
        1 if soup.find("iframe") or soup.find("frame") else -1
    )

    return features
