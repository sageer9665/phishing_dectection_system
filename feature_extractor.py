
import ipaddress
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup


# Common URL-shortening services
SHORTENER_DOMAINS = {      
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "tiny.cc",
    "v.gd",
    "lnkd.in"
}


def same_site(host1, host2):
    # Treat a domain and its subdomains as the same website
    if not host1 or not host2:
        return False

    host1 = host1.lower().strip(".")
    host2 = host2.lower().strip(".")

    return (
        host1 == host2
        or host1.endswith("." + host2)
        or host2.endswith("." + host1)
    )


def normalize_url(url):
    # Add HTTPS when the user enters a URL without a scheme
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


def extract_features(url):
    # Normalize the URL
    url = normalize_url(url)

    # Break the URL into separate components
    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    hostname_lower = hostname.lower()
    scheme = parsed.scheme.lower()

    features = {}

    # ==========================================
    # 1. UsingIP
    # ==========================================

    try:
        ipaddress.ip_address(hostname)
        features["UsingIP"] = -1
    except ValueError:
        features["UsingIP"] = 1

    # ==========================================
    # 2. LongURL
    # ==========================================

    if len(url) < 54:
        features["LongURL"] = 1
    elif len(url) <= 75:
        features["LongURL"] = 0
    else:
        features["LongURL"] = -1

    # ==========================================
    # 3. ShortURL
    # ==========================================

    if hostname_lower in SHORTENER_DOMAINS:
        features["ShortURL"] = -1
    else:
        features["ShortURL"] = 1

    # ==========================================
    # 4. Symbol@
    # ==========================================

    features["Symbol@"] = -1 if "@" in url else 1

    # ==========================================
    # 5. Redirecting//
    # ==========================================

    # Ignore the "//" belonging to http:// or https://
    features["Redirecting//"] = -1 if url.find("//", 8) != -1 else 1

    # ==========================================
    # 6. PrefixSuffix-
    # ==========================================

    features["PrefixSuffix-"] = -1 if "-" in hostname else 1

    # ==========================================
    # 7. SubDomains
    # ==========================================

    # Count the components in the hostname
    hostname_parts = hostname.split(".")

    if len(hostname_parts) <= 2:
        features["SubDomains"] = 1
    elif len(hostname_parts) == 3:
        features["SubDomains"] = 0
    else:
        features["SubDomains"] = -1

    # ==========================================
    # 8. HTTPS
    # ==========================================

    features["HTTPS"] = 1 if scheme == "https" else -1

    # ==========================================
    # 9. NonStdPort
    # ==========================================

    try:
        port = parsed.port

        if port is None or port in (80, 443):
            features["NonStdPort"] = 1
        else:
            features["NonStdPort"] = -1

    except ValueError:
        features["NonStdPort"] = -1

    # ==========================================
    # 10. HTTPSDomainURL
    # ==========================================

    # Check whether "https" appears suspiciously inside the hostname
    features["HTTPSDomainURL"] = (
        -1 if "https" in hostname_lower else 1
    )

    # ==========================================
    # Retrieve the webpage
    # ==========================================

    response = None
    soup = None

    try:
        response = requests.get(
            url,
            timeout=5,
            headers={
                "User-Agent": "Mozilla/5.0"
            }
        )

        soup = BeautifulSoup(
            response.text,
            "html.parser"
        )

    except requests.RequestException:
        pass

    # ==========================================
    # 11. Favicon
    # ==========================================

    if soup is None:
        features["Favicon"] = -1
    else:
        favicon_found = False

        for link in soup.find_all("link", href=True):
            rel = link.get("rel", [])

            if any("icon" in str(item).lower() for item in rel):
                favicon_url = urljoin(url, link["href"])
                favicon_host = urlparse(favicon_url).hostname

                if same_site(favicon_host, hostname):
                    favicon_found = True
                    break

        features["Favicon"] = 1 if favicon_found else -1

    # ==========================================
    # 12. RequestURL
    # ==========================================

    if soup is None:
        features["RequestURL"] = -1
    else:
        resources = []

        for tag_name, attribute in [
            ("img", "src"),
            ("audio", "src"),
            ("embed", "src"),
            ("iframe", "src")
        ]:
            for element in soup.find_all(tag_name):
                value = element.get(attribute)

                if value:
                    resources.append(value)

        if not resources:
            features["RequestURL"] = 1
        else:
            external_count = 0

            for resource in resources:
                resource_url = urljoin(url, resource)
                resource_host = urlparse(resource_url).hostname

                if resource_host and not same_site(resource_host, hostname):
                    external_count += 1

            external_percentage = (
                external_count / len(resources)
            ) * 100

            if external_percentage < 22:
                features["RequestURL"] = 1
            elif external_percentage <= 61:
                features["RequestURL"] = 0
            else:
                features["RequestURL"] = -1

    # ==========================================
    # 13. AnchorURL
    # ==========================================

    if soup is None:
        features["AnchorURL"] = -1
    else:
        anchors = soup.find_all("a", href=True)

        if not anchors:
            features["AnchorURL"] = 1
        else:
            unsafe_count = 0

            for anchor in anchors:
                href = anchor.get("href", "").strip().lower()

                if (
                    href.startswith("javascript:")
                    or href.startswith("mailto:")
                    or href == "#"
                ):
                    unsafe_count += 1
                    continue

                anchor_url = urljoin(url, href)
                anchor_host = urlparse(anchor_url).hostname

                if anchor_host and not same_site(anchor_host, hostname):
                    unsafe_count += 1

            unsafe_percentage = (
                unsafe_count / len(anchors)
            ) * 100

            if unsafe_percentage < 31:
                features["AnchorURL"] = 1
            elif unsafe_percentage <= 67:
                features["AnchorURL"] = 0
            else:
                features["AnchorURL"] = -1

    # ==========================================
    # 14. ServerFormHandler
    # ==========================================

    if soup is None:
        features["ServerFormHandler"] = -1
    else:
        forms = soup.find_all("form")

        if not forms:
            features["ServerFormHandler"] = 1
        else:
            form_result = 1

            for form in forms:
                action = form.get("action", "").strip()

                if action == "" or action.lower() == "about:blank":
                    form_result = -1
                    break

                action_url = urljoin(url, action)
                action_host = urlparse(action_url).hostname

                if action_host and not same_site(action_host, hostname):
                    form_result = 0

            features["ServerFormHandler"] = form_result

    # ==========================================
    # 15. IframeRedirection
    # ==========================================

    if soup is None:
        features["IframeRedirection"] = -1
    else:
        iframe = soup.find("iframe")
        frame = soup.find("frame")

        features["IframeRedirection"] = (
            -1 if iframe is None and frame is None else 1
        )

    # ==========================================
    # 16. WebsiteForwarding
    # ==========================================

    if response is None:
        features["WebsiteForwarding"] = -1
    else:
        # Check whether the request ended on a different URL
        if response.url.rstrip("/") == url.rstrip("/"):
            features["WebsiteForwarding"] = 1
        else:
            features["WebsiteForwarding"] = -1

    # ==========================================
    # 17. InfoEmail
    # ==========================================

    if soup is None:
        features["InfoEmail"] = -1
    else:
        page_text = soup.get_text(" ", strip=True).lower()

        email_links = soup.find_all(
            "a",
            href=True
        )

        has_mailto = any(
            link.get("href", "").lower().startswith("mailto:")
            for link in email_links
        )

        has_email_text = "email" in page_text

        features["InfoEmail"] = (
            1 if has_mailto or has_email_text else -1
        )

    # ==========================================
    # 18. LinksInScriptTags
    # ==========================================

    if soup is None:
        features["LinksInScriptTags"] = -1
    else:
        scripts = soup.find_all("script")

        if not scripts:
            features["LinksInScriptTags"] = 1
        else:
            external_script_count = 0

            for script in scripts:
                script_src = script.get("src")

                if script_src:
                    script_url = urljoin(url, script_src)
                    script_host = urlparse(script_url).hostname

                    if script_host and not same_site(script_host, hostname):
                        external_script_count += 1

            if external_script_count == 0:
                features["LinksInScriptTags"] = 1
            elif external_script_count < len(scripts):
                features["LinksInScriptTags"] = 0
            else:
                features["LinksInScriptTags"] = -1

    return features