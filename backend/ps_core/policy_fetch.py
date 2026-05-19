import hashlib
from urllib.parse import urljoin
import requests
from bs4 import BeautifulSoup

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 PrivacyShield/1.0"

def discover_policy_urls(base_url, html=""):
    """
    Find BOTH privacy policy and terms URLs from html.
    Returns: (policy_url, terms_url)
    """
    policy_url = None
    terms_url = None

    privacy_keywords = ["privacy", "privacy policy", "privacy notice", "data policy", "privacy-policy"]
    terms_keywords = ["terms", "terms of service", "terms-of-service", "tos", "legal"]

    if html:
        soup = BeautifulSoup(html, 'html.parser')
        for a in soup.find_all('a', href=True):
            text = a.get_text(separator=' ', strip=True).lower()
            href = a['href']
            
            # Check for privacy policy
            if not policy_url and any(kw in text for kw in privacy_keywords):
                policy_url = urljoin(base_url, href)
            
            # Check for terms
            if not terms_url and any(kw in text for kw in terms_keywords):
                terms_url = urljoin(base_url, href)

    # Some basic fallbacks if we didn't find them in HTML
    if not policy_url:
        policy_url = urljoin(base_url, '/privacy')
    if not terms_url:
        terms_url = urljoin(base_url, '/terms')

    return policy_url, terms_url

def fetch_url(url):
    """
    Fetch HTML with a generic User-Agent.
    """
    headers = {"User-Agent": USER_AGENT}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        return resp.text
    except requests.RequestException:
        return ""

def html_to_text(html):
    """
    Remove scripts, styles, nav, header, footer and extract readable text.
    Collapse whitespace.
    """
    if not html:
        return ""

    soup = BeautifulSoup(html, 'html.parser')
    for element in soup(["script", "style", "noscript", "nav", "header", "footer"]):
        element.extract()

    text = soup.get_text(separator=' ', strip=True)
    # Collapse multiple whitespaces
    text = ' '.join(text.split())
    return text

def sha256_text(text):
    """
    Compute SHA-256 hash of text.
    """
    if not text:
        return ""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()
