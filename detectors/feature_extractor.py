import re
import tldextract
from urllib.parse import urlparse
from difflib import SequenceMatcher
from datetime import datetime
import whois 

TOP_DOMAINS = ["paypal.com", "bankofamerica.com", "wellsfargo.com", "chase.com", "citibank.com", "google.com", "amazon.com", "walmart.com", "microsoft.com"]

def similarity(url):
    return max(SequenceMatcher(None, url, domain).ratio() for domain in TOP_DOMAINS)

def extract_domain_age(url):
    try:
        w = whois.whois(url)
        if isinstance(w.creation_date, list):
            creation_date = w.creation_date[0]
        else:
            creation_date = w.creation_date
        if creation_date is None:
            return -1
        age = (datetime.now() - creation_date).days
        return age
    except: 
        return -1



def shannon_entropy(s):
    import math
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum([p * math.log(p, 2) for p in prob])

def extract_domain(url):
    exd = tldextract.extract(url)
    phishing_keywords = ['login', 'secure', 'account', 'update', 'verify', 'bank', 'webscr', 'signin']
    suspicious_tlds = ['xyz', 'top', 'club', 'info', 'online']
    bank_keywords = ['bank', 'secure', 'account', 'verify']

    features = {
        "url_length": len(url),
        "num_digits": len(re.findall(r'\d', url)),
        "num_special_chars": len(re.findall(r'[^a-zA-Z0-9]', url)),
        "domain_entropy": shannon_entropy(exd.domain),
        "url_entropy": shannon_entropy(url),
        "num_subdomains": len(exd.subdomain.split('.')) if exd.subdomain else 0,
        "domain_length": len(exd.domain),
        "path_length": len(url.split('/', 3)[-1]) if '/' in url[8:] else 0,
        "has_https": int(url.lower().startswith('https://')),
        "has_phishing_keyword": int(any(kw in url.lower() for kw in phishing_keywords)),
        "suspicious_tld": int(exd.suffix in suspicious_tlds),
        "similarity_to_known_sites": similarity(url), 
        "domain_age": extract_domain_age(url), 
        "has_bank_keyword": int(any(word in url.lower() for word in bank_keywords)),
    }
    return features