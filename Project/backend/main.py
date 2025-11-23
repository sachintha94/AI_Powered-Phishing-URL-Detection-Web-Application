# main.py
from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import joblib
import numpy as np
import pandas as pd
import re
import math
from urllib.parse import urlsplit, urljoin
import tldextract
from datetime import datetime, timezone

# ---------------- Optional dependencies (handled gracefully) ----------------
try:
    import httpx
except Exception:
    httpx = None

try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None

try:
    import whois
except Exception:
    whois = None

try:
    import dns.resolver
except Exception:
    dns = None

# ---------------- App & CORS ----------------
app = FastAPI(title="Phishing URL Detector API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- Load model ----------------
bundle = joblib.load("model.pkl")
model = bundle["model"] if isinstance(bundle, dict) and "model" in bundle else bundle

# ---------------- EXACT feature order (87) ----------------
FEATURE_ORDER = [
    "length_url","length_hostname","ip","nb_dots","nb_hyphens","nb_at","nb_qm","nb_and","nb_or","nb_eq",
    "nb_underscore","nb_tilde","nb_percent","nb_slash","nb_star","nb_colon","nb_comma","nb_semicolumn",
    "nb_dollar","nb_space","nb_www","nb_com","nb_dslash","http_in_path","https_token","ratio_digits_url",
    "ratio_digits_host","punycode","port","tld_in_path","tld_in_subdomain","abnormal_subdomain",
    "nb_subdomains","prefix_suffix","random_domain","shortening_service","path_extension",
    "nb_redirection","nb_external_redirection","length_words_raw","char_repeat","shortest_words_raw",
    "shortest_word_host","shortest_word_path","longest_words_raw","longest_word_host","longest_word_path",
    "avg_words_raw","avg_word_host","avg_word_path","phish_hints","domain_in_brand","brand_in_subdomain",
    "brand_in_path","suspecious_tld","statistical_report","nb_hyperlinks","ratio_intHyperlinks",
    "ratio_extHyperlinks","ratio_nullHyperlinks","nb_extCSS","ratio_intRedirection","ratio_extRedirection",
    "ratio_intErrors","ratio_extErrors","login_form","external_favicon","links_in_tags","submit_email",
    "ratio_intMedia","ratio_extMedia","sfh","iframe","popup_window","safe_anchor","onmouseover","right_clic",
    "empty_title","domain_in_title","domain_with_copyright","whois_registered_domain",
    "domain_registration_length","domain_age","web_traffic","dns_record","google_index","page_rank"
]

# ---------------- Heuristics used by some features ----------------
SHORTENERS = {
    "bit.ly","goo.gl","t.co","ow.ly","tinyurl.com","is.gd","buff.ly","adf.ly","s.id","rebrand.ly","cutt.ly",
    "shorte.st","soo.gd","bit.do","lc.chat","1url.com","u.to","zws.im"
}
SUSPICIOUS_TLDS = {"zip","xyz","top","country","kim","cricket","science","work","gq","ml","cf"}
PHISH_KEYWORDS = {
    "login","verify","update","secure","account","bank","confirm","webscr","signin",
    "ebayisapi","wp-admin","paypal","password","billing"
}

# ---------------- Request model ----------------
class UrlIn(BaseModel):
    url: str

# ---------------- JSON-safe conversion ----------------
def to_py(o):
    """Recursively convert numpy/scalar types to plain Python for clean JSON."""
    if isinstance(o, (np.generic,)):
        return o.item()
    if isinstance(o, np.ndarray):
        return [to_py(v) for v in o.tolist()]
    if isinstance(o, (list, tuple)):
        return [to_py(v) for v in o]
    if isinstance(o, dict):
        return {str(k): to_py(v) for k, v in o.items()}
    return o

# ---------------- Helpers for features ----------------
def safe_len(s):
    return len(s) if s else 0

def count_token(s: str, token: str) -> int:
    return s.count(token)

def ratio_digits(s: str) -> float:
    if not s:
        return 0.0
    digits = sum(c.isdigit() for c in s)
    return digits / len(s)

def is_ip(host: str) -> int:
    if not host:
        return 0
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return 1
    return 0

def entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    cnt = Counter(s)
    total = len(s)
    return -sum((c/total)*math.log2(c/total) for c in cnt.values())

def looks_random_domain(domain: str) -> int:
    if not domain:
        return 0
    ent = entropy(domain.lower())
    vowels = sum(ch in "aeiou" for ch in domain.lower())
    return 1 if (ent > 3.5 and vowels/len(domain) < 0.25) else 0

def https_token_flag(u: str) -> int:
    u_low = u.lower()
    without_scheme = u_low.replace("https://", "").replace("http://", "")
    return 1 if "https" in without_scheme else 0

def get_words(s: str):
    w = re.split(r"[^A-Za-z0-9]+", s or "")
    return [x for x in w if x]

def first_path_ext(path: str) -> str:
    if not path:
        return ""
    seg = path.strip("/").split("/")[-1]
    if "." in seg:
        return seg.rsplit(".", 1)[-1][:10].lower()
    return ""

def is_shortener(host: str) -> int:
    return 1 if host.lower() in SHORTENERS else 0

def suspicious_tld_flag(ext) -> int:
    tld = (ext.suffix or "").lower()
    return 1 if tld in SUSPICIOUS_TLDS else 0

def abnormal_subdomain_flag(ext) -> int:
    subs = [p for p in (ext.subdomain or "").split(".") if p]
    if not subs:
        return 0
    long_parts = sum(1 for s in subs if len(s) >= 14)
    return 1 if (len(subs) >= 3 or long_parts >= 1) else 0

def same_site(url_a: str, url_b: str) -> bool:
    ea = tldextract.extract(url_a)
    eb = tldextract.extract(url_b)
    da = ".".join([x for x in [ea.domain, ea.suffix] if x]).lower()
    db = ".".join([x for x in [eb.domain, eb.suffix] if x]).lower()
    return bool(da and db and da == db)

def fetch_html(url: str, timeout=6.0):
    if httpx is None:
        return url, None, "", 0, 0
    headers = {"User-Agent": "Mozilla/5.0 (Phish-Detector/1.0)"}
    redirs, ext_redirs, final_url, status, html = 0, 0, url, None, ""
    try:
        with httpx.Client(follow_redirects=True, headers=headers, timeout=timeout, http2=True) as client:
            r = client.get(url)
            status = r.status_code
            hist = r.history or []
            redirs = len(hist)
            for h in hist:
                loc = h.headers.get("location")
                if loc and not same_site(url, urljoin(url, loc)):
                    ext_redirs += 1
            final_url = str(r.url)
            ctype = r.headers.get("content-type","").lower()
            html = r.text if ctype.startswith(("text/html","application/xhtml")) else ""
    except Exception:
        pass
    return final_url, status, html, redirs, ext_redirs

def parse_html_features(base_url: str, html: str):
    feats = {
        "nb_hyperlinks": -1, "ratio_intHyperlinks": -1, "ratio_extHyperlinks": -1, "ratio_nullHyperlinks": -1,
        "nb_extCSS": -1, "ratio_intRedirection": -1, "ratio_extRedirection": -1,
        "ratio_intErrors": -1, "ratio_extErrors": -1, "login_form": 0, "external_favicon": 0,
        "links_in_tags": -1, "submit_email": 0, "ratio_intMedia": -1, "ratio_extMedia": -1,
        "sfh": 0, "iframe": 0, "popup_window": 0, "safe_anchor": 0, "onmouseover": 0, "right_clic": 0,
        "empty_title": 0, "domain_in_title": 0, "domain_with_copyright": 0
    }
    if not html or BeautifulSoup is None:
        return feats

    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")

    # anchors
    anchors = soup.find_all("a")
    tot = len(anchors); n_null = n_int = n_ext = 0
    for a in anchors:
        href = (a.get("href") or "").strip()
        if not href or href in {"#", "javascript:void(0)", "javascript:;", "/#"}:
            n_null += 1; continue
        absu = urljoin(base_url, href)
        if same_site(base_url, absu): n_int += 1
        else: n_ext += 1
    ratio = lambda p,w: (p/w) if w>0 else 0.0
    feats["nb_hyperlinks"] = tot
    feats["ratio_intHyperlinks"] = ratio(n_int, tot)
    feats["ratio_extHyperlinks"] = ratio(n_ext, tot)
    feats["ratio_nullHyperlinks"] = ratio(n_null, tot)

    # CSS
    css_links = [l for l in soup.find_all("link") if (l.get("rel") and "stylesheet" in [x.lower() for x in (l.get("rel") or [])])]
    feats["nb_extCSS"] = sum(0 if same_site(base_url, urljoin(base_url, (l.get("href") or ""))) else 1 for l in css_links)

    # forms (SFH + login)
    forms = soup.find_all("form")
    sfh_flag = 0; login_flag = 0
    for f in forms:
        action = (f.get("action") or "").strip()
        if not action:
            sfh_flag = 1
        else:
            if not same_site(base_url, urljoin(base_url, action)):
                sfh_flag = 1
        if f.find("input", {"type":"password"}): login_flag = 1
    feats["sfh"] = sfh_flag
    feats["login_form"] = login_flag

    # favicon external
    fav = soup.find("link", rel=lambda v: v and "icon" in [x.lower() for x in (v if isinstance(v, list) else [v])])
    if fav and fav.get("href"):
        fav_abs = urljoin(base_url, fav.get("href"))
        feats["external_favicon"] = 0 if same_site(base_url, fav_abs) else 1

    # links in tags
    feats["links_in_tags"] = sum(1 for tag in soup.find_all(["script","meta","link"]) if (tag.get("href") or tag.get("src")))

    # submit email
    feats["submit_email"] = 1 if ("mailto:" in html.lower()) else 0

    # media
    media = []
    for t in ["img","video","audio","source"]:
        media.extend(soup.find_all(t))
    tm = len(media); im = em = 0
    for m in media:
        src = (m.get("src") or "").strip()
        if not src:
            continue
        abs_src = urljoin(base_url, src)
        if same_site(base_url, abs_src): im += 1
        else: em += 1
    feats["ratio_intMedia"] = ratio(im, tm)
    feats["ratio_extMedia"] = ratio(em, tm)

    # iframe / popups / anchors
    feats["iframe"] = 1 if soup.find("iframe") else 0
    feats["popup_window"] = 1 if ("window.open(" in html.lower()) else 0
    feats["safe_anchor"] = ratio(sum(1 for a in anchors if (a.get("href") or "").startswith("#")), tot)

    # js tricks
    low_html = html.lower()
    feats["onmouseover"] = 1 if "onmouseover" in low_html else 0
    feats["right_clic"] = 1 if ("oncontextmenu" in low_html or "event.button==2" in low_html) else 0

    # title signals
    title_tag = soup.find("title")
    title_text = (title_tag.get_text(strip=True) if title_tag else "")
    feats["empty_title"] = 1 if not title_text else 0
    e = tldextract.extract(base_url)
    registrable = ".".join([x for x in [e.domain, e.suffix] if x]).lower()
    try:
        page_text_lower = soup.get_text(" ", strip=True).lower()
    except Exception:
        page_text_lower = ""

    feats["domain_in_title"] = 1 if (title_text and registrable and registrable in title_text.lower()) else 0
    feats["domain_with_copyright"] = 1 if (page_text_lower and registrable and (("©" in page_text_lower or "(c)" in page_text_lower) and registrable in page_text_lower)) else 0

    return feats

def whois_dns_features(url: str):
    feats = {
        "whois_registered_domain": -1,
        "domain_registration_length": -1,
        "domain_age": -1,
        "web_traffic": -1,
        "dns_record": -1,
        "google_index": -1,
        "page_rank": -1
    }
    try:
        ext = tldextract.extract(url)
        domain = ".".join([x for x in [ext.domain, ext.suffix] if x])
        if not domain:
            return feats

        # WHOIS
        if whois is not None:
            try:
                w = whois.whois(domain)
                if w:
                    feats["whois_registered_domain"] = 1
                    created = w.creation_date
                    expires = w.expiration_date
                    if isinstance(created, list):
                        created = created[0]
                    if isinstance(expires, list):
                        expires = expires[0]
                    now = datetime.now(timezone.utc)
                    if created:
                        created = created if getattr(created, 'tzinfo', None) else created.replace(tzinfo=timezone.utc)
                        feats["domain_age"] = max((now - created).days, 0)
                    if created and expires:
                        expires = expires if getattr(expires, 'tzinfo', None) else expires.replace(tzinfo=timezone.utc)
                        feats["domain_registration_length"] = max((expires - created).days, 0)
            except Exception:
                feats["whois_registered_domain"] = 0
        else:
            feats["whois_registered_domain"] = 0

        # DNS
        if dns is not None:
            try:
                answers = dns.resolver.resolve(domain, 'A')
                feats["dns_record"] = 1 if answers else 0
            except Exception:
                feats["dns_record"] = 0
        else:
            feats["dns_record"] = 0

    except Exception:
        pass
    return feats

# ---------------- Full feature extractor ----------------
def extract_all_features(url: str):
    parsed = urlsplit(url)
    full = url
    host = parsed.netloc or ""
    path = parsed.path or ""
    ext = tldextract.extract(url)

    hostname = host.split(":")[0]
    port_present = 1 if (":" in host and host.split(":")[-1].isdigit()) else 0

    features = {}

    # lexical / structural
    features["length_url"] = safe_len(full)
    features["length_hostname"] = safe_len(hostname)
    features["ip"] = is_ip(hostname)

    tokens = {
        "nb_dots": ".","nb_hyphens": "-","nb_at": "@","nb_qm": "?","nb_and": "&","nb_or": "|",
        "nb_eq": "=","nb_underscore": "_","nb_tilde": "~","nb_percent": "%","nb_slash": "/","nb_star":"*",
        "nb_colon": ":", "nb_comma": ",","nb_semicolumn": ";","nb_dollar":"$","nb_space":" "
    }
    for k, sym in tokens.items():
        features[k] = count_token(full, sym)

    features["nb_www"] = full.lower().count("www")
    features["nb_com"] = full.lower().count(".com")
    features["nb_dslash"] = full.count("//") - (1 if full.startswith(("http://","https://")) else 0)
    features["http_in_path"] = 1 if "http" in path.lower() else 0
    features["https_token"] = https_token_flag(full)
    features["ratio_digits_url"] = ratio_digits(full)
    features["ratio_digits_host"] = ratio_digits(hostname)
    features["punycode"] = 1 if hostname.lower().startswith("xn--") else 0
    features["port"] = port_present

    tld_pattern = (ext.suffix or "").lower()
    features["tld_in_path"] = 1 if (tld_pattern and tld_pattern in path.lower()) else 0
    features["tld_in_subdomain"] = 1 if (tld_pattern and tld_pattern in (ext.subdomain or "").lower()) else 0

    subs = [p for p in (ext.subdomain or "").split(".") if p]
    features["abnormal_subdomain"] = abnormal_subdomain_flag(ext)
    features["nb_subdomains"] = len(subs)
    features["prefix_suffix"] = 1 if "-" in ext.domain else 0
    features["random_domain"] = looks_random_domain(ext.domain or "")
    features["shortening_service"] = is_shortener(hostname.lower())

    pe = first_path_ext(path)
    features["path_extension"] = 0 if not pe else 1

    # fetch page + HTML features + redirections
    final_url, status, html, redirs, ext_redirs = fetch_html(full)
    features["nb_redirection"] = redirs
    features["nb_external_redirection"] = ext_redirs
    features.update(parse_html_features(final_url, html))

    # word stats
    def stats_words(words):
        if not words:
            return dict(shortest=0, longest=0, avg=0, length_total=0)
        lengths = [len(w) for w in words]
        return dict(shortest=min(lengths), longest=max(lengths), avg=sum(lengths)/len(lengths), length_total=sum(lengths))

    words_raw = get_words(full)
    words_host = get_words(hostname)
    words_path = get_words(path)
    wr, wh, wp = stats_words(words_raw), stats_words(words_host), stats_words(words_path)

    features["length_words_raw"] = wr["length_total"]
    features["char_repeat"] = 1 if re.search(r"(.)\1\1", full) else 0
    features["shortest_words_raw"] = wr["shortest"]
    features["shortest_word_host"] = wh["shortest"]
    features["shortest_word_path"] = wp["shortest"]
    features["longest_words_raw"] = wr["longest"]
    features["longest_word_host"] = wh["longest"]
    features["longest_word_path"] = wp["longest"]
    features["avg_words_raw"] = wr["avg"]
    features["avg_word_host"] = wh["avg"]
    features["avg_word_path"] = wp["avg"]

    # keyword hints from URL
    low_full = full.lower()
    features["phish_hints"] = sum(1 for k in PHISH_KEYWORDS if k in low_full)

    # brand signals (kept 0 unless you add a brand dictionary)
    features["domain_in_brand"] = 0
    features["brand_in_subdomain"] = 0
    features["brand_in_path"] = 0

    features["suspecious_tld"] = suspicious_tld_flag(ext)
    features["statistical_report"] = 0  # keep 0 unless you add an intel feed

    # WHOIS + DNS
    features.update(whois_dns_features(full))

    # Fill any missing features with -1 to keep shape consistent
    for f in FEATURE_ORDER:
        if f not in features:
            features[f] = -1.0

    return features

# ---------------- Endpoints ----------------
@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/predict-url")
def predict_url(payload: UrlIn):
    url = payload.url.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        return {"detail": "URL must start with http:// or https://"}

    feats_dict = extract_all_features(url)  # 87-feature dict (by name)
    X = pd.DataFrame([[feats_dict[f] for f in FEATURE_ORDER]], columns=FEATURE_ORDER)

    # Your training used 0=phishing, 1=legitimate
    raw_pred = model.predict(X)[0]
    class_id = int(raw_pred)  # ensure pure Python int
    label = "Phishing" if class_id == 1 else "Legitimate"

    # return only the result (plus optional echo of class)
    response = {
        "label": label,
        "class_id": class_id  # 0 => phishing, 1 => legitimate
    }
    return to_py(response)
