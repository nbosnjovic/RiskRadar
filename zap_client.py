import os, time, urllib.parse, re
from zapv2 import ZAPv2
from dotenv import load_dotenv; load_dotenv()

# ===== ENV / podešavanja =====
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "changeme")
ZAP_PROXY   = os.getenv("ZAP_PROXY", "http://localhost:8090")

BUSINESS_IMPACT_DEFAULT = int(os.getenv("BUSINESS_IMPACT_DEFAULT", "3"))  # 1..5 (trenutno se ne koristi)

ALLOWED = set(os.getenv("ALLOWED_SCAN_HOSTS", "localhost").split(","))
ALLOW_ANY_ACTIVE_SCAN = os.getenv("ALLOW_ANY_ACTIVE_SCAN", os.getenv("ALLOW_ANY_ACTIVE", "false")).lower() == "true"

# FULL limiti
FULL_SCAN_BUDGET_MIN       = int(os.getenv("FULL_SCAN_BUDGET_MIN", "5"))
FULL_SCAN_RULE_MIN         = int(os.getenv("FULL_SCAN_RULE_MIN", "2"))
FULL_SCAN_THREADS_PER_HOST = int(os.getenv("FULL_SCAN_THREADS_PER_HOST", "6"))

# Triage (grupisanje u izvještaju)
RISK_MIN           = os.getenv("RISK_MIN", "MEDIUM").upper()        # HIGH|MEDIUM|LOW|INFORMATIONAL
CONFIDENCE_MIN     = os.getenv("CONFIDENCE_MIN", "MEDIUM").upper()  # CONFIRMED|HIGH|MEDIUM|LOW|FALSE POSITIVE
MAX_GROUPS         = int(os.getenv("MAX_GROUPS", "40"))
SAMPLES_PER_GROUP  = int(os.getenv("SAMPLES_PER_GROUP", "3"))

QUICK_SPIDER_MAX_DEPTH         = int(os.getenv("QUICK_SPIDER_MAX_DEPTH", "2"))
QUICK_SPIDER_MAX_CHILDREN      = int(os.getenv("QUICK_SPIDER_MAX_CHILDREN", "60"))
QUICK_SPIDER_MAX_DURATION_MIN  = int(os.getenv("QUICK_SPIDER_MAX_DURATION_MIN", "1"))
PSCAN_TIMEOUT_QUICK            = int(os.getenv("PSCAN_TIMEOUT_QUICK", "25"))

FULL_SPIDER_MAX_DEPTH          = int(os.getenv("FULL_SPIDER_MAX_DEPTH", "3"))
FULL_SPIDER_MAX_CHILDREN       = int(os.getenv("FULL_SPIDER_MAX_CHILDREN", "120"))
FULL_SPIDER_MAX_DURATION_MIN   = int(os.getenv("FULL_SPIDER_MAX_DURATION_MIN", "3"))
PSCAN_TIMEOUT_FULL             = int(os.getenv("PSCAN_TIMEOUT_FULL", "60"))

# ===== RR kalkulacija (Likelihood, Impact, Score) =====
PROB_LABELS   = {1:"Very Unlikely", 2:"Unlikely", 3:"Moderate", 4:"Likely", 5:"Very Likely"}
IMPACT_LABELS = {1:"Insignificant", 2:"Minor", 3:"Significant", 4:"Major", 5:"Severe"}

def _bucket(score: int) -> str:
    if 1  <= score <= 4:   return "pri"   # Prihvatljivo
    if 5  <= score <= 9:   return "zad"   # Zadovoljavajuće
    if 10 <= score <= 16:  return "tol"   # Tolerantno
    if 17 <= score <= 25:  return "nep"   # Neprihvatljivo
    return "unk"

BUCKET_LABEL = {
    "pri": "Prihvatljivo",
    "zad": "Zadovoljavajuće",
    "tol": "Tolerantno",
    "nep": "Neprihvatljivo",
    "unk": "N/A",
}

def _risk_val(s: str) -> int:
    return {"HIGH":3, "MEDIUM":2, "LOW":1, "INFORMATIONAL":0}.get((s or "").upper(), 0)

def _conf_val(s: str) -> int:
    return {"CONFIRMED":4, "HIGH":3, "MEDIUM":2, "LOW":1, "FALSE POSITIVE":0}.get((s or "").upper(), 0)

zap = ZAPv2(apikey=ZAP_API_KEY, proxies={"http": ZAP_PROXY, "https": ZAP_PROXY})
STATIC_RX = r".*\.(?:png|jpe?g|gif|svg|ico|css|js|map|woff2?|ttf)(?:\?.*)?$"
CTX_NAME  = "RiskRadarCtx"

def _human_fix(a: dict) -> str:
    pid = str(a.get("pluginId") or a.get("pluginID") or a.get("pluginid") or "")
    name = (a.get("alert") or a.get("name") or "").lower()
    ev   = (a.get("evidence") or "").lower()

    if pid in ("10098",) or "cross-domain" in name or "access-control-allow-origin" in ev:
        return ("CORS: ograniči dozvoljene domene. Umjesto '*' navedi konkretne origene "
                "(npr. https://app.example.com). Ne koristi '*' zajedno sa 'Access-Control-Allow-Credentials: true'.")

    # CSP header not set
    if pid in ("10038",) or ("csp" in name and "header not set" in name):
        return ("Postavi Content-Security-Policy header (npr. "
                "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'). "
                "Počni striktno i širi po potrebi.")

    # CSP directive/fallback
    if pid in ("10063",) or ("csp" in name and "directive" in name):
        return ("U CSP dodaj eksplicitne direktive (script-src, style-src, img-src…). "
                "Ne oslanjaj se na default-src za sve.")

    # X-Content-Type-Options missing
    if pid in ("10021",):
        return "Dodaj header 'X-Content-Type-Options: nosniff' kako bi spriječio MIME sniffing."

    # X-Frame-Options missing
    if pid in ("10020",):
        return "Dodaj 'X-Frame-Options: DENY' ili 'SAMEORIGIN' ili koristi CSP 'frame-ancestors'."

    return a.get("solution") or ""

def _tech_impact_guess(a: dict) -> int:
    """Heuristika uticaja (1–5) po tipu nalaza/CWE."""
    name = (a.get("alert") or a.get("name") or "").lower()
    cwe  = a.get("cweid")

    severe_cwe = {79, 89, 22, 352, 287, 918}  # XSS, SQLi, Path Traversal, CSRF, Auth, SSRF…
    if (cwe and str(cwe).isdigit() and int(cwe) in severe_cwe) or \
       any(s in name for s in ["xss", "sql injection", "path traversal", "csrf", "ssrf"]):
        return 5

    if "content security policy" in name or "csp" in name:        return 3
    if "x-frame-options" in name or "clickjacking" in name:       return 3
    if "x-content-type-options" in name or "nosniff" in name:     return 2
    if "cors" in name or "cross-domain" in name:                  return 3

    risk = (a.get("risk") or a.get("riskdesc") or "").split()[0].upper()
    return {"HIGH":5, "MEDIUM":3, "LOW":2, "INFORMATIONAL":1}.get(risk, 2)

def _likelihood_default(a: dict, instances: int) -> int:
    """1–5: kombinuj rizik/confidence + prevalencu (broj instanci)."""
    risk = (a.get("risk") or a.get("riskdesc") or "").split()[0].upper()
    base = {"HIGH":4, "MEDIUM":3, "LOW":2, "INFORMATIONAL":1}.get(risk, 2)

    conf = (a.get("confidence") or a.get("confidenceStr") or a.get("confidenceString") or "Medium").upper()
    if conf in ("HIGH", "CONFIRMED"): base += 1
    if conf in ("LOW", "FALSE POSITIVE"): base -= 1

    prev_bump = 2 if instances >= 50 else 1 if instances >= 10 else 0
    return max(1, min(5, base + prev_bump))

def _bucket(score: int) -> str:
    if 1 <= score <= 4:   return "pri"
    if 5 <= score <= 9:   return "zad"
    if 10 <= score <= 16: return "tol"
    return "nep"  

BUCKET_LABEL = {
    "pri": "Prihvatljivo",
    "zad": "Zadovoljavajuće",
    "tol": "Tolerantno",
    "nep": "Neprihvatljivo",
}

def apply_rr(groups: list) -> list:
    for g in groups or []:
        seed = {
            "alert":      g.get("alert"),
            "risk":       g.get("risk"),
            "confidence": g.get("confidence") or g.get("confidenceStr") or g.get("confidenceString"),
            "cweid":      g.get("cweid"),
        }

        L = g.get("rr_likelihood") or g.get("likelihood")
        if L is None:
            L = _likelihood_default(seed, int(g.get("instances") or 1))
        try:
            L = int(L)
        except:
            L = 0
        L = max(1, min(5, L))

        I = g.get("rr_impact") or g.get("impact")
        if I is None:
            I = _tech_impact_guess(seed)
        try:
            I = int(I)
        except:
            I = 0
        I = max(1, min(5, I))
        S = max(1, min(25, L * I))
        b = _bucket(S)

        g["rr_likelihood"]       = L
        g["rr_likelihood_label"] = PROB_LABELS.get(L, "")
        g["rr_impact"]           = I
        g["rr_impact_label"]     = IMPACT_LABELS.get(I, "")
        g["rr_score"]            = S
        g["rr_bucket"]           = b
        g["rr_severity"]         = BUCKET_LABEL[b]
    return groups


def _group_alerts(alerts: list) -> list:
    groups = {}
    rmin = _risk_val(RISK_MIN)
    cmin = _conf_val(CONFIDENCE_MIN)

    for a in (alerts or []):
        risk = (a.get("risk") or a.get("riskdesc") or "").split()[0]
        conf = a.get("confidence") or a.get("confidenceStr") or a.get("confidenceString") or "Medium"

        if _risk_val(risk) < rmin or _conf_val(conf) < cmin:
            continue

        pid  = str(a.get("pluginId") or a.get("pluginID") or a.get("pluginid") or "0")
        name = a.get("alert") or a.get("name") or pid
        key  = (pid, name, risk)

        g = groups.setdefault(key, {
            "pluginid": pid,
            "alert": name,
            "risk": risk,
            "solution": a.get("solution"),
            "reference": a.get("reference"),
            "cweid": a.get("cweid"),
            "instances": 0,
            "sample_urls": [],
            "evidence": a.get("evidence"),
            "param": a.get("param"),
            "fix": None,
        })

        g["instances"] += 1
        if not g["fix"]:
         g["fix"] = a.get("solution") or ""


        u = a.get("url")
        if u and len(g["sample_urls"]) < SAMPLES_PER_GROUP:
            g["sample_urls"].append(u)

    grouped = list(groups.values())
    grouped.sort(key=lambda x: (-_risk_val(x["risk"]), -x["instances"], x["alert"]))
    return grouped[:MAX_GROUPS]

def _origin(u: str) -> str:
    p = urllib.parse.urlparse(u)
    port = f":{p.port}" if p.port else ""
    return f"{p.scheme}://{p.hostname}{port}"

def _remap_localhost(u: str) -> str:
    p = urllib.parse.urlparse(u)
    if p.hostname in ("localhost", "127.0.0.1"):
        port = f":{p.port}" if p.port else ""
        p = p._replace(netloc=f"host.docker.internal{port}")
        return urllib.parse.urlunparse(p)
    return u

def _ensure_context(origin: str):
    try:
        if CTX_NAME not in zap.context.context_list:
            zap.context.new_context(CTX_NAME)
        pattern = rf'^{re.escape(origin)}/.*'
        zap.context.include_in_context(CTX_NAME, pattern)
        zap.context.set_context_in_scope(CTX_NAME, True)
    except Exception:
        pass

def _guard_and_tune(target_url: str, enforce_allowlist=True):
    host = urllib.parse.urlparse(target_url).hostname or ""
    if enforce_allowlist and host not in ALLOWED and not ALLOW_ANY_ACTIVE_SCAN:
        raise ValueError(f"Host '{host}' nije na listi ALLOWED_SCAN_HOSTS")

    try: zap.core.exclude_from_proxy(STATIC_RX)
    except: pass
    try: zap.ascan.exclude_from_scan(STATIC_RX)
    except: pass
    try: zap.pscan.set_scan_only_in_scope(False)
    except: pass
    try: zap.pscan.enable_all_scanners()
    except: pass

    origin = _origin(target_url)
    _ensure_context(origin)

    try:
        zap.core.access_url(target_url, followredirects=True)
        zap.core.urlopen(target_url)
        time.sleep(1)
    except Exception:
        pass
    return origin

def _wait_spider(sid):
    while True:
        try: status = int(zap.spider.status(sid))
        except: status = 100
        if status >= 100: break
        time.sleep(1)

def _wait_pscan(timeout_s=90):
    t0 = time.time()
    while True:
        try: left = int(zap.pscan.records_to_scan)
        except: left = 0
        if left <= 0 or time.time() - t0 > timeout_s: break
        time.sleep(1)

def _alerts_for_origin(origin: str):
    arr = zap.core.alerts(start=0, count=100000) or []
    return [a for a in arr if (a.get("url") or "").startswith(origin)]

# ===== QUICK / FULL =====
def quick_scan(target_url: str):
    target_url = _remap_localhost(target_url)
    origin = _guard_and_tune(target_url, enforce_allowlist=False)

    try:
        zap.spider.set_option_max_depth(QUICK_SPIDER_MAX_DEPTH)
        zap.spider.set_option_max_children(QUICK_SPIDER_MAX_CHILDREN)
        zap.spider.set_option_max_duration(QUICK_SPIDER_MAX_DURATION_MIN)
    except: pass

    sid = zap.spider.scan(target_url)
    _wait_spider(sid)
    _wait_pscan(timeout_s=PSCAN_TIMEOUT_QUICK)

    alerts = _alerts_for_origin(origin)
    groups = _group_alerts(alerts)
    return apply_rr(_group_alerts(alerts))  

def full_scan(target_url: str, budget_minutes=None, per_rule_minutes=None, threads_per_host=None):
    target_url = _remap_localhost(target_url)
    origin = _guard_and_tune(target_url, enforce_allowlist=not ALLOW_ANY_ACTIVE_SCAN)

    try:
        zap.spider.set_option_max_depth(FULL_SPIDER_MAX_DEPTH)
        zap.spider.set_option_max_children(FULL_SPIDER_MAX_CHILDREN)
        zap.spider.set_option_max_duration(FULL_SPIDER_MAX_DURATION_MIN)
    except: pass

    budget  = budget_minutes or FULL_SCAN_BUDGET_MIN
    perrule = per_rule_minutes or FULL_SCAN_RULE_MIN
    threads = threads_per_host or FULL_SCAN_THREADS_PER_HOST

    sid = zap.spider.scan(target_url)
    _wait_spider(sid)

    try: zap.ascan.set_option_thread_per_host(threads)
    except: pass
    try: zap.ascan.set_option_max_rule_duration_in_mins(perrule)
    except: pass
    try: zap.ascan.set_option_max_scan_duration_in_mins(budget)
    except: pass

    policy = "RiskRadarFast"
    try: zap.ascan.remove_scan_policy(policy)
    except: pass
    try:
        zap.ascan.add_scan_policy(policy, alertthreshold="Medium", attackstrength="Low")
        zap.ascan.enable_all_scanners(policy)
    except:
        policy = None

    scanid = zap.ascan.scan(target_url, scanpolicyname=policy) if policy else zap.ascan.scan(target_url)

    t0 = time.time()
    while True:
        try: status = int(zap.ascan.status(scanid))
        except: status = 100
        if status >= 100: break
        if time.time() - t0 > budget*60 + 10:
            try: zap.ascan.stop(scanid)
            except: pass
            break
        time.sleep(2)

    _wait_pscan(timeout_s=PSCAN_TIMEOUT_FULL)

    alerts = _alerts_for_origin(origin)
    groups = _group_alerts(alerts)
    return apply_rr(_group_alerts(alerts))  
