import sqlite3, json, hashlib, urllib.parse, time
from contextlib import contextmanager
from pathlib import Path


BASE = Path(__file__).resolve().parent
DB_PATH = BASE / "instance" / "riskradar.db"
SQL_PATH = BASE / "db.sql"

@contextmanager
def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    try:
        yield con
    finally:
        con.commit()
        con.close()

def init_db():
    with db() as con:
        con.executescript(open("db.sql","r",encoding="utf-8").read())

def rr_bucket(score:int) -> str:
    if score is None: return "unk"
    if score <= 4: return "pri"
    if score <= 9: return "zad"
    if score <= 16: return "tol"
    return "nep"

def hostname_of(url:str) -> str:
    try:
        return urllib.parse.urlparse(url).hostname or ""
    except:
        return ""

def make_signature(alert:str, cwe_id, param, sample_urls:list) -> str:
    host = hostname_of(sample_urls[0]) if sample_urls else ""
    payload = f"{alert}|{cwe_id or ''}|{param or ''}|{host}"
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()

def upsert_system(name, url, note=""):
    with db() as con:
        cur = con.execute("SELECT id FROM systems WHERE url=?", (url,))
        row = cur.fetchone()
        if row: return row["id"]
        cur = con.execute("INSERT INTO systems(name,url,note) VALUES(?,?,?)",
                          (name or url, url, note))
        return cur.lastrowid

def insert_scan_run(system_id, mode, duration_s, h,m,l, max_rr, max_bucket, pdf_path=None):
    with db() as con:
        cur = con.execute("""INSERT INTO scan_runs
            (system_id, mode, duration_s, high_count, med_count, low_count, max_rr, max_rr_bucket, pdf_path)
            VALUES (?,?,?,?,?,?,?,?,?)""",
            (system_id, mode, duration_s, h, m, l, max_rr, max_bucket, pdf_path))
        return cur.lastrowid

def insert_finding(scan_id, g):
    with db() as con:
        sig = make_signature(g["alert"], g.get("cweid"), g.get("param"), g.get("sample_urls") or [])
        con.execute("""INSERT INTO findings
          (scan_id, alert, cwe_id, risk, rr_likelihood, rr_impact, rr_score, rr_bucket,
           instances, sample_urls, param, evidence, fix, reference, signature)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
          (scan_id, g["alert"], g.get("cweid"), (g["risk"] or "LOW").upper(),
           int(g.get("rr_likelihood") or 0), int(g.get("rr_impact") or 0),
           int(g.get("rr_score") or (int(g.get("rr_likelihood") or 0)*int(g.get("rr_impact") or 0))),
           g.get("rr_bucket") or rr_bucket(int(g.get("rr_score") or 0)),
           int(g.get("instances") or 0),
           json.dumps(g.get("sample_urls") or []),
           g.get("param"), g.get("evidence"), g.get("fix") or g.get("solution"),
           g.get("reference"), sig))

def status_map_for_system(system_id:int) -> dict:
    with db() as con:
        cur = con.execute("SELECT signature, status, note FROM finding_status WHERE system_id=?", (system_id,))
        return {r["signature"]: (r["status"], r["note"]) for r in cur.fetchall()}

def set_status(system_id:int, signature:str, status:str, note:str=""):
    with db() as con:
        con.execute("""INSERT INTO finding_status(system_id, signature, status, note)
                       VALUES(?,?,?,?)
                       ON CONFLICT(system_id, signature)
                       DO UPDATE SET status=excluded.status, note=excluded.note, updated_at=CURRENT_TIMESTAMP""",
                    (system_id, signature, status, note))

def last_two_scans(system_id:int):
    with db() as con:
        cur = con.execute("""SELECT * FROM scan_runs WHERE system_id=?
                             ORDER BY datetime(started_at) DESC LIMIT 2""", (system_id,))
        return cur.fetchall()

def signatures_for_scan(scan_id:int) -> set:
    with db() as con:
        cur = con.execute("SELECT signature FROM findings WHERE scan_id=?", (scan_id,))
        return {r["signature"] for r in cur.fetchall()}
