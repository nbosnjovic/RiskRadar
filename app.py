import os, time, io
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session, make_response
from models import db 
from zap_client import quick_scan, full_scan, apply_rr
import pdfkit
import db as sdb 
from refs import remediation_refs
import csv
from flask import make_response
import re
from dotenv import load_dotenv
load_dotenv()



SESSION_PDF_TTL = 300

# ---- PDF (wkhtmltopdf) konfiguracija ----
WKHTMLTOPDF = os.getenv(
    "WKHTMLTOPDF",
    r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe" if os.name == "nt" else "/usr/bin/wkhtmltopdf"
)
PDFKIT_CONFIG = pdfkit.configuration(wkhtmltopdf=WKHTMLTOPDF)
PDF_OPTS = {
    "page-size": "A4",
    "margin-top": "12mm",
    "margin-right": "12mm",
    "margin-bottom": "12mm",
    "margin-left": "12mm",
    "encoding": "UTF-8",
    "enable-local-file-access": "",  
    "print-media-type": "",          
    "dpi": "144",
    "zoom": "1.0",
    "footer-right": "[page]/[toPage]",
    "footer-font-size": "8",
    "quiet": ""
}


app = Flask(__name__, static_folder="static", template_folder="templates")
app.config['SECRET_KEY'] = os.getenv("FLASK_SECRET", "dev-secret")

BASE_DIR = Path(__file__).resolve().parent
DB_DIR = BASE_DIR / "instance"
DB_DIR.mkdir(parents=True, exist_ok=True)

app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_DIR / 'riskradar.db'}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)
    
with app.app_context():
    sdb.init_db()   


def _build_context(url: str, mode: str) -> dict:
    t0 = time.time()
    groups = full_scan(url) if mode == "FULL" else quick_scan(url)
    groups = apply_rr(groups or [])  # RR (L/I/S + bucket/label)

    for g in (groups or []):
        # --- ID i ime nalaza
        pid      = str(g.get("pluginid") or g.get("pluginId") or g.get("pluginID") or "").strip()
        alert    = (g.get("alert") or "").strip()
        alert_lc = alert.lower()

        # 1) kurirane reference
        g["rem_refs"] = remediation_refs.get(pid) or remediation_refs.get(alert_lc) or []

        # 2) dodatni URL-ovi iz ZAP 'reference' (SIGURNO: definiraj ref_blob prije regexa)
        ref_blob = g.get("reference")
        if not isinstance(ref_blob, str):
            ref_blob = ""
        urls = re.findall(r'https?://[^\s)>,;"\]]+', ref_blob, flags=re.IGNORECASE)
        # deduplikacija uz očuvanje redoslijeda
        seen = set()
        ref_urls = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                ref_urls.append(u)
            if len(ref_urls) >= 3:
                break
        g["ref_urls"] = ref_urls

        # 3) signature za Status kolonu (isti kao u db.py)
        try:
            g["signature"] = sdb.make_signature(
                g.get("alert"),
                g.get("cweid"),
                g.get("param"),
                g.get("sample_urls") or []
            )
        except Exception:
            g["signature"] = ""

    duration_s = round(time.time() - t0, 1)

    # broj po ZAP risku
    counts = {"high": 0, "medium": 0, "low": 0}
    for g in groups:
        r = (g.get("risk") or "").upper()
        if r.startswith("HIGH"): counts["high"] += 1
        elif r.startswith("MEDIUM"): counts["medium"] += 1
        elif r.startswith("LOW"): counts["low"] += 1

    # bodovi i sortiranje
    def priority_pts(g):
        r = (g.get("risk") or "").upper()
        return 3 if r.startswith("HIGH") else 2 if r.startswith("MEDIUM") else 1

    for g in groups:
        L = int(g.get("rr_likelihood") or 0)
        I = int(g.get("rr_impact") or 0)
        S = int(g.get("rr_score") or (L * I))
        g["rr_score"] = S
        g["priority_pts"] = priority_pts(g)

    groups = sorted(
        groups,
        key=lambda g: (-g["priority_pts"], -int(g.get("rr_score") or 0),
                       -int(g.get("instances") or 0), (g.get("alert") or "").lower())
    )

    total_points = sum(g["priority_pts"] for g in groups)

    return {
        "url": url,
        "mode": mode,
        "duration_s": duration_s,
        "groups": groups,
        "counts": counts,
        "high": counts["high"],
        "med": counts["medium"],
        "low": counts["low"],
        "total_points": total_points,
    }


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/scan")
def scan():
    url  = (request.args.get("url") or "").strip()
    mode = (request.args.get("mode") or "QUICK").upper()
    if not url:
        flash("Unesi URL.", "warning")
        return redirect(url_for("home"))

    try:
        ctx = _build_context(url, mode)
        session['last_report'] = {'url': url, 'mode': mode, 'ctx': ctx, 'ts': time.time()}
    except Exception as e:
        app.logger.exception("Scan error")
        flash(f"Skeniranje nije uspjelo: {e}", "danger")
        return redirect(url_for("home"))

    system_id = None
    scan_id   = None
    status_map = {}
    db_warning = None

    try:
        system_id = sdb.upsert_system(name=url, url=url, note="")
        scores = []
        for g in ctx.get("groups", []):
            L = int(g.get("rr_likelihood") or 0)
            I = int(g.get("rr_impact") or 0)
            S = int(g.get("rr_score") or (L * I))
            g["rr_score"]  = S
            g["rr_bucket"] = sdb.rr_bucket(S)
            scores.append(S)

        max_rr     = max(scores) if scores else 0
        max_bucket = sdb.rr_bucket(max_rr)

        scan_id = sdb.insert_scan_run(
            system_id=system_id, mode=mode,
            duration_s=ctx.get("duration_s", 0.0),
            h=ctx.get("high", 0), m=ctx.get("med", 0), l=ctx.get("low", 0),
            max_rr=max_rr, max_bucket=max_bucket, pdf_path=None,
        )
        for g in ctx.get("groups", []):
            sdb.insert_finding(scan_id, g)

        status_map = sdb.status_map_for_system(system_id)
    except Exception as e:
        app.logger.exception("DB save failed (non-fatal)")
        db_warning = str(e)
        flash("Skeniranje je uspjelo, ali spremanje u bazu nije uspjelo. Statusi nalaza neće biti sačuvani.", "warning")

    return render_template("report.html", **ctx,
                           system_id=system_id, scan_id=scan_id,
                           status_map=status_map, db_warning=db_warning)


@app.route("/scan/pdf")
def scan_pdf():
    url  = (request.args.get("url") or "").strip()
    mode = (request.args.get("mode") or "QUICK").upper()
    if not url:
        flash("Unesi URL.", "warning")
        return redirect(url_for("home"))

    cached = session.get('last_report')
    use_ctx = None
    now = time.time()
    if cached and cached.get('url') == url and cached.get('mode') == mode:
        if now - cached.get('ts', 0) <= SESSION_PDF_TTL:
            use_ctx = cached['ctx']

    if not use_ctx:
        try:
            use_ctx = _build_context(url, mode)
        except Exception as e:
            flash(f"Greška pri skeniranju: {e}", "danger")
            return redirect(url_for("home"))

    html = render_template("report.html", **use_ctx, printable=True)
    pdf_bytes = pdfkit.from_string(html, False, configuration=PDFKIT_CONFIG, options=PDF_OPTS)

    return send_file(
        io.BytesIO(pdf_bytes),
        as_attachment=True,
        download_name="RiskRadar-Izvještaj.pdf",
        mimetype="application/pdf"
    )

@app.post("/api/finding_status")
def api_finding_status():
    data = request.get_json(force=True)
    sdb.set_status(int(data["system_id"]),
                   data["signature"],
                   data["status"],
                   data.get("note", ""))
    return {"ok": True}

@app.get("/systems")
def systems_list():
    with sdb.db() as con:
        systems = con.execute("""
            SELECT s.*,
                   (SELECT COUNT(*) FROM scan_runs r WHERE r.system_id = s.id) AS runs
            FROM systems s
            ORDER BY s.created_at DESC
        """).fetchall()
    return render_template("systems.html", systems=systems)


@app.post("/systems/new")
def systems_new():
    name = request.form.get("name") or request.form.get("url")
    url  = request.form.get("url")
    note = request.form.get("note")
    sdb.upsert_system(name, url, note)
    return redirect(url_for("systems_list"))


@app.get("/systems/<int:sid>")
def system_detail(sid):
    with sdb.db() as con:
        s = con.execute("SELECT * FROM systems WHERE id=?", (sid,)).fetchone()
        runs = con.execute("""
            SELECT * FROM scan_runs
            WHERE system_id=?
            ORDER BY datetime(started_at) DESC
        """, (sid,)).fetchall()

    delta = {"new": 0, "gone": 0, "same": 0}
    if len(runs) >= 2:
        cur_sigs  = sdb.signatures_for_scan(runs[0]["id"])
        prev_sigs = sdb.signatures_for_scan(runs[1]["id"])
        delta["new"]  = len(cur_sigs - prev_sigs)
        delta["gone"] = len(prev_sigs - cur_sigs)
        delta["same"] = len(cur_sigs & prev_sigs)

    return render_template("systems_detail.html", s=s, runs=runs, delta=delta)


@app.get("/scan/<int:scan_id>/csv")
def scan_csv(scan_id):
    with sdb.db() as con:
        rows = con.execute("""
            SELECT alert, cwe_id, risk, rr_likelihood, rr_impact, rr_score,
                   instances, param, evidence, fix, reference
            FROM findings WHERE scan_id=?
        """, (scan_id,)).fetchall()

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["alert","cwe_id","risk","L","I","RR","instances","param","evidence","fix","reference"])
    for r in rows:
        w.writerow([r["alert"], r["cwe_id"], r["risk"], r["rr_likelihood"], r["rr_impact"],
                    r["rr_score"], r["instances"], r["param"], (r["evidence"] or "")[:3000],
                    r["fix"], r["reference"]])

    resp = make_response(buf.getvalue())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = f'attachment; filename="scan_{scan_id}.csv"'
    return resp


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
