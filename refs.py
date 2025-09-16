remediation_refs = {
    # po pluginId
    "10038": [  # CSP header not set
        ("OWASP CSP Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"),
        ("MDN Content-Security-Policy", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"),
    ],
    "10020": [  # X-Frame-Options missing
        ("OWASP Clickjacking Defense", "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"),
        ("MDN X-Frame-Options", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"),
    ],
    "10021": [  # X-Content-Type-Options missing
        ("MDN X-Content-Type-Options", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"),
    ],
    "10098": [  # (primjer) "Access-Control-Allow-Origin header"
        ("MDN: CORS", "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"),
        ("MDN: Access-Control-Allow-Origin", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin"),
    ],

    # fallback po nazivu nalaza
    "csp header not set": [
        ("OWASP CSP Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"),
        ("MDN Content-Security-Policy", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"),
    ],
    "x-frame-options header missing": [
        ("OWASP Clickjacking Defense", "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"),
    ],
    "x-content-type-options header missing": [
        ("MDN X-Content-Type-Options", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"),
    ],
    "cors": [
        ("MDN CORS", "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"),
    ],
     "access-control-allow-origin": [
        ("MDN: CORS", "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"),
        ("MDN: Access-Control-Allow-Origin", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin"),
    ],
}
