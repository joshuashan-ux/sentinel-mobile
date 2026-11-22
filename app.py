
import os
import re
import ipaddress
from urllib.parse import urlsplit

from flask import Flask, request, render_template_string

app = Flask(__name__)

PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#091321">
<title>Sentinel Mobile</title>
<style>
*{box-sizing:border-box}
body{
 margin:0;background:#091321;color:#f4f7fb;
 font-family:-apple-system,BlinkMacSystemFont,Arial,sans-serif;
 padding:20px;max-width:760px;margin:auto
}
header{text-align:center;padding:25px 0}
.logo{font-size:48px}
h1{color:#55d8c4;margin:8px;font-size:29px}
.sub{color:#9eafc3}
.card{
 background:#15243a;padding:22px;border-radius:17px;
 margin:18px 0;border:1px solid #203750
}
h2{color:#55d8c4;font-size:20px}
p{line-height:1.55}
input[type=text],input[type=url]{
 width:100%;padding:16px;border:1px solid #405773;
 border-radius:10px;background:#091321;color:white;
 font-size:16px;margin:10px 0
}
button{
 width:100%;padding:16px;background:#55c5b2;
 color:#071521;border:0;border-radius:10px;
 font-weight:bold;font-size:16px;margin-top:12px
}
label{display:flex;align-items:center;gap:12px;
 padding:12px 0;color:#d8e3ef;line-height:1.4}
input[type=checkbox]{width:19px;height:19px;accent-color:#55d8c4}
.score{font-size:53px;color:#55d8c4;
 text-align:center;font-weight:bold;margin:15px}
.result{
 background:#263950;padding:15px;border-radius:10px;
 margin:10px 0;line-height:1.5;overflow-wrap:anywhere
}
.good{border-left:4px solid #40d6a3}
.warning{border-left:4px solid #f5bd54}
.danger{border-left:4px solid #ff7373}
.muted{color:#9eafc3;font-size:13px}
footer{text-align:center;color:#8293a9;
 font-size:13px;padding:28px 5px}
a{color:#55d8c4}
</style>
</head>
<body>

<header>
<div class="logo">🛡️</div>
<h1>SENTINEL MOBILE</h1>
<p class="sub">Your personal mobile security centre</p>
<p class="muted">FREE SECURITY TOOLS · VERSION 0.2</p>
</header>

<div class="card">
<h2>🔍 Mobile Security Assessment</h2>
<p>Answer these questions to assess your security habits.</p>
<form method="POST" action="/assess">

<label><input type="checkbox" name="updates">
My phone has the latest security updates</label>

<label><input type="checkbox" name="lock">
I use a strong screen lock</label>

<label><input type="checkbox" name="twofa">
I use two-factor authentication</label>

<label><input type="checkbox" name="wifi">
I avoid unsecured public Wi-Fi</label>

<label><input type="checkbox" name="apps">
I only install trusted applications</label>

<label><input type="checkbox" name="backup">
I regularly back up important data</label>

<label><input type="checkbox" name="phishing">
I check links before opening them</label>

<button>Assess My Security</button>
</form>
</div>

<div class="card">
<h2>🔗 Advanced Link Checker</h2>
<p>Analyse a website address for common suspicious characteristics.</p>
<form method="POST" action="/check">
<input type="text" name="url"
placeholder="Enter website address"
maxlength="2048" required>
<button>Analyse Website</button>
</form>
<p class="muted">
Your submitted address is analysed without visiting it.
</p>
</div>

{% if score is not none %}
<div class="card">
<h2>📊 Your Security Assessment</h2>
<div class="score">{{score}}/100</div>
<div class="result good">{{message}}</div>
<h3>Recommended improvements</h3>
{% for tip in tips %}
<div class="result warning">{{tip}}</div>
{% endfor %}
{% if not tips %}
<div class="result good">
You completed all seven security checks. Keep maintaining these habits.
</div>
{% endif %}
<p class="muted">
This score measures your answers, not a technical inspection
of your phone.
</p>
</div>
{% endif %}

{% if findings %}
<div class="card">
<h2>🔎 Link Analysis Results</h2>
<div class="result {{level}}">
<strong>{{verdict}}</strong>
</div>
<p><strong>Risk indicator: {{risk}}/100</strong></p>
{% for finding in findings %}
<div class="result {{level}}">{{finding}}</div>
{% endfor %}
<p class="muted">
This is a heuristic assessment, not a malware scan.
A low score does not prove that a website is safe.
No external threat-intelligence database is queried.
</p>
</div>
{% endif %}

<div class="card">
<h2>🔐 Your Privacy</h2>
<p>
Sentinel Mobile analyses submitted website addresses
without opening them. Never submit passwords, private
messages or confidential information.
</p>
</div>

<footer>
🛡️ Sentinel Mobile V0.2<br>
Free mobile security awareness platform<br>
Built to help everyone stay safer online.
</footer>
</body>
</html>
"""


def analyse_url(raw):
    findings = []
    risk = 0

    raw = raw.strip()

    if not raw:
        return 100, "Unable to analyse this address.", [
            "No website address was supplied."
        ], "danger"

    if len(raw) > 2048:
        return 100, "Address too long.", [
            "The submitted address exceeds the allowed length."
        ], "danger"

    if re.search(r"\\s", raw):
        return 40, "Suspicious formatting detected.", [
            "The address contains whitespace characters."
        ], "warning"

    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw

    try:
        parsed = urlsplit(raw)
        host = parsed.hostname

        if parsed.scheme.lower() not in ("http", "https"):
            return 100, "Unsupported address type.", [
                "Only HTTP and HTTPS website addresses are supported."
            ], "danger"

        if not host:
            return 100, "Invalid website address.", [
                "A valid hostname could not be identified."
            ], "danger"

        port = parsed.port

    except ValueError:
        return 100, "Invalid website address.", [
            "The address contains invalid formatting or port information."
        ], "danger"

    host = host.lower().rstrip(".")

    if parsed.scheme.lower() == "http":
        risk += 20
        findings.append(
            "Warning: This address uses HTTP rather than HTTPS."
        )

    else:
        findings.append(
            "HTTPS is present. This encrypts the connection "
            "but does not guarantee the website is trustworthy."
        )

    if parsed.username or parsed.password:
        risk += 35
        findings.append(
            "Warning: The address contains embedded login credentials."
        )

    try:
        ip = ipaddress.ip_address(host)
        risk += 25
        findings.append(
            "Warning: The website uses a direct IP address instead of a domain."
        )

        if ip.is_private or ip.is_loopback or ip.is_link_local:
            findings.append(
                "Caution: The address points to a private or local network."
            )

    except ValueError:
        pass

    try:
        ascii_host = host.encode("idna").decode("ascii").lower()

        if "xn--" in ascii_host:
            risk += 30
            findings.append(
                "Warning: The domain contains encoded international characters. "
                "Check carefully for lookalike domains."
            )

    except UnicodeError:
        risk += 30
        findings.append(
            "Warning: The domain contains unusual international characters."
        )

    shorteners = {
        "bit.ly", "tinyurl.com", "t.co", "is.gd",
        "ow.ly", "buff.ly", "cutt.ly", "rebrand.ly"
    }

    if host in shorteners:
        risk += 15
        findings.append(
            "Caution: This is a URL-shortening service. "
            "The final destination is hidden."
        )

    labels = host.split(".")

    if len(labels) >= 5:
        risk += 10
        findings.append(
            "Caution: The domain contains many subdomains."
        )

    if host.count("-") >= 3:
        risk += 5
        findings.append(
            "Caution: The hostname contains several hyphens."
        )

    if port is not None and port not in (80, 443):
        risk += 10
        findings.append(
            "Caution: The website uses a non-standard web port."
        )

    if len(raw) > 180:
        risk += 5
        findings.append(
            "Caution: This is an unusually long website address."
        )

    risk = min(risk, 100)

    if risk >= 40:
        verdict = "High number of warning indicators detected."
        level = "danger"
    elif risk >= 20:
        verdict = "Several warning indicators detected."
        level = "warning"
    elif risk > 0:
        verdict = "Some caution indicators detected."
        level = "warning"
    else:
        verdict = "No basic warning indicators detected."
        level = "good"

    if not findings:
        findings.append(
            "No basic suspicious characteristics were detected."
        )

    return risk, verdict, findings, level


@app.route("/")
def home():
    return render_template_string(
        PAGE,
        score=None,
        findings=[],
        tips=[]
    )


@app.route("/assess", methods=["POST"])
def assess():
    questions = {
        "updates": "Enable automatic security updates.",
        "lock": "Set a strong screen lock.",
        "twofa": "Enable two-factor authentication.",
        "wifi": "Avoid unsecured public Wi-Fi.",
        "apps": "Only install trusted applications.",
        "backup": "Set up regular backups.",
        "phishing": "Learn to recognise phishing links."
    }

    score = round(
        sum(100 / len(questions) for key in questions
            if request.form.get(key))
    )

    tips = [
        questions[key]
        for key in questions
        if not request.form.get(key)
    ]

    if score >= 85:
        message = "Excellent security habits!"
    elif score >= 60:
        message = "Good progress. A few improvements remain."
    elif score >= 35:
        message = "Your security habits need improvement."
    else:
        message = "Several important security steps are missing."

    return render_template_string(
        PAGE,
        score=score,
        message=message,
        tips=tips,
        findings=[]
    )


@app.route("/check", methods=["POST"])
def check():
    url = request.form.get("url", "")

    risk, verdict, findings, level = analyse_url(url)

    return render_template_string(
        PAGE,
        score=None,
        tips=[],
        findings=findings,
        verdict=verdict,
        risk=risk,
        level=level
    )


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 10000))
    )
