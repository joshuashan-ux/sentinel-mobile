
import os
import re
import ipaddress
from urllib.parse import urlparse
from flask import Flask, request, render_template_string

app = Flask(__name__)

PAGE = """
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentinel Mobile</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#091321;color:#fff;font-family:Arial,sans-serif;padding:22px}
header{text-align:center;padding:25px 0}
.logo{font-size:48px}
h1{color:#42d9c4;font-size:30px;margin:8px}
.sub{color:#9eafc3}
.card{background:#142337;padding:20px;border-radius:15px;margin:16px 0}
h2{font-size:19px;color:#42d9c4}
input{width:100%;padding:15px;border:1px solid #38516c;border-radius:9px;background:#091321;color:white;margin:10px 0}
button{width:100%;padding:15px;background:#16bba9;color:#071521;border:0;border-radius:9px;font-weight:bold;font-size:16px;margin-top:10px}
label{display:block;padding:12px 0;color:#d5e0ed}
.score{font-size:48px;color:#42d9c4;text-align:center;font-weight:bold}
.result{background:#20364d;padding:15px;border-radius:10px;margin-top:12px}
footer{text-align:center;color:#8192a5;font-size:12px;padding:25px}
</style>
</head>
<body>
<header>
<div class="logo">🛡️</div>
<h1>SENTINEL MOBILE</h1>
<p class="sub">Your personal mobile security centre</p>
</header>

<div class="card">
<h2>🔍 Security Assessment</h2>
<p>Check your everyday security habits.</p>
<form method="POST" action="/assess">
<label><input type="checkbox" name="updates"> My phone is running the latest updates</label>
<label><input type="checkbox" name="lock"> I use a strong screen lock</label>
<label><input type="checkbox" name="twofa"> I use two-factor authentication</label>
<label><input type="checkbox" name="wifi"> I avoid unsecured public Wi-Fi</label>
<label><input type="checkbox" name="apps"> I only install trusted apps</label>
<button>Assess My Security</button>
</form>
</div>

<div class="card">
<h2>🔗 Suspicious Link Checker</h2>
<p>Check a link for common warning signs.</p>
<form method="POST" action="/check">
<input name="url" placeholder="Enter website address" required>
<button>Check This Link</button>
</form>
</div>

{% if score is not none %}
<div class="card">
<h2>Your Security Score</h2>
<div class="score">{{score}}/100</div>
<p>{{message}}</p>
{% for tip in tips %}
<div class="result">{{tip}}</div>
{% endfor %}
</div>
{% endif %}

{% if findings %}
<div class="card">
<h2>Link Analysis</h2>
{% for finding in findings %}
<div class="result">{{finding}}</div>
{% endfor %}
<p><b>{{verdict}}</b></p>
<p class="sub">This is a basic warning-sign assessment, not a guarantee that a link is safe.</p>
</div>
{% endif %}

<footer>
Sentinel Mobile V0.1<br>
Free mobile security awareness tool
</footer>
</body>
</html>
"""

@app.route("/")
def home():
    return render_template_string(
        PAGE, score=None, tips=[], findings=[]
    )

@app.route("/assess", methods=["POST"])
def assess():
    questions = {
        "updates": "Enable automatic phone updates.",
        "lock": "Set a strong screen lock.",
        "twofa": "Enable two-factor authentication.",
        "wifi": "Avoid unsecured public Wi-Fi.",
        "apps": "Only install trusted applications."
    }

    score = sum(
        20 for key in questions if request.form.get(key)
    )

    tips = [
        questions[key]
        for key in questions
        if not request.form.get(key)
    ]

    message = (
        "Excellent security habits!"
        if score >= 80 else
        "There is room to improve your security."
    )

    return render_template_string(
        PAGE, score=score, message=message,
        tips=tips, findings=[]
    )

@app.route("/check", methods=["POST"])
def check():
    url = request.form.get("url", "").strip()
    findings = []

    if len(url) > 2048:
        findings.append("URL is too long.")
        verdict = "Unable to assess this link."
    else:
        if not re.match(r"^https?://", url, re.I):
            url = "https://" + url

        parsed = urlparse(url)
        host = parsed.hostname or ""

        if parsed.scheme != "https":
            findings.append("Warning: HTTPS is not being used.")

        if not host or "." not in host:
            findings.append("Warning: Website address looks unusual.")

        if parsed.username or parsed.password:
            findings.append("Warning: Link contains embedded credentials.")

        try:
            ipaddress.ip_address(host)
            findings.append("Warning: Link uses a direct IP address.")
        except ValueError:
            pass

        if "xn--" in host.lower():
            findings.append("Warning: Domain uses encoded characters.")

        if "@" in url:
            findings.append("Warning: Link contains an @ symbol.")

        if len(url) > 150:
            findings.append("Warning: Link is unusually long.")

        if re.search(r"login|verify|password|account|secure", url, re.I):
            findings.append("Caution: Link contains common account-related keywords.")

        if not findings:
            findings.append("No basic warning signs were detected.")

        verdict = (
            "Potential warning signs detected."
            if any("Warning:" in x for x in findings)
            else "Review the link carefully before opening."
        )

    return render_template_string(
        PAGE, score=None, tips=[],
        findings=findings, verdict=verdict
    )

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 10000))
    )
