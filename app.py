
from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse
import ipaddress
import re

app = Flask(__name__)


def detect_url(raw_url):
    raw_url = raw_url.strip()

    if not raw_url or len(raw_url) > 2048:
        return None, "Enter a URL with fewer than 2049 characters."

    # Parse and validate the URL
    try:
        candidate = (
            raw_url
            if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", raw_url)
            else "https://" + raw_url
        )

        parsed = urlparse(candidate)

        if parsed.scheme not in ("http", "https"):
            return None, "Only HTTP and HTTPS URLs are supported."

        if not parsed.hostname:
            return None, "The URL must contain a valid hostname."

        hostname = parsed.hostname.encode("idna").decode("ascii").lower()

        # Validate the port if the URL contains one
        _ = parsed.port

    except (ValueError, UnicodeError):
        return None, "Invalid URL format."

    score = 0
    findings = []

    def flag(points, message):
        nonlocal score
        score += points
        findings.append(message)

    # Algorithm 1: URL feature-based detection

    if len(raw_url) > 100:
        flag(1, "Unusually long URL")

    if "@" in parsed.netloc:
        flag(2, "Contains an @ symbol in the authority")

    try:
        ipaddress.ip_address(hostname)
        flag(2, "Uses an IP address instead of a domain name")
    except ValueError:
        pass

    if parsed.scheme != "https":
        flag(1, "Does not use HTTPS")

    if "xn--" in hostname:
        flag(2, "Contains an internationalized domain label")

    if hostname.count(".") >= 4:
        flag(1, "Contains many subdomains")

    # Algorithm 2: Heuristic pattern detection

    suspicious_words = [
        "login-verify",
        "account-suspended",
        "password-reset",
        "free-prize",
        "claim-reward",
        "urgent-verification",
    ]

    full_url = (hostname + parsed.path + "?" + parsed.query).lower()

    if any(word in full_url for word in suspicious_words):
        flag(2, "Contains suspicious URL wording")

    # Check for brand names embedded in misleading hostnames.
    brands = ["paypal", "google", "microsoft", "amazon", "apple"]

    for brand in brands:
        if brand in hostname:
            labels = hostname.split(".")
            legitimate_domain_shapes = (
                hostname == brand + ".com"
                or hostname.endswith("." + brand + ".com")
                or hostname == brand + ".org"
                or hostname.endswith("." + brand + ".org")
            )

            if not legitimate_domain_shapes and (
                brand in labels[0] or brand in hostname
            ):
                flag(2, f"Possible misleading use of brand name: {brand}")
                break

    if score >= 4:
        verdict = "High risk indicators"
        level = "danger"
    elif score >= 2:
        verdict = "Suspicious indicators"
        level = "warning"
    else:
        verdict = "No major warning signs detected"
        level = "safe"

    if not findings:
        findings.append("No configured warning patterns detected")

    return {
        "url": candidate,
        "hostname": hostname,
        "score": score,
        "verdict": verdict,
        "level": level,
        "findings": findings,
        "note": (
            "This heuristic score is not a probability. "
            "A low score does not prove that a URL is safe. "
            "No live threat-intelligence database was checked."
        ),
    }, None


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Send a JSON object containing a URL."}), 400

    raw_url = data.get("url")

    if not isinstance(raw_url, str):
        return jsonify({"error": "The URL must be a text value."}), 400

    result, error = detect_url(raw_url)

    if error:
        return jsonify({"error": error}), 400

    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)
