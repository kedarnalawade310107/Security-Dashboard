from flask import Flask, render_template, request, jsonify
import hashlib
import requests
import re

app = Flask(__name__)


def check_password_strength(password):
    score = 0
    feedback = []
    tips = []

    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Too short")
        tips.append("Use at least 8 characters — longer is always stronger.")

    if len(password) >= 12:
        score += 1

    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("No uppercase letters")
        tips.append("Mix uppercase and lowercase letters (e.g. 'Hello' not 'hello').")

    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("No lowercase letters")

    if re.search(r'\d', password):
        score += 1
    else:
        feedback.append("No numbers")
        tips.append("Add numbers to make your password harder to guess.")

    if re.search(r'[!@#$%^&*(),.?\":{}|<>]', password):
        score += 1
    else:
        feedback.append("No special characters")
        tips.append("Special characters like !@#$ dramatically increase password strength.")

    common_passwords = ["password", "123456", "qwerty", "abc123", "letmein", "welcome", "monkey", "dragon"]
    if password.lower() in common_passwords:
        score = 1
        feedback.append("This is a very common password!")
        tips.append("Avoid common passwords — attackers try these first in brute-force attacks.")

    if score <= 2:
        strength = "Weak"
    elif score <= 4:
        strength = "Fair"
    elif score == 5:
        strength = "Good"
    else:
        strength = "Strong"

    if not tips:
        tips.append("Great password! Consider using a password manager to store it safely.")

    return {
        "score": score,
        "max_score": 6,
        "strength": strength,
        "issues": feedback,
        "tips": tips
    }


def check_pwned_password(password):
    """Uses HaveIBeenPwned k-anonymity API — password is never sent, only first 5 chars of its hash."""
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    try:
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
        hashes = response.text.splitlines()
        for line in hashes:
            h, count = line.split(":")
            if h == suffix:
                return int(count)
        return 0
    except Exception:
        return None


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/check-password", methods=["POST"])
def check_password():
    data = request.get_json()
    password = data.get("password", "")

    if not password:
        return jsonify({"error": "No password provided"}), 400

    strength_result = check_password_strength(password)
    pwned_count = check_pwned_password(password)

    return jsonify({
        "strength": strength_result,
        "pwned_count": pwned_count
    })


if __name__ == "__main__":
    app.run(debug=True)
