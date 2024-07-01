from flask import Flask, render_template, request, jsonify
import re
from zxcvbn import zxcvbn
import json

app = Flask(__name__)

# Load a small dictionary of common words for content-aware analysis
with open('common_words.json', 'r') as file:
    common_words = set(json.load(file))

# OWASP Password Complexity Checks
def check_password_strength(password):
    # Regex checks
    regex_checks = {
        "length": re.compile(r".{12,}"),  
        "lowercase": re.compile(r"[a-z]"),
        "uppercase": re.compile(r"[A-Z]"),
        "digits": re.compile(r"\d"),
        "special": re.compile(r"[@$!%*?&]")
    }

    results = {key: bool(regex.search(password)) for key, regex in regex_checks.items()}
    score = sum(results.values())

    # Detailed feedback using zxcvbn for entropy analysis
    zxcvbn_result = zxcvbn(password)
    entropy = zxcvbn_result['score']  # Change this to 'score'
    feedback = zxcvbn_result['feedback']['suggestions']

    # Content-aware analysis: Check for common words
    content_analysis = any(word in password.lower() for word in common_words)

    return {
        "regex_checks": results,
        "score": score,
        "entropy": entropy,
        "feedback": feedback,
        "content_analysis": content_analysis
    }

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        password = request.json['password']
        strength = check_password_strength(password)
        return jsonify(strength)
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
