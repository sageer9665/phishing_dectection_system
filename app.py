from flask import Flask, render_template, request
import pandas as pd
import joblib

from feature_extractor import extract_features

app = Flask(__name__)

# Load the existing 15-feature model
model = joblib.load("models/phishing_detector.joblib")

# Load the feature order used by the model
selected_features = joblib.load("models/selected_features.joblib")


# ==========================================
# PLAIN-ENGLISH MEANING OF EACH FEATURE VALUE
#   1  = normal / safe sign
#   0  = unclear sign
#  -1  = warning sign
# ==========================================

FEATURE_MESSAGES = {
    "UsingIP": {
        "label": "IP address",
        1: "The address uses a normal domain name.",
        -1: "The address uses an IP number instead of a domain name.",
    },
    "LongURL": {
        "label": "URL length",
        1: "The URL has a normal length.",
        0: "The URL is fairly long.",
        -1: "The URL is very long, which is common in phishing links.",
    },
    "ShortURL": {
        "label": "URL shortener",
        1: "No URL shortening service is used.",
        -1: "A URL shortening service is used, which hides the real address.",
    },
    "Symbol@": {
        "label": "@ symbol",
        1: "There is no @ symbol in the URL.",
        -1: "The URL contains an @ symbol, which can hide the real destination.",
    },
    "Redirecting//": {
        "label": "Hidden redirect",
        1: "There is no extra // redirect in the URL.",
        -1: "The URL contains an extra // that can redirect to another website.",
    },
    "PrefixSuffix-": {
        "label": "Hyphen in domain",
        1: "The domain name has no hyphen.",
        -1: "The domain name has a hyphen, which is common in fake look-alike domains.",
    },
    "SubDomains": {
        "label": "Subdomains",
        1: "The URL has a normal number of subdomains.",
        0: "The URL has several subdomains.",
        -1: "The URL has many subdomains, which can disguise the real domain.",
    },
    "HTTPS": {
        "label": "Secure connection",
        1: "The website uses a secure HTTPS connection.",
        -1: "The website does not use a secure HTTPS connection.",
    },
    "NonStdPort": {
        "label": "Port number",
        1: "The standard web port is used.",
        -1: "A non-standard port number is used.",
    },
    "HTTPSDomainURL": {
        "label": "'https' in domain",
        1: "The domain name does not contain the word 'https'.",
        -1: "The word 'https' appears inside the domain name to look secure.",
    },
    "Favicon": {
        "label": "Website icon",
        1: "The website icon loads from the same website.",
        -1: "The website icon is missing or loads from another website (or the page could not be read).",
    },
    "RequestURL": {
        "label": "Page resources",
        1: "Images and other page resources look normal.",
        0: "Page resources are mixed, or none were found.",
        -1: "Most page resources load from other websites (or the page could not be read).",
    },
    "AnchorURL": {
        "label": "Page links",
        1: "The links on the page look normal.",
        0: "The links on the page are mixed, or none were found.",
        -1: "Most links on the page lead to other websites (or the page could not be read).",
    },
    "ServerFormHandler": {
        "label": "Form destination",
        1: "No suspicious form was found on the page.",
        0: "No form was found, or a form sends data to another website.",
        -1: "A form sends data to a blank address (or the page could not be read).",
    },
    "IframeRedirection": {
        "label": "Hidden frames",
        1: "No hidden frame was found on the page.",
        -1: "The page contains a frame (iframe) that can hide other content (or the page could not be read).",
    },
}

STATUS_NAMES = {1: "good", 0: "mid", -1: "bad"}
STATUS_ORDER = {"bad": 0, "mid": 1, "good": 2}


def explain_features(features):
    """Turn the extracted feature values into readable findings."""

    findings = []

    for name in selected_features:
        value = features.get(name)
        info = FEATURE_MESSAGES.get(name)

        if info is None or value not in info:
            continue

        findings.append({
            "label": info["label"],
            "text": info[value],
            "status": STATUS_NAMES[value],
        })

    # Show warning signs first, then unclear, then normal signs
    findings.sort(key=lambda item: STATUS_ORDER[item["status"]])

    summary = {
        "bad": sum(1 for item in findings if item["status"] == "bad"),
        "mid": sum(1 for item in findings if item["status"] == "mid"),
        "good": sum(1 for item in findings if item["status"] == "good"),
    }

    return findings, summary


@app.route("/", methods=["GET", "POST"])
def home():

    result = None
    confidence = None
    error = None
    submitted_url = ""
    findings = []
    summary = None

    if request.method == "POST":

        submitted_url = request.form.get("url", "").strip()

        if not submitted_url:
            error = "Please enter a website URL."

        else:
            try:
                # Extract features from the submitted URL
                features = extract_features(submitted_url)

                # Show exactly what the extractor is giving the model
                print("\n==============================")
                print("URL:", submitted_url)
                print("EXTRACTED FEATURES:")

                for feature in selected_features:
                    print(feature, "=", features.get(feature))

                # Arrange features in model order
                input_data = pd.DataFrame(
                    [[features[feature] for feature in selected_features]],
                    columns=selected_features
                )

                # Make prediction
                prediction = model.predict(input_data)[0]

                # Get probabilities
                probabilities = model.predict_proba(input_data)[0]

                # Get probability of predicted class
                class_index = list(model.classes_).index(prediction)

                confidence = round(
                    probabilities[class_index] * 100,
                    2
                )

                print("PREDICTION:", prediction)
                print("CONFIDENCE:", confidence)
                print("==============================\n")

                if prediction == 1:
                    result = "Legitimate Website"
                else:
                    result = "Phishing Website"

                # Build the readable list of what the system detected
                findings, summary = explain_features(features)

            except Exception as exc:

                error = "The URL could not be analyzed."

                print("ERROR:", exc)

    return render_template(
        "index.html",
        result=result,
        confidence=confidence,
        error=error,
        submitted_url=submitted_url,
        findings=findings,
        summary=summary
    )


if __name__ == "__main__":
    app.run(debug=True)
