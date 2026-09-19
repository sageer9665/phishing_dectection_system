# ==========================================
# FLASK APPLICATION
# ==========================================

from flask import Flask, render_template, request
import pandas as pd
import joblib

from feature_extractor import extract_features


app = Flask(__name__)

MODEL_PATH = "models/phishing_detector.joblib"
FEATURES_PATH = "models/selected_features.joblib"

model = joblib.load(MODEL_PATH)
selected_features = joblib.load(FEATURES_PATH)


# Stop the application early if the saved model and feature list disagree.
if model.n_features_in_ != len(selected_features):
    raise ValueError(
        f"Model expects {model.n_features_in_} features, "
        f"but selected_features contains {len(selected_features)}."
    )


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    confidence = None
    error = None
    submitted_url = ""

    if request.method == "POST":
        submitted_url = request.form.get("url", "").strip()

        if not submitted_url:
            error = "Please enter a website URL."
        else:
            try:
                extracted_features = extract_features(submitted_url)

                # Verify that every model feature was produced.
                missing = [
                    feature for feature in selected_features
                    if feature not in extracted_features
                ]

                if missing:
                    raise ValueError(f"Missing features: {missing}")

                # Create the model input in the exact training order.
                input_data = pd.DataFrame(
                    [[extracted_features[feature] for feature in selected_features]],
                    columns=selected_features
                )

                prediction = model.predict(input_data)[0]
                probabilities = model.predict_proba(input_data)[0]
                predicted_index = list(model.classes_).index(prediction)
                confidence = round(probabilities[predicted_index] * 100, 2)

                result = (
                    "Legitimate Website"
                    if prediction == 1
                    else "Phishing Website"
                )

                # Temporary diagnostic output in the terminal.
                print("\n--- Prediction Debug ---")
                print("URL:", submitted_url)
                print("Features:")
                print(input_data.to_dict("records")[0])
                print("Prediction:", prediction)
                print("Probabilities:", dict(zip(model.classes_, probabilities)))
                print("------------------------\n")

            except Exception as exc:
                error = "The URL could not be analyzed."
                print("Prediction error:", exc)

    return render_template(
        "index.html",
        result=result,
        confidence=confidence,
        error=error,
        submitted_url=submitted_url
    )


if __name__ == "__main__":
    app.run(debug=True)
