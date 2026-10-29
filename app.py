
from flask import Flask, render_template, request, redirect, url_for, session
import secrets
import time
import os

app = Flask(__name__)

# Set FLASK_SECRET_KEY as an environment variable for deployment.
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "change-this-demo-secret-before-deployment"
)

OTP_VALIDITY = 30
MAX_ATTEMPTS = 5


@app.route("/")
def home():
    otp = session.get("otp")
    generated_at = session.get("generated_at")
    message = session.pop("message", None)
    message_type = session.pop("message_type", "info")

    remaining = 0

    if otp and generated_at:
        remaining = max(
            0,
            OTP_VALIDITY - int(time.time() - generated_at)
        )

        if remaining <= 0:
            session.pop("otp", None)
            session.pop("generated_at", None)
            session.pop("attempts", None)
            otp = None

    return render_template(
        "index.html",
        otp=otp,
        remaining=remaining,
        message=message,
        message_type=message_type,
        verified=session.get("verified", False)
    )


@app.route("/generate", methods=["POST"])
def generate():
    otp = f"{secrets.randbelow(1_000_000):06d}"

    session["otp"] = otp
    session["generated_at"] = time.time()
    session["attempts"] = 0
    session["verified"] = False
    session["message"] = "OTP generated! Enter it below to verify."
    session["message_type"] = "info"

    return redirect(url_for("home"))


@app.route("/verify", methods=["POST"])
def verify():
    saved_otp = session.get("otp")
    generated_at = session.get("generated_at")
    entered_otp = request.form.get("otp", "").strip()

    if session.get("verified"):
        session["message"] = "This OTP has already been verified."
        session["message_type"] = "success"

    elif not saved_otp or not generated_at:
        session["message"] = "Please generate an OTP first."
        session["message_type"] = "error"

    elif time.time() - generated_at >= OTP_VALIDITY:
        session.pop("otp", None)
        session.pop("generated_at", None)
        session.pop("attempts", None)
        session["message"] = "OTP expired. Please generate a new one."
        session["message_type"] = "error"

    elif session.get("attempts", 0) >= MAX_ATTEMPTS:
        session.pop("otp", None)
        session.pop("generated_at", None)
        session.pop("attempts", None)
        session["message"] = "Too many attempts. Generate a new OTP."
        session["message_type"] = "error"

    elif not entered_otp.isdigit() or len(entered_otp) != 6:
        session["message"] = "Enter a valid 6-digit OTP."
        session["message_type"] = "error"

    elif secrets.compare_digest(entered_otp, saved_otp):
        session["verified"] = True
        session.pop("otp", None)
        session.pop("generated_at", None)
        session.pop("attempts", None)
        session["message"] = "OTP verified successfully!"
        session["message_type"] = "success"

    else:
        attempts = session.get("attempts", 0) + 1
        session["attempts"] = attempts

        if attempts >= MAX_ATTEMPTS:
            session.pop("otp", None)
            session.pop("generated_at", None)
            session.pop("attempts", None)
            session["message"] = (
                "Maximum attempts reached. Generate a new OTP."
            )
        else:
            session["message"] = (
                f"Incorrect OTP. Attempts remaining: "
                f"{MAX_ATTEMPTS - attempts}."
            )

        session["message_type"] = "error"

    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=True)
