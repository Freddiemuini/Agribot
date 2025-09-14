from flask import Flask, request, jsonify, url_for
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import requests
import os
from requests.exceptions import JSONDecodeError
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from flask_mail import Mail, Message
from datetime import timedelta
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)

# ===== DATABASE SETUP =====
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(BASE_DIR, "users.db")

app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# ===== JWT CONFIG =====
app.config["JWT_SECRET_KEY"] = "super-secret-key"  # ⚠️ Change in production
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
jwt = JWTManager(app)

# ===== MAIL CONFIG =====
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "freddymuini@gmail.com"
app.config["MAIL_PASSWORD"] = "vvkenhdxprvvqfwm"  # Gmail App Password
app.config["MAIL_DEFAULT_SENDER"] = ("AgriBot", "freddymuini@gmail.com")
mail = Mail(app)

# ===== TOKEN SERIALIZER =====
serializer = URLSafeTimedSerializer(app.config["JWT_SECRET_KEY"])

# ===== USER MODEL =====
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)

# ===== DISEASE MODEL =====
class Disease(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    crop = db.Column(db.String(50), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    organic = db.Column(db.Text)
    chemical = db.Column(db.Text)
    prevention = db.Column(db.Text)
    details = db.Column(db.Text)

    def to_dict(self):
        return {
            "id": self.id,
            "crop": self.crop,
            "name": self.name,
            "description": self.description,
            "organicSolutions": self.organic.split(",") if self.organic else [],
            "chemicalSolutions": self.chemical.split(",") if self.chemical else [],
            "prevention": self.prevention.split(",") if self.prevention else [],
            "details": self.details
        }

# ===== CREATE TABLES =====
with app.app_context():
    db.create_all()

# ===== API KEYS =====
AGROMONITORING_API_KEY = "4f84c6035c447f4c14faf4ac0f2f1a06"
ROBOFLOW_API_KEY = "ctkt12G5XN3jQUlLIiIk"
ROBOFLOW_MODEL_ID = "crop-disease-2rilx"
ROBOFLOW_MODEL_VERSION = "4"

@app.route('/')
def home():
    return "<h1>Crop Bot API with Auth, JWT, DB, Email, Weather & Roboflow AI is running!</h1>"

# ========== AUTH ENDPOINTS ==========
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    if not name or not email or not password:
        return jsonify({"error": "All fields (name, email, password) are required"}), 400

    if User.query.filter_by(email=email.lower()).first():
        return jsonify({"error": "User already exists"}), 400

    hashed_password = generate_password_hash(password, method="pbkdf2:sha256")

    new_user = User(
        name=name,
        email=email.lower(),
        password=hashed_password
    )
    db.session.add(new_user)
    db.session.commit()

    try:
        msg = Message(
            subject="Welcome to AgriBot 🌱",
            recipients=[email],
            body=f"Hello {name},\n\n"
                 f"Welcome to AgriBot! 🎉\n\n"
                 "You can now log in and start identifying crop diseases, "
                 "getting prevention tips, and weather insights.\n\n"
                 "Happy Farming!\n\n- AgriBot Team"
        )
        mail.send(msg)
    except Exception as e:
        print("Email sending failed:", str(e))
        return jsonify({"message": "Signup successful, but email sending failed."}), 201

    return jsonify({"message": "Signup successful, welcome email sent!"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    user = User.query.filter_by(email=email.lower()).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({"error": "Invalid email or password"}), 401

    access_token = create_access_token(identity=user.email)
    return jsonify({
        "message": "Login successful",
        "access_token": access_token,
        "user": {"name": user.name, "email": user.email}
    }), 200

# ========== PASSWORD RESET ==========
@app.route('/reset-password-request', methods=['POST'])
def reset_password_request():
    data = request.get_json()
    email = data.get("email")

    if not email:
        return jsonify({"error": "Email is required"}), 400

    user = User.query.filter_by(email=email.lower()).first()
    if not user:
        return jsonify({"error": "No account found with this email"}), 404

    token = serializer.dumps(email.lower(), salt="password-reset-salt")
    reset_link = url_for('reset_password_confirm', token=token, _external=True)

    try:
        msg = Message(
            subject="AgriBot Password Reset 🔑",
            recipients=[email],
            body=f"Hello {user.name},\n\n"
                 f"We received a request to reset your password.\n\n"
                 f"Click the link below to reset it:\n{reset_link}\n\n"
                 f"This link is valid for 30 minutes.\n\n"
                 f"If you didn't request this, you can ignore this email."
        )
        mail.send(msg)
    except Exception as e:
        print("Password reset email failed:", str(e))
        return jsonify({"error": "Failed to send reset email"}), 500

    return jsonify({"message": "Password reset link sent to your email."}), 200

@app.route('/reset-password-confirm/<token>', methods=['POST'])
def reset_password_confirm(token):
    try:
        email = serializer.loads(token, salt="password-reset-salt", max_age=1800)
    except SignatureExpired:
        return jsonify({"error": "The reset link has expired"}), 400
    except BadSignature:
        return jsonify({"error": "Invalid reset link"}), 400

    data = request.get_json()
    new_password = data.get("new_password")

    if not new_password:
        return jsonify({"error": "New password is required"}), 400

    user = User.query.filter_by(email=email.lower()).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    user.password = generate_password_hash(new_password, method="pbkdf2:sha256")
    db.session.commit()

    return jsonify({"message": "Password has been reset successfully"}), 200

# ========== ROBOFLOW DISEASE PREDICTION ==========
@app.route("/predict-disease", methods=["POST"])
@jwt_required()
def predict_disease():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]

    try:
        response = requests.post(
            f"https://detect.roboflow.com/{ROBOFLOW_MODEL_ID}/{ROBOFLOW_MODEL_VERSION}",
            params={"api_key": ROBOFLOW_API_KEY},
            files={"file": file.read()},
            timeout=30
        )
        response.raise_for_status()
        return jsonify(response.json()), 200
    except requests.exceptions.HTTPError as e:
        return jsonify({"error": f"Roboflow API HTTP Error: {e.response.status_code} - {e.response.text}"}), e.response.status_code
    except Exception as e:
        return jsonify({"error": f"Roboflow API failed: {str(e)}"}), 500

# ========== ANALYZE ENDPOINT ==========
@app.route('/analyze', methods=['POST'])
@jwt_required()
def analyze():
    file = request.files.get("file")
    lat = request.form.get("lat")
    lon = request.form.get("lon")

    if not file:
        return jsonify({"error": "Image file is required"}), 400
    if not lat or not lon:
        return jsonify({"error": "Latitude and Longitude are required"}), 400

    current_user = get_jwt_identity()

    # Weather API
    try:
        weather_url = f"http://api.agromonitoring.com/agro/1.0/weather?lat={lat}&lon={lon}&appid={AGROMONITORING_API_KEY}"
        weather_response = requests.get(weather_url, timeout=15)
        weather_response.raise_for_status()
        weather_data = weather_response.json()

        weather_description = weather_data.get('weather', [{}])[0].get('description', 'Unknown')
        temp_kelvin = weather_data.get('main', {}).get('temp')
        temp_celsius = temp_kelvin - 273.15 if temp_kelvin else 'Unknown'
    except Exception as e:
        return jsonify({"error": f"Weather API failed: {str(e)}"}), 500

    # Roboflow Disease Detection
    file.seek(0)  # Reset file pointer to the beginning of the file
    
    try:
        response = requests.post(
            f"https://detect.roboflow.com/{ROBOFLOW_MODEL_ID}/{ROBOFLOW_MODEL_VERSION}",
            params={"api_key": ROBOFLOW_API_KEY},
            files={"file": file.read()},
            timeout=30
        )
        response.raise_for_status()
        rf_result = response.json()

        if "predictions" in rf_result and len(rf_result["predictions"]) > 0:
            prediction = rf_result["predictions"][0]
            disease_name = prediction.get("class", "Unknown Disease")
            disease_details = str(prediction)
        else:
            disease_name = "Unknown Disease"
            disease_details = "No predictions from model."
    except requests.exceptions.HTTPError as e:
        return jsonify({"error": f"Roboflow API HTTP Error: {e.response.status_code} - {e.response.text}"}), e.response.status_code
    except Exception as e:
        return jsonify({"error": f"Roboflow API failed: {str(e)}"}), 500

    recommendation = "Not suitable for planting"
    if temp_celsius != 'Unknown' and isinstance(temp_celsius, (int, float)) and temp_celsius > 17:
        recommendation = "Suitable for planting"

    result = {
        "user": current_user,
        "location": f"{lat},{lon}",
        "recommendation": recommendation,
        "weather": weather_description,
        "temperature_celsius": round(temp_celsius, 2) if isinstance(temp_celsius, (int, float)) else temp_celsius,
        "diseaseName": disease_name,
        "diseaseDescription": "Identified using Roboflow AI",
        "details": disease_details
    }
    return jsonify(result), 200

# ========== ADMIN ENDPOINT ==========
@app.route('/add-disease', methods=['POST'])
def add_disease():
    data = request.get_json()
    required = ["crop", "name", "description"]
    if not all(field in data for field in required):
        return jsonify({"error": "crop, name, description are required"}), 400

    new_disease = Disease(
        crop=data["crop"].lower(),
        name=data["name"],
        description=data["description"],
        organic=",".join(data.get("organic", [])),
        chemical=",".join(data.get("chemical", [])),
        prevention=",".join(data.get("prevention", [])),
        details=data.get("details", "")
    )
    db.session.add(new_disease)
    db.session.commit()

    return jsonify({"message": "Disease added successfully"}), 201

if __name__ == '__main__':
    app.run(debug=True)