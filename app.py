from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_session import Session
from routes.auth import auth_bp
from routes.cargo import cargo_bp
from routes.resources import resources_bp
from routes.ships import ships_bp
from routes.port_operations import port_operations_bp
from database import create_tables
import os

# Initialize Flask App
app = Flask(__name__)

# Configure CORS to allow credentials and handle preflight requests
CORS(app, supports_credentials=True, resources={r"/*": {"origins": "http://127.0.0.1:5500"}})

# Configure Session Management
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Register Blueprints (APIs)
app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(cargo_bp, url_prefix='/cargo')
app.register_blueprint(resources_bp, url_prefix='/resources')
app.register_blueprint(ships_bp, url_prefix='/ships')
app.register_blueprint(port_operations_bp, url_prefix='/operations')

# Database Initialization
with app.app_context():
    create_tables()

# Define Routes
@app.route('/')
def home():
    return jsonify({"message": "Welcome to the Seaport Cargo Management API"}), 200

# Handle Preflight Requests
@app.before_request
def handle_options_request():
    if request.method == "OPTIONS":
        response = app.make_default_options_response()
        headers = response.headers

        # Add CORS headers
        headers["Access-Control-Allow-Origin"] = "http://127.0.0.1:5500"
        headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        headers["Access-Control-Allow-Headers"] = "Content-Type"
        headers["Access-Control-Allow-Credentials"] = "true"

        return response

# Error Handlers
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({"error": "Resource not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

# Run Flask App
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))