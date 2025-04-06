from flask import Blueprint, request, jsonify, session
import pymysql
from database import get_db_connection
from werkzeug.security import generate_password_hash, check_password_hash

auth_bp = Blueprint('auth', __name__)

# User Registration
@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    hashed_password = generate_password_hash(password)

    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute('INSERT INTO users (username, password) VALUES (%s, %s)', 
                           (username, hashed_password))
            connection.commit()
        return jsonify({"message": "User registered successfully!"}), 201
    except pymysql.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if connection:
            connection.close()

# User Login
@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute('SELECT id, password FROM users WHERE username = %s', (username,))
            user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):
            session['loggedin'] = True
            session['username'] = username
            session['user_id'] = user['id']  # Store user ID in session
            return jsonify({"message": "Login successful!"})
        else:
            return jsonify({"error": "Invalid username or password"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if connection:
            connection.close()

# Check Session
@auth_bp.route('/check_session', methods=['GET'])
def check_session():
    if 'loggedin' in session:
        return jsonify({"loggedin": True, "username": session.get('username')}), 200
    return jsonify({"loggedin": False}), 401

# User Logout
@auth_bp.route('/logout', methods=['POST'])
def logout():
    session.clear()  # Clear the session
    return jsonify({"message": "Logged out successfully!"}), 200