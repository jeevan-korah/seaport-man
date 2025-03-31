from flask import Blueprint, request, jsonify
import pymysql
from database import get_db_connection

cargo_bp = Blueprint('cargo', __name__)

@cargo_bp.route('/', methods=['POST'])
def add_cargo():
    data = request.json  # Get JSON request body
    connection = get_db_connection()
    with connection.cursor() as cursor:
        cursor.execute(
            'INSERT INTO cargo (cargo_name, status, location, arrival_date) VALUES (%s, %s, %s, %s)',
            (data['cargo_name'], data['status'], data['location'], data['arrival_date'])
        )
        connection.commit()
    connection.close()
    return jsonify({"message": "Cargo added successfully"}), 201

@cargo_bp.route('/', methods=['GET'])
def get_cargo():
    connection = get_db_connection()
    with connection.cursor() as cursor:
        cursor.execute('SELECT * FROM cargo')
        cargo = cursor.fetchall()
    connection.close()
    return jsonify(cargo)
