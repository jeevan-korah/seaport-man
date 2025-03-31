from flask import Blueprint, request, jsonify, session
import pymysql
from database import get_db_connection

port_operations_bp = Blueprint('port_operations', __name__)

@port_operations_bp.route('/', methods=['POST'])
def add_operation():
    if 'loggedin' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    connection = get_db_connection()
    with connection.cursor() as cursor:
        cursor.execute('INSERT INTO port_operations (operation_type, details) VALUES (%s, %s)', 
                       (data['operation_type'], data['details']))
        connection.commit()
    connection.close()
    return jsonify({"message": "Operation logged successfully"})

@port_operations_bp.route('/', methods=['GET'])
def get_operations():
    connection = get_db_connection()
    with connection.cursor() as cursor:
        cursor.execute('SELECT * FROM port_operations')
        operations = cursor.fetchall()
    connection.close()
    return jsonify(operations)
