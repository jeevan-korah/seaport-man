from flask import Blueprint, request, jsonify, session
import pymysql
from database import get_db_connection

ships_bp = Blueprint('ships', __name__)

@ships_bp.route('/', methods=['POST'])  # '/' instead of '/ships'
def add_ship():
    if 'loggedin' not in session or not session['loggedin']:
        return jsonify({"error": "Unauthorized. Please log in to add ship."}), 401

    data = request.json
    connection = get_db_connection()
    with connection.cursor() as cursor:
        cursor.execute('INSERT INTO ships (ship_name, captain, capacity, status) VALUES (%s, %s, %s, %s)', 
                       (data['ship_name'], data['captain'], data['capacity'], data['status']))
        connection.commit()
    connection.close()
    return jsonify({"message": "Ship added successfully"})

@ships_bp.route('/', methods=['GET'])
def get_ships():
    # if 'loggedin' not in session:
    #     return jsonify({"error": "Unauthorized"}), 401
    
    connection = get_db_connection()
    with connection.cursor() as cursor:
        cursor.execute('SELECT * FROM ships')
        ships = cursor.fetchall()
    connection.close()
    return jsonify(ships)
