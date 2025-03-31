from flask import Blueprint, request, jsonify
from database import get_db_connection

resources_bp = Blueprint('resources', __name__)

# Get all resources
@resources_bp.route('/', methods=['GET'])
def get_resources():
    connection = get_db_connection()
    with connection.cursor() as cursor:
        cursor.execute('SELECT * FROM resources')
        resources = cursor.fetchall()
    connection.close()
    return jsonify(resources)

# Add a new resource
@resources_bp.route('/', methods=['POST'])
def add_resource():
    data = request.json
    connection = get_db_connection()
    with connection.cursor() as cursor:
        cursor.execute('INSERT INTO resources (resource_name, availability) VALUES (%s, %s)',
                       (data['resource_name'], data['availability']))
        connection.commit()
    connection.close()
    return jsonify({"message": "Resource added successfully"})
