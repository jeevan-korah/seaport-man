import os
import pymysql


DB_CONFIG = {
    'host': os.getenv('DB_HOST'),
    'port': int(os.getenv('DB_PORT', 3306)),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_NAME')
}
def get_db_connection():
    return pymysql.connect(**DB_CONFIG, cursorclass=pymysql.cursors.DictCursor)

def create_tables():
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(100) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cargo (
            id INT AUTO_INCREMENT PRIMARY KEY,
            cargo_name VARCHAR(255) NOT NULL,
            status VARCHAR(100) NOT NULL,
            location VARCHAR(255) NOT NULL,
            arrival_date DATETIME NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS resources (
            id INT AUTO_INCREMENT PRIMARY KEY,
            resource_name VARCHAR(255) NOT NULL,
            availability BOOLEAN NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ships (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ship_name VARCHAR(255) NOT NULL,
            captain VARCHAR(255) NOT NULL,
            capacity INT NOT NULL,
            status VARCHAR(100) NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS port_operations (
            id INT AUTO_INCREMENT PRIMARY KEY,
            operation_type VARCHAR(255) NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            details TEXT NOT NULL
        )
    ''')

    connection.commit()
    cursor.close()
    connection.close()

if __name__ == "__main__":
    create_tables()