import pyodbc
import bcrypt
from config import DATABASE_CONFIG

def create_connection():
    connection_string = f"DRIVER={{{DATABASE_CONFIG['DRIVER']}}};SERVER={{{DATABASE_CONFIG['SERVER']}}};DATABASE={{{DATABASE_CONFIG['DATABASE']}}};UID={{{DATABASE_CONFIG['USERNAME']}}};PWD={{{DATABASE_CONFIG['PASSWORD']}}};"
    return pyodbc.connect(connection_string)

def execute_query(query, params=None, fetch_results=True):
    connection = create_connection()
    cursor = connection.cursor()

    try:
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)

        if fetch_results:
            result = cursor.fetchall()
            return result
    except Exception as e:
        connection.rollback()
        raise e
    finally:
        cursor.close()
        connection.commit()
        connection.close()

    return None

def add_user(username, full_password, full_name):
    hashed_password = bcrypt.hashpw(full_password.encode('utf-8'), bcrypt.gensalt())
    query = "INSERT INTO Users (Username, FullPassword, FullName) VALUES (?, ?, ?)"
    params = (username, hashed_password.decode('utf-8'), full_name)
    execute_query(query, params, fetch_results=False)

def add_password_substring(user_id, substring):
    query = "INSERT INTO PasswordSubstrings (UserID, Substring1) VALUES (?, ?)"
    params = (user_id, substring)
    execute_query(query, params, fetch_results=False)