import pyodbc
import bcrypt
from config import DATABASE_CONFIG, AZURE_KEY
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

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

def add_user(username, full_password, first_name, last_name, account_number, balance, card_number_last_digits, document_number_first_last_chars):
    hashed_password = bcrypt.hashpw(full_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    number_of_password_combinations = 5 + len(full_password) - 8 if len(full_password) > 8 else 5

    connection = create_connection()
    cursor = connection.cursor()

    try:
        query = """INSERT INTO Users (Username, HashedPassword, FirstName, LastName, AccountNumber, Balance,
                   CardNumberLastDigits, DocumentNumberFirstLastChars, NumberOfPasswordCombinations, LastPasswordChangedTime) 
                   OUTPUT INSERTED.UserID
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""
        params = (username, hashed_password, first_name, last_name, account_number, balance, card_number_last_digits, 
                  document_number_first_last_chars, number_of_password_combinations, datetime.utcnow())
        cursor.execute(query, params)
        user_id = cursor.fetchone()[0]
        connection.commit()

        return user_id
    except Exception as e:
        connection.rollback()
        raise e
    finally:
        cursor.close()
        connection.close()

def add_transaction(user_id, amount, title, other_side_name, other_side_account_number):
    query = """INSERT INTO Transactions (UserID, Amount, Title, OtherSideName, OtherSideAccountNumber)
    VALUES (?, ?, ?, ?, ?)"""
    execute_query(query, (user_id, amount, title, other_side_name, other_side_account_number), fetch_results=False)

def add_card(user_id, full_card_number):
    encrypted_card_number = encrypt(full_card_number)
    query = "INSERT INTO Cards (UserID, EncryptedCardNumber) VALUES (?, ?)"
    params = (user_id, encrypted_card_number)
    execute_query(query, params, fetch_results=False)

def add_document(user_id, full_document_number):
    encrypted_document_number = encrypt(full_document_number)
    query = "INSERT INTO Documents (UserID, EncryptedDocumentNumber) VALUES (?, ?)"
    params = (user_id, encrypted_document_number)
    execute_query(query, params, fetch_results=False)

def add_subpasswords(user_id, substrings):
    query = """INSERT INTO SubPasswords (UserID, SubPassword1, SubPassword2, SubPassword3, SubPassword4, SubPassword5, SubPassword6, SubPassword7, 
                SubPassword8, SubPassword9, SubPassword10, SubPassword11, SubPassword12, SubPassword13, SubPassword14, SubPassword15) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""
    params = [user_id] + substrings + [None] * (15 - len(substrings))
    execute_query(query, params, fetch_results=False)

def update_subpasswords(user_id, substrings):
    query = """UPDATE SubPasswords 
               SET SubPassword1 = ?, SubPassword2 = ?, SubPassword3 = ?, SubPassword4 = ?, 
                   SubPassword5 = ?, SubPassword6 = ?, SubPassword7 = ?, SubPassword8 = ?, 
                   SubPassword9 = ?, SubPassword10 = ?, SubPassword11 = ?, SubPassword12 = ?, 
                   SubPassword13 = ?, SubPassword14 = ?, SubPassword15 = ? 
               WHERE UserId = ?"""
    params = substrings + [None] * (15 - len(substrings)) + [user_id]
    execute_query(query, params, fetch_results=False)

def encrypt(data):
    iv = get_random_bytes(16)
    cipher = AES.new(AZURE_KEY['KEY'], AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    return iv + encrypted_data

def get_card_number(user_id):
    result = execute_query("SELECT EncryptedCardNumber FROM Cards WHERE UserId = ?", (user_id,))
    if result:
        encrypted_card_number = result[0][0]
        return decrypt(encrypted_card_number)

def get_document_number(user_id):
    result = execute_query("SELECT EncryptedDocumentNumber FROM Documents WHERE UserId = ?", (user_id,))
    if result:
        encrypted_document_number = result[0][0]
        return decrypt(encrypted_document_number)

def decrypt(encrypted_data):
    iv = encrypted_data[:16]
    cipher = AES.new(AZURE_KEY['KEY'], AES.MODE_CBC, iv)
    padded_decrypted_data = cipher.decrypt(encrypted_data[16:])
    decrypted_data = unpad(padded_decrypted_data, AES.block_size)
    return decrypted_data.decode('utf-8')