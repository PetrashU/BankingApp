from flask import Flask, render_template, request, redirect, url_for, flash
from database import execute_query, add_user, add_password_substring
import bcrypt

app = Flask(__name__)
app.secret_key = 'your_very_secret_key_here'  # TODO change


@app.route('/')
def home():
    result = execute_query("SELECT * FROM Users")
    return render_template('index.html', data=result)


@app.route('/add_user', methods=['GET', 'POST'])
def add_user_page():
    if request.method == 'POST':
        username = request.form['username']
        full_password = request.form['password']
        full_name = request.form['full_name']

        add_user(username, full_password, full_name)

        user_id_result = execute_query("SELECT UserID FROM Users WHERE Username = ?", (username,))
        user_id = user_id_result[0][0] if user_id_result else None

        password_length = len(full_password)
        substring_1 = ''.join([full_password[i] for i in [0, 2, 3, 6]])
        hashed_substring_1 = bcrypt.hashpw(substring_1.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        add_password_substring(user_id, hashed_substring_1)

        return redirect(url_for('home'))

    return render_template('add_user.html')

@app.route('/enter_username', methods=['GET', 'POST'])
def enter_username():
    if request.method == 'POST':
        username = request.form['username']

        user_exists = execute_query("SELECT 1 FROM Users WHERE Username = ?", (username,))

        if user_exists:
            return redirect(url_for('enter_password', username=username))
        else:
            flash('Invalid username. Please try again.', 'error')

    return render_template('enter_username.html')

@app.route('/enter_password/<username>', methods=['GET', 'POST'])
def enter_password(username):
    enabled_positions = [1,3,4,7]
    if request.method == 'POST':
        entered_password = ''.join([request.form.get(f'char{i}') for i in enabled_positions])

        user_id_result = execute_query("SELECT UserID FROM Users WHERE Username = ?", (username,))
        user_id = user_id_result[0][0] if user_id_result else None

        if user_id:
            hashed_substrings_result = execute_query("SELECT Substring1 FROM PasswordSubstrings WHERE UserID = ?", (user_id,))
            hashed_substrings = [row[0] for row in hashed_substrings_result]

            is_valid_password = any(bcrypt.checkpw(entered_password.encode('utf-8'), hashed_substring.encode('utf-8')) for hashed_substring in hashed_substrings)

            if is_valid_password:
                flash('Password is valid. Access granted!', 'success')
                return redirect(url_for('home'))
            else:
                flash('Invalid password. Please try again.', 'error')
        else:
            flash('Invalid username. Access denied.', 'error')
            return redirect(url_for('enter_username'))

    return render_template('enter_password.html', username=username, enabled_positions=enabled_positions)

if __name__ == '__main__':
    app.run(debug=True)
