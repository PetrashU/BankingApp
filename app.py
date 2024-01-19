import time
from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
from database import execute_query, add_user, add_password_substring
import bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import timedelta
from flask_limiter import Limiter, RateLimitExceeded
from flask_limiter.util import get_remote_address


app = Flask(__name__)
app.secret_key = 'your_very_secret_key_here'  # TODO change

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

login_manager = LoginManager(app)
login_manager.login_view = 'enter_username' #TODO change?

limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://" #TODO
)

class User(UserMixin):
    def __init__(self, user_id, username):
        self.id = user_id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    user_result = execute_query("SELECT UserID, Username FROM Users WHERE UserID = ?", (user_id,))
    if user_result:
        user_id, username = user_result[0]
        return User(user_id, username)
    return None

def no_cache(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.route('/')
@login_required
def home():
    result = execute_query("SELECT * FROM Users")
    response = make_response(render_template('index.html', data=result))
    return no_cache(response)


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

@app.route('/login', methods=['GET', 'POST'])
def enter_username():
    
    if request.method == 'POST':
        username = request.form['username']
        
        time.sleep(2)

        return redirect(url_for('enter_password', username=username))
    
    response = make_response(render_template('enter_username.html'))
    return no_cache(response)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('enter_username'))

@app.route('/account')
def account():
    return render_template('account.html')

@app.errorhandler(429)
def ratelimit_handler(e):
    flash('Too many attempts. Try again later.', 'error')
    return redirect(url_for('enter_username'))

@app.route('/login/<username>', methods=['GET', 'POST'])
@limiter.limit('5 per minute')
def enter_password(username):
    enabled_positions = [1, 3, 4, 7]

    if request.method == 'POST':
        entered_password = ''.join([request.form.get(f'char{i}') for i in enabled_positions])

        time.sleep(2)

        user_result = execute_query("SELECT UserID, Username FROM Users WHERE Username = ?", (username,))

        if user_result:
            user_id, username = user_result[0]

            hashed_substrings_result = execute_query("SELECT Substring1 FROM PasswordSubstrings WHERE UserID = ?", (user_id,))
            hashed_substrings = [row[0] for row in hashed_substrings_result]

            is_valid_password = any(bcrypt.checkpw(entered_password.encode('utf-8'), hashed_substring.encode('utf-8')) for hashed_substring in hashed_substrings)

            if is_valid_password:
                user = User(user_id, username)
                login_user(user)
                session.permanent = True

                return redirect(url_for('home'))
            else:
                flash('Invalid password. Please try again.', 'error')
        else:
            flash('Invalid password. Please try again.', 'error')

    response = make_response(render_template('enter_password.html', username=username, enabled_positions=enabled_positions))
    return no_cache(response)


if __name__ == '__main__':
    app.run(debug=True)
