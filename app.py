import datetime
import random
import time
import re
from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session, make_response
from database import execute_query, add_user, add_card, add_document, add_subpasswords, add_transaction, update_subpasswords, get_card_number, get_document_number
import bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import timedelta, datetime
from flask_limiter import Limiter, RateLimitExceeded
from flask_limiter.util import get_remote_address
from config import APP_KEY
from flask_wtf.csrf import CSRFProtect


app = Flask(__name__)
app.secret_key = APP_KEY['KEY']
csrf = CSRFProtect(app)

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

login_manager = LoginManager(app)
login_manager.login_view = 'enter_username'

limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://"  # TODO
)


class User(UserMixin):
    def __init__(self, user_id, username):
        self.id = user_id
        self.username = username


@login_manager.user_loader
def load_user(user_id):
    user_result = execute_query(
        "SELECT UserID, Username FROM Users WHERE UserID = ?", (user_id,))
    if user_result:
        user_id, username = user_result[0]
        return User(user_id, username)
    return None


def no_cache(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


def clean_flashes():
    session.pop('_flashes', None)

@app.route('/')
@limiter.limit('10 per minute')
@login_required
def home():
    result = execute_query("SELECT * FROM Transactions WHERE UserID = ?", (current_user.id))
    balance_result = execute_query("SELECT Balance FROM Users WHERE UserID = ?", (current_user.id))
    balance = balance_result[0][0]
    session['user_info']['balance'] = balance
    response = make_response(render_template('index.html', data=result, balance = balance))
    return no_cache(response)


@app.route('/login', methods=['GET', 'POST'])
def enter_username():

    if request.method == 'POST':
        username = request.form['username']

        time.sleep(2)

        return redirect(url_for('enter_password', username=username))

    response = make_response(render_template('enter_username.html'))
    return no_cache(response)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('enter_username'))


@app.route('/account')
@login_required
def account():
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

    return render_template('account.html')


@app.errorhandler(429)
def ratelimit_handler(e):
    flash('Too many attempts. Try again later', 'error')
    return redirect(url_for('enter_username'))


@app.route('/login/<username>', methods=['GET', 'POST'])
@limiter.limit('10 per minute')
def enter_password(username):
    session.setdefault('failed_login_attempts', 0)
    if request.method == 'GET':
        time.sleep(2)
        user_result = execute_query(
            "SELECT UserID, NumberOfPasswordCombinations FROM Users WHERE Username = ?", (username,))
        if user_result:
            user_id, num_password_combinations = user_result[0]
            combination_index, enabled_positions = get_random_combination(
                num_password_combinations)
        else:
            combination_index, enabled_positions = get_random_combination(15)

        session['combination_index'] = combination_index
        session['enabled_positions'] = enabled_positions
        response = make_response(render_template(
            'enter_password.html', username=username, enabled_positions=enabled_positions))
        return no_cache(response)

    elif request.method == 'POST':
        enabled_positions = session.get('enabled_positions')
        if not enabled_positions:
            flash('Session error. Please try again', 'error')
            return redirect(url_for('enter_username'))
        entered_password = ''.join(
            [request.form.get(f'char{i}') for i in enabled_positions])
        time.sleep(2)
        user_result = execute_query(
            "SELECT UserID, Username, Status, NumberOfFailedLogins, LastFailedLoginTime FROM Users WHERE Username = ?", (username,))
        if user_result:
            user_id, username, status, num_failed_logins, last_failed_time = user_result[0]

            if status in ['Suspended', 'Blocked']:
                time_difference = datetime.now() - last_failed_time
                suspension_time = timedelta(
                    hours=1) if status == 'Suspended' else timedelta(days=1)

                if time_difference < suspension_time:
                    execute_query("UPDATE Users SET LastFailedLoginTime = ? WHERE UserID = ?", (
                        datetime.now(), user_id), fetch_results=False)
                    flash(
                        'Login attempt failed. Please try again or come back later', 'error')
                    return redirect(url_for('enter_username'))

            combination_index = session.get('combination_index')
            if not combination_index:
                flash('Session error. Please try again.', 'error')
                return redirect(url_for('enter_username'))

            hashed_substring_result = execute_query(
                f"SELECT SubPassword{combination_index} FROM SubPasswords WHERE UserID = ?", (user_id,))
            hashed_substring = hashed_substring_result[0][0]

            is_valid_password = bcrypt.checkpw(entered_password.encode(
                'utf-8'), hashed_substring.encode('utf-8'))

            if is_valid_password:
                execute_query(
                    "UPDATE Users SET NumberOfFailedLogins = 0, LastFailedLoginTime = NULL, Status = 'Active' WHERE UserID = ?", (user_id,), fetch_results=False)
                user_result = execute_query(
                    "SELECT Balance, FirstName, LastName, AccountNumber, CardNumberLastDigits, DocumentNumberFirstLastChars FROM Users WHERE UserID = ?", (user_id,))
                if user_result:
                    balance, first_name, last_name, account_number, card_last_digits, document_digits = user_result[0]
                    session['user_info'] = {'balance': balance, 'first_name': first_name, 'last_name': last_name,
                                            'account_number': account_number, 'card_last_digits': card_last_digits, 'document_digits': document_digits}
                user = User(user_id, username)
                login_user(user)
                session.permanent = False
                return redirect(url_for('home'))
            else:
                num_failed_logins += 1
                execute_query("UPDATE Users SET NumberOfFailedLogins = ?, LastFailedLoginTime = ? WHERE UserID = ?",
                              (num_failed_logins, datetime.now(), user_id), fetch_results=False)
                if num_failed_logins == 3:
                    execute_query(
                        "UPDATE Users SET Status = 'Suspended' WHERE UserID = ?", (user_id,), fetch_results=False)
                    flash(
                        'Too many wrong logins. Please try again in an hour. Every try before that will only restart the timer', 'error')
                    return redirect(url_for('enter_username'))
                elif num_failed_logins == 6:
                    execute_query(
                        "UPDATE Users SET Status = 'Blocked' WHERE UserID = ?", (user_id,), fetch_results=False)
                    flash('Too many wrong logins. From now on you have 1 attempt every 24 hours. Every try before that will only restart the timer', 'error')
                    return redirect(url_for('enter_username'))
                else:
                    flash('Invalid password', 'error')
        else:
            session['failed_login_attempts'] += 1
            if (session['failed_login_attempts'] == 3):
                flash(
                    'Too many wrong logins. Please try again in an hour. Every try before that will only restart the timer', 'error')
                return redirect(url_for('enter_username'))
            elif (session['failed_login_attempts'] > 3):
                flash(
                    'Login attempt failed. Please try again or come back later', 'error')
                return redirect(url_for('enter_username'))
            else:
                flash('Invalid password', 'error')

    response = make_response(render_template(
        'enter_password.html', username=username, enabled_positions=enabled_positions))
    return no_cache(response)


def get_password_combinations_by_length(password_length):
    base_combinations = {
        8: [[0, 2, 3, 6], [0, 2, 4, 6], [1, 3, 4, 6], [1, 2, 4, 6], [0, 1, 3, 6]],
        9: [[1, 3, 6, 7], [0, 2, 3, 6, 7]],
        10: [[0, 2, 4, 6, 7], [1, 3, 6, 7, 8]],
        11: [[0, 1, 4, 6, 8]],
        12: [[2, 3, 6, 8, 9]],
        13: [[0, 2, 3, 7, 8, 11]],
        14: [[1, 2, 4, 6, 8, 11]],
        15: [[0, 1, 3, 6, 9, 11]],
        16: [[2, 4, 7, 8, 10, 11]]
    }
    combinations = []
    for length in range(8, password_length + 1):
        combinations.extend(base_combinations.get(length, []))

    return combinations


def get_password_combinations_all():
    base_combinations = {
        8: [[1, 3, 4, 7], [1, 3, 5, 7], [2, 4, 5, 7], [2, 3, 5, 7], [1, 2, 4, 7]],
        9: [[2, 4, 7, 8], [1, 3, 4, 7, 8]],
        10: [[1, 3, 5, 7, 8], [2, 4, 7, 8, 9]],
        11: [[1, 2, 5, 7, 9]],
        12: [[3, 4, 7, 9, 10]],
        13: [[1, 3, 4, 8, 9, 12]],
        14: [[2, 3, 5, 7, 9, 12]],
        15: [[1, 2, 4, 7, 10, 12]],
        16: [[3, 5, 8, 9, 11, 12]]
    }
    return base_combinations


def get_random_combination(number_of_combinations):
    combinations = []
    for lenght, combo_list in get_password_combinations_all().items():
        if len(combinations) < number_of_combinations:
            combinations.extend(combo_list)
        else:
            break

    if not combinations:
        return []

    random_index = random.randint(0, len(combinations) - 1)
    return random_index+1, combinations[random_index]


@app.route('/new_transaction', methods=['GET', 'POST'])
@limiter.limit('5 per minute')
@login_required
def new_transaction():
    if request.method == 'POST':
        amount = float(request.form['amount'])
        title = request.form['title']
        other_side_name = request.form['other_side_name']
        other_side_account_number = request.form['other_side_account_number']
        entered_password = request.form['password']

        status, data = validate_transaction_input(
            current_user.id, amount, title, other_side_name, other_side_account_number)
        if not status:
            flash(data, 'error')
            return redirect(url_for('new_transaction'))
        else:
            session['pending_transaction'] = {
                'amount': data[0],
                'title': data[1],
                'other_side_name': data[2],
                'other_side_account_number': data[3]
            }
            confirm_transaction(entered_password)

    response = make_response(render_template('new_transaction.html'))
    return no_cache(response)


def validate_transaction_input(user_id, amount, title, other_side_name, other_side_account_number):
    if not amount:
        return False, 'Ammount can not be empty'
    try:
        amount = float(amount)
        if amount == 0:
            return False, "Amount can't be zero"
        elif amount < 0:
            return False, "Amount can't be negative"
        elif not has_sufficient_balance(user_id, abs(amount)):
            return False, 'Insufficient balance for the debit transaction'
    except ValueError:
        return False, 'Invalid amount. Use period, commas and whitespaces'

    title = re.sub(r'[^a-zA-z,. ]', '', title)
    if not title:
        return False, 'Title cannot be empty or contain anything but letters, commas and dots'

    other_side_name = re.sub(r'[^a-zA-z ]', '', other_side_name)
    if not other_side_name:
        return False, "Other side's name cannot be empty."
    
    other_side_account_number = re.sub(r'[^0-9]', '', other_side_account_number)
    if not other_side_account_number.isdigit() or len(other_side_account_number) != 18:
        return False, "Invalid other side's account number format. It should contain 18 digits and additional whitespaces"

    return True, (amount, title, other_side_name, other_side_account_number)


def has_sufficient_balance(user_id, amount):
    result = execute_query(
        "SELECT Balance FROM Users WHERE UserID = ?", (user_id,))
    if result and result[0][0] >= amount:
        return True
    return False


def confirm_transaction(entered_password):
    session.setdefault('failed_confirm_attempts', 0)
    if not is_valid_password(current_user.id, entered_password):
        flash('Invalid password. Please try again', 'error')
        session['failed_confirm_attempts'] += 1

        if session['failed_confirm_attempts'] >= 3:
            flash('Too many incorrect password attempts. Transaction canceled', 'error')
            session['failed_confirm_attempts'] = 0
            return redirect(url_for('home'))

        return redirect(url_for('new_transaction'))

    session['failed_confirm_attempts'] = 0

    transaction_data = session.get('pending_transaction')
    if transaction_data:
        error_message = perform_transaction(
            current_user.id, **transaction_data)
        if error_message:
            flash(error_message, 'error')
            session.pop('pending_transaction', None)
        else:
            flash('Transaction successful!', 'success')
            session.pop('pending_transaction', None)
    else:
        flash('Transaction data not found.', 'error')

    return redirect(url_for('new_transaction'))


def is_valid_password(user_id, entered_password):
    hashed_password_result = execute_query(
        "SELECT HashedPassword FROM Users WHERE UserID = ?", (user_id,))
    if hashed_password_result:
        hashed_password = hashed_password_result[0][0]
        return bcrypt.checkpw(entered_password.encode('utf-8'), hashed_password.encode('utf-8'))
    return False


def perform_transaction(user_id, amount, title, other_side_name, other_side_account_number):
    user_account = execute_query(
        'SELECT AccountNumber, Balance, FirstName, LastName From Users WHERE UserID = ?', (user_id))
    user_account_number, user_balance, user_first_name, user_last_name = user_account[0]
    user_balance = float(user_balance)
    if other_side_account_number.startswith("88"):
        other_side_result = execute_query(
            "SELECT UserID, Balance FROM Users WHERE AccountNumber = ?", (other_side_account_number,))
        if other_side_result:
            other_side_user_id, other_side_balance = other_side_result[0]
            other_side_balance = float(other_side_balance)
            add_transaction(other_side_user_id, amount, title,
                            user_first_name + " " + user_last_name, user_account_number)
            execute_query("UPDATE Users SET Balance = ? WHERE UserID = ?",
                          (other_side_balance + amount, other_side_user_id), fetch_results=False)
    
    #Tu placeholder na obsługę żądań do innych banków lub obsługę jeżeli konta takiego nie ma. Nie chcę tego sprawdzać odrazu i dawać znać, bo jakoś niebezpiecznie brzmi
        #Ja zakładam, że jak jest inny bank lub błąd to to musi gdzieś się księgować i tylko potem odsyłać/zwracać. Ale nie wiem jak to zrobić
    add_transaction(user_id, -amount, title, other_side_name,
                    other_side_account_number)
    execute_query("UPDATE Users SET Balance = ? WHERE UserID = ?",
                  (user_balance - amount, user_id), fetch_results=False)

    return None

@app.route('/change_password', methods=['POST'])
@limiter.limit('5 per minute')
@login_required
def change_password():

    user_id = current_user.id
    old_password = request.form.get('old_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if new_password != confirm_password:
        flash('New passwords do not match', 'error')
        return redirect(url_for('account'))
    
    if not is_strong_password(new_password):
        flash('Password is not strong enough. It must contain 8 to 16 characters, including a digit, an uppercase letter, a lowercase letter, and a special character', 'error')
        return redirect(url_for('account'))

    user_details = execute_query('SELECT LastPasswordChangedTime FROM Users WHERE UserID = ?', (user_id,))
    if not user_details:
        flash('User not found', 'error')
        return redirect(url_for('account'))
    
    last_password_changed = user_details[0][0]
    
    if last_password_changed and datetime.utcnow() - last_password_changed < timedelta(days=3):
        flash('You can only change your password every 3 days', 'error')
        return redirect(url_for('account'))
    
    if not is_valid_password(user_id, old_password):
        flash('Incorrect password.', 'error')
        return redirect(url_for('account'))
    
    password_update(user_id, new_password)

    flash('Password successfully changed', 'success')
    return redirect(url_for('account'))

def is_strong_password(password):
    if (len(password) < 8) | (len(password) > 16):
        return False

    if not re.search(r"\d", password):
        return False

    if not re.search(r"[A-Z]", password):
        return False

    if not re.search(r"[a-z]", password):
        return False

    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False

    return True

def password_update(user_id, new_password):
    number_of_password_combinations = 5 + len(new_password) - 8 if len(new_password) > 8 else 5
    new_hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    execute_query('UPDATE Users SET HashedPassword = ?, LastPasswordChangedTime = ?, NumberOfPasswordCombinations = ? WHERE UserID = ?', (new_hashed_password, datetime.utcnow(), number_of_password_combinations, user_id), fetch_results=False)

    password_combinations = get_password_combinations_by_length(
        len(new_password))
    hashed_substrings = []
    for combo in password_combinations:
        substring = ''.join(new_password[i] for i in combo)
        hashed_substring = bcrypt.hashpw(substring.encode(
            'utf-8'), bcrypt.gensalt()).decode('utf-8')
        hashed_substrings.append(hashed_substring)
    update_subpasswords(user_id, hashed_substrings)

@app.route('/get_full_card_number', methods=['POST'])
@login_required
def get_full_card_number():
    password_data = request.get_json()
    entered_password = password_data.get('password')
    
    user_id = current_user.id
    if is_valid_password(user_id, entered_password):
        full_card_number = get_card_number(user_id)
        if full_card_number:
            return jsonify(result='success', full_card_number=full_card_number)
        else:
            return jsonify(result='error', message='Database error. Try again later')
    else:
        return jsonify(result='error', message='Incorrect password')
    
@app.route('/get_full_document_number', methods=['POST'])
@login_required
def get_full_document_number():
    password_data = request.get_json()
    entered_password = password_data.get('password')
    
    user_id = current_user.id
    if is_valid_password(user_id, entered_password):
        full_document_number = get_document_number(user_id)
        if full_document_number:
            return jsonify(result='success', full_document_number=full_document_number)
        else:
            return jsonify(result='error', message='Database error. Try again later')
    else:
        return jsonify(result='error', message='Incorrect password')

if __name__ == '__main__':
    app.run(debug=True)
