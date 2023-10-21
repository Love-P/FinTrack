import plaid
import datetime
import json
from datetime import datetime as dt, timedelta
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, Length, EqualTo, Email, ValidationError
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_mail import Mail, Message
from plaid.api import plaid_api
from plaid.model.link_token_create_request import LinkTokenCreateRequest
from plaid.model.link_token_create_request_user import LinkTokenCreateRequestUser
from plaid.model.products import Products
from plaid.model.country_code import CountryCode
from plaid.model.accounts_get_request import AccountsGetRequest
from plaid.model.item_public_token_exchange_request import ItemPublicTokenExchangeRequest
from plaid.model.transactions_sync_request import TransactionsSyncRequest

app = Flask(__name__)

# Secret key that is used to secure a session cookie
app.config['SECRET_KEY'] = ' '
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = ' '
app.config['MAIL_PASSWORD'] = ' '
mail = Mail(app)


# +++++++++++++++++++++++++++++Database++++++++++++++++++++++++++++++++
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    plaid_transaction_id = db.Column(db.String, nullable=False, unique=True)
    name = db.Column(db.String, nullable=False)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.Date, nullable=False)
    category = db.Column(db.String, nullable=True)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    # Existing field for access_token
    plaid_access_token = db.Column(db.String, nullable=True)
    # New field for item_id
    plaid_item_id = db.Column(db.String, nullable=True)
    plaid_sync_cursor = db.Column(db.String, nullable=True)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

    # how object is printed when it's printed out
    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image_file}')"


# +++++++++++++++++++++++++++++++Forms+++++++++++++++++++++++++++++++++++
class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password',
                             validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])

    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError(
                'That username is taken. Please choose a different one')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError(
                'That email is taken. Please choose a different one')


class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password',
                             validators=[DataRequired()])

    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class RequestResetForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError(
                'There is no account with that email. You must resigter first.')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password',
                             validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')


# +++++++++++++++++++++++++++++++Routes+++++++++++++++++++++++++++++++++++
# Home Page - home.html
@app.route('/home')
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(
            form.password.data).decode('utf-8')
        user = User(username=form.username.data,
                    email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash(f'Your account has been created! You can now log in', 'success')
    return render_template('register.html', title='Register', form=form)

# Login Page - login.html


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', title='Login', form=form)


# Main Dashboard - dashboard.html
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    return render_template('dashboard.html', title='Dashboard')


@app.route('/transaction_display', methods=['GET', 'POST'])
def transaction_display():
    return render_template('transaction_display.html', title='Transactions')

# Returns to Login Page - login.html


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    # if current_user.is_authenticated:
    # Clear Plaid data
    # current_user.plaid_access_token = None
    # current_user.plaid_item_id = None
    # current_user.plaid_sync_cursor = None
    # db.session.commit()
    logout_user()
    return redirect(url_for('home'))


@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    return render_template('account.html', title='Account', user=current_user)


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='YOUR_EMAIL_GOES_HERE',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}
If you did not make this request, then simply ignore this email and no change will be made.
'''
    mail.send(msg)


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset password.', 'info')
    return render_template('reset_request.html', title='Reset Password', form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token.', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(
            form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash(f'Your password has been updated! You can now log in', 'success')
    return render_template('reset_token.html', title='Reset Password', form=form)


configuration = plaid.Configuration(
    host=plaid.Environment.Sandbox,
    api_key={
        'clientId': 'YOUR_CLIENT_ID',
        'secret': 'YOUR_SECRET_KEY',
    }
)

api_client = plaid.ApiClient(configuration)
client = plaid_api.PlaidApi(api_client)


@app.route("/create_link_token", methods=['POST'])
# Ensure the user is logged in before they can create a link token.
@login_required
def create_link_token():
    # Get the client_user_id by searching for the current user
    client_user_id = str(current_user.id)
    # Create a link_token for the given user
    request = LinkTokenCreateRequest(
        products=[Products('transactions')],
        client_name="FinTrack",
        country_codes=[CountryCode('US')],
        # redirect_uri='https://domainname.com/oauth-page.html',
        language='en',
        # webhook='https://webhook.example.com',
        user=LinkTokenCreateRequestUser(
            client_user_id=client_user_id
        )
    )
    try:
        response = client.link_token_create(request)
        return jsonify(response.to_dict())
    except plaid.ApiException as e:
        print(e)
        return jsonify({'error': 'Unable to create link token'}), 400


@app.route("/exchange_public_token", methods=['POST'])
@login_required
def exchange_public_token_route():
    public_token = request.json['public_token']

    try:
        exchange_request = ItemPublicTokenExchangeRequest(
            public_token=public_token)
        response = client.item_public_token_exchange(exchange_request)

        # Directly assign the values to the user object
        current_user.plaid_access_token = response.access_token
        current_user.plaid_item_id = response.item_id
        db.session.commit()
    except plaid.ApiException as e:
        db.session.rollback()
        response = json.loads(e.body)
        return jsonify({
            'error': {
                'status_code': e.status,
                'display_message': response.get('error_message', 'Unknown error'),
                'error_code': response.get('error_code', 'Unknown error code'),
                'error_type': response.get('error_type', 'Unknown error type')
            }
        }), 400

    return jsonify({'message': 'Public token exchanged and stored successfully'}), 200


@app.route('/accounts', methods=['GET'])
def get_accounts():
    if current_user.plaid_access_token is None:
        return jsonify({'error': 'No access token found for the user.'}), 400

    try:
        request = AccountsGetRequest(
            access_token=current_user.plaid_access_token)
        accounts_response = client.accounts_get(request)
    except plaid.ApiException as e:
        response = json.loads(e.body)
        return jsonify({
            'error': {
                'status_code': e.status,
                'display_message': response['error_message'],
                'error_code': response['error_code'],
                'error_type': response['error_type']
            }
        })
    return jsonify(accounts_response.to_dict())


def get_latest_cursor_or_none(item_id):
    user = User.query.filter_by(plaid_item_id=item_id).first()
    if user:
        return user.plaid_sync_cursor
    return None


def apply_updates(item_id, added, modified, removed, cursor):
    user = User.query.filter_by(plaid_item_id=item_id).first()
    if user:
        # Update the cursor
        user.plaid_sync_cursor = cursor
        # Handle added, modified, and removed transactions.
        for transaction in added:
            category_as_string = json.dumps(transaction.get(
                'category', []))  # Convert list to JSON string
            existing_transaction = Transaction.query.filter_by(
                plaid_transaction_id=transaction['transaction_id']).first()

            # If the transaction doesn't exist, create a new one.
            if not existing_transaction:
                new_transaction = Transaction(
                    user_id=user.id,
                    plaid_transaction_id=transaction['transaction_id'],
                    name=transaction['name'],
                    amount=transaction['amount'],
                    date=transaction['date'] if isinstance(transaction['date'], datetime.date) else dt.strptime(
                        transaction['date'], '%Y-%m-%d').date(),
                    category=category_as_string
                )
                db.session.add(new_transaction)
            else:
                # Update the existing transaction with new details
                existing_transaction.name = transaction['name']
                existing_transaction.amount = transaction['amount']
                existing_transaction.date = transaction['date'] if isinstance(
                    transaction['date'], datetime.date) else dt.strptime(transaction['date'], '%Y-%m-%d').date()
                existing_transaction.category = category_as_string

        db.session.commit()


start_date = (dt.now() - timedelta(days=30)).strftime('%Y-%m-%d')
end_date = dt.now().strftime('%Y-%m-%d')


@app.route('/transactions', methods=['GET'])
@login_required
def get_transactions():
    if not current_user.plaid_access_token:
        return jsonify({'error': 'No access token found for the user.'}), 400

    try:
        # Use the TransactionsSyncRequest to efficiently sync with Plaid
        cursor = get_latest_cursor_or_none(current_user.plaid_item_id)
        request = TransactionsSyncRequest(
            access_token=current_user.plaid_access_token,
            count=250  # Number of transactions to fetch (change as needed)
        )
        transactions_response = client.transactions_sync(request)
        transactions = transactions_response.to_dict()

        # Apply the updates to your database using the .get() method
        apply_updates(
            current_user.plaid_item_id,
            transactions.get('added'),
            transactions.get('modified'),
            transactions.get('removed'),
            transactions.get('cursor')
        )

        # Return the transactions to the client
        return jsonify(transactions)
    except plaid.ApiException as e:
        response = json.loads(e.body)
        return jsonify({
            'error': {
                'status_code': e.status,
                'display_message': response['error_message'],
                'error_code': response['error_code'],
                'error_type': response['error_type']
            }
        }), 400


# ++++++++++++++++++++++++++++++APP+++++++++++++++++++++++++++++++++++
# If we want to run the application
if __name__ == '__main__':
    app.run(debug=True)
