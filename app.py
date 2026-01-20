import sqlite3
import random
import jwt
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, g
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from dotenv import load_dotenv
import os
import string
import plotly.express as px
from matplotlib.backends.backend_pdf import PdfPages
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import bcrypt
import secrets
import matplotlib.pyplot as plt 
import io 
import matplotlib 
matplotlib.use('Agg')
import seaborn as sns
import base64
import pandas as pd
import matplotlib.dates as mdates
from flask import send_file
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import tempfile
from datetime import datetime, timedelta
from textblob import TextBlob
import re
import plotly.graph_objs as go
import plotly.io as pio
from functools import wraps
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
import joblib
import numpy as np

load_dotenv()  # Load environment variables from .env file

app = Flask(__name__, static_folder='static')
# Use environment variable for secret key in production, fallback for development
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, 'existing_database.db')
JWT_SECRET = os.environ.get('JWT_SECRET', 'your_jwt_secret')  # Use env variable for JWT secret
UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Configuring Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS')

mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

EMAIL_ADDRESS = os.environ.get('EMAIL_ADDRESS')  # Replace with your Gmail address
EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD')  # Replace with your Gmail password
# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = EMAIL_ADDRESS  # Replace with your email
app.config['MAIL_PASSWORD'] = EMAIL_PASSWORD  # Replace with your email password
app.config['MAIL_DEFAULT_SENDER'] = EMAIL_ADDRESS  # Replace with your email
mail = Mail(app)
# Configuring OAuth


# Configuring OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID'),  # Your Google client ID
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),  # Your Google client secret
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile',
        'token_endpoint_auth_method': 'client_secret_basic'
    }
)

facebook = oauth.register(
    name='facebook',
    client_id=os.environ.get('FACEBOOK_CLIENT_ID'),  # Your Facebook client ID
    client_secret=os.environ.get('FACEBOOK_CLIENT_SECRET'),  # Your Facebook client secret
    authorize_url='https://www.facebook.com/dialog/oauth',
    authorize_params=None,
    access_token_url='https://graph.facebook.com/oauth/access_token',
    access_token_params=None,
    refresh_token_url=None,
    redirect_uri='http://127.0.0.1:5000/facebook/callback',  # Your redirect URI
    client_kwargs={
        'scope': 'openid email profile',
        'token_endpoint_auth_method': 'client_secret_basic'
    }
)

twitter = oauth.register(
    name='twitter',
    client_id=os.environ.get('TWITTER_CLIENT_ID'),  # Your Twitter client ID
    client_secret=os.environ.get('TWITTER_CLIENT_SECRET'),  # Your Twitter client secret
    request_token_url='https://api.twitter.com/oauth/request_token',
    authorize_url='https://api.twitter.com/oauth/authenticate',
    access_token_url='https://api.twitter.com/oauth/access_token',
    access_token_params=None,
    redirect_uri='http://localhost:5000/twitter/callback',  # Your redirect URI
    client_kwargs={'scope': 'email'}
)

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def create_token(email):
    payload = {
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload['email']
    except jwt.ExpiredSignatureError:
        return None

# Function to generate a random OTP
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

# Function to send OTP email
def send_otp_email(recipient, otp):
    msg = Message('Your OTP Code', recipients=[recipient])
    msg.body = f'Your OTP code is {otp}'
    msg.sender = app.config['MAIL_DEFAULT_SENDER']  # Ensure sender is specified
    mail.send(msg)

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        contact_info = request.form['contact_info']
        
        # Generate OTP and store it in the session
        otp = generate_otp()
        session['otp'] = otp
        session['contact_info'] = contact_info
        
        # Send OTP to user's email
        send_otp_email(contact_info, otp)
        
        flash('OTP sent to your registered contact.', 'success')
        return redirect(url_for('verify_otp'))
    
    return render_template('forgot.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        verification_code = request.form['verification_code']
        
        # Retrieve the OTP from the session
        stored_otp = session.get('otp')
        
        if verification_code == stored_otp:
            flash('Verification successful!', 'success')
            return redirect(url_for('reset_password'))
        else:
            flash('Invalid verification code. Please try again.', 'error')
            return redirect(url_for('verify_otp'))
    
    return render_template('verify_otp.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not email or not new_password or not confirm_password:
            flash('All fields are required!', 'error')
            return redirect(url_for('reset_password'))

        if new_password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('reset_password'))

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Users WHERE email = ?', (email,))
        user = cursor.fetchone()

        if user:
            hashed_password = hash_password(new_password)
            cursor.execute('UPDATE Users SET password_hash = ? WHERE email = ?', (hashed_password, email))
            conn.commit()
            conn.close()
            flash('Password reset successful. Please sign in.', 'success')
            return redirect(url_for('signin'))
        else:
            conn.close()
            flash('Email not found!', 'error')
            return redirect(url_for('reset_password'))

    return render_template('reset_password.html')


def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8') if isinstance(hashed_password, str) else hashed_password)



@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm-password']
        full_name = request.form['full-name']
        phone_number = request.form['phone-number']

        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('signup'))
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Users WHERE email = ?', (email,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            flash('Email already exists!', 'error')
            return redirect(url_for('signup'))
        
        hashed_password = hash_password(password)
        cursor.execute('INSERT INTO Users (email, password_hash, full_name, phone_number, is_active, is_delivery_boy, is_admin) VALUES (?, ?, ?, ?, ?, ?, ?)',
                       (email, hashed_password, full_name, phone_number, 0, 0, 0))  # Initially inactive
        conn.commit()

        # Send confirmation email
        token = s.dumps(email, salt='email-confirm')
        msg = Message('Confirm your email', sender=os.environ.get('EMAIL_USER'), recipients=[email])
        link = url_for('confirm_email', token=token, _external=True)
        msg.body = f"Hello, welcome to HiFi Eats! Please confirm your email by clicking the link below:\n\n{link}"
        mail.send(msg)
        
        flash('Registration successful! A confirmation email has been sent to your email address.', 'success')
        return redirect(url_for('signin'))
    
    return render_template('signup.html')

# @app.route('/signin', methods=['GET', 'POST'])
# def signin():
#     if request.method == 'POST':
#         email = request.form['phone-email']
#         password = request.form['password']
        
#         conn = get_db()
#         cursor = conn.cursor()
#         cursor.execute('SELECT * FROM Users WHERE email = ?', (email,))
#         user = cursor.fetchone()
        
#         if user and verify_password(password, user['password_hash']):
#             session['user_id'] = user['user_id']
#             session['is_admin'] = user['is_admin']

#             conn.close()
#             flash('Sign in successful', 'success')
#             return redirect(url_for('dashboard'))  # Redirect to the dashboard route
#         else:
#             conn.close()
#             flash('Invalid credentials', 'error')
#             return redirect(url_for('signin'))
#     return render_template('signin.html')

# Dummy promotions for the example
PROMOTIONS = {
    "offers": [
        {
            "id": 1,
            "title": "Welcome Bonus",
            "description": "Get 20% off on your first order!",
            "promo_code": "WELCOME20",
            "discount_amount": 20.0,
            "discount_type": "percentage",
            "valid_from": (datetime.now()).strftime('%Y-%m-%d'),
            "valid_until": (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d'),
            "usage_limit": 1,
            "min_order_amount": 0.0,
            "image_url": "/static/images/welcome.jpg"
        },
        {
            "id": 2,
            "title": "Summer Special",
            "description": "Flat ₹100 off on orders above ₹500",
            "promo_code": "SUMMER100",
            "discount_amount": 100.0,
            "discount_type": "fixed",
            "valid_from": (datetime.now()).strftime('%Y-%m-%d'),
            "valid_until": (datetime.now() + timedelta(days=60)).strftime('%Y-%m-%d'),
            "usage_limit": None,
            "min_order_amount": 500.0,
            "image_url": "/static/images/summer.jpg"
        }
    ]
}

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form['phone-email']
        password = request.form['password']

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        
        if user and verify_password(password, user['password_hash']):
            session.permanent = True  # Set session as permanent
            session['user_id'] = user['user_id']
            session['user'] = user['email']  # Set the user email in session
            session['is_admin'] = user['is_admin']
            session['is_delivery_boy'] = user['is_delivery_boy']
            if not user['is_admin'] and not user['is_delivery_boy']:
                session['is_customer'] = True
            else:
                session['is_customer'] = False
            session['claimed_promotions'] = {}

            conn.close()
            flash('Sign in successful', 'success')
            if user['is_admin']:
                return redirect(url_for('admin_dashboard'))
            elif user['is_delivery_boy']:
                return redirect(url_for('delivery_agent_dashboard',agent_id=user['user_id']))
            else:
                return redirect(url_for('menu', user_id=user['user_id']))
  # Redirect to the promotions page
        else:
            conn.close()
            flash('Invalid credentials', 'error')
            return redirect(url_for('signin'))

    return render_template('signin.html')


# Decorator to check if the user is logged in
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'error')
            return redirect(url_for('signin'))
        return f(*args, **kwargs)
    return decorated_function

def is_admin():
    user_email = session.get('user')
    if not user_email:
        print("No user in session")
        return False
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT is_admin FROM Users WHERE email = ?', (user_email,))
    user = cursor.fetchone()
    conn.close()
    if user:
        print(f"User {user_email} is {'an admin' if user['is_admin'] == 1 else 'not an admin'}")
    return user and user['is_admin'] == 1

def is_delivery_boy():
    user_email = session.get('user')
    if not user_email:
        print("No user in session")
        return False
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT is_delivery_boy FROM Users WHERE email = ?', (user_email,))
    user = cursor.fetchone()
    conn.close()
    if user:
        print(f"User {user_email} is a delivery boy")
        return True
    else:
        return False

def is_customer():
    user_email = session.get('user')
    if not user_email:
        print("No user in session")
        return False
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT is_admin, is_delivery_boy FROM Users WHERE email = ?', (user_email,))
    user = cursor.fetchone()
    conn.close()
    if not user['is_admin'] and not user['is_delivery_boy']:
        print(f"User {user_email} is a customer")
        return True
    else:
        return False

# Function to get active promotions
def get_active_promotions(user_id):
    current_date = datetime.now().strftime('%Y-%m-%d')
    claimed_promos = session.get('claimed_promotions', {})
    
    active_promotions = [
        {**promo, 'is_claimed': str(promo['id']) in claimed_promos}
        for promo in PROMOTIONS['offers']
        if promo['valid_from'] <= current_date <= promo['valid_until']
    ]
    return active_promotions

@app.route('/promotions')
@login_required
def promotions():
    if not is_customer():
        flash('Access denied. Users only.', 'error')
        return redirect(url_for('signin'))
    
    user_id = session['user_id']
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE user_id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    active_promotions = get_active_promotions(user_id)
    claimed_promotions = session.get('claimed_promotions', {})
    return render_template('promotions.html', user=user, promotions=active_promotions, claimed_promotions=claimed_promotions, user_id=user_id)

@app.route('/claim_promotion/<int:promotion_id>')
@login_required
def claim_promotion(promotion_id):
    if 'user' not in session:
        flash('Please log in to claim promotions', 'error')
        return redirect(url_for('signin'))

    user_email = session['user']
    claimed_promos = session.get('claimed_promotions', {})
    
    promotion = next((p for p in PROMOTIONS['offers'] if p['id'] == promotion_id), None)
    
    if not promotion:
        flash('Promotion not found', 'error')
        return redirect(url_for('promotions'))
    
    if str(promotion_id) in claimed_promos:
        flash('You have already claimed this promotion', 'error')
        return redirect(url_for('promotions'))
    
    current_date = datetime.now().strftime('%Y-%m-%d')
    if not (promotion['valid_from'] <= current_date <= promotion['valid_until']):
        flash('This promotion has expired', 'error')
        return redirect(url_for('promotions'))
    
    claimed_promos[str(promotion_id)] = {
        'claimed_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'used': False
    }
    session['claimed_promotions'] = claimed_promos
    
    try:
        msg = Message(
            f"Your Claimed Promotion: {promotion['title']}",
            sender=app.config['MAIL_USERNAME'],
            recipients=[user_email]
        )
        
        discount_text = (
            f"{promotion['discount_amount']}% off" 
            if promotion['discount_type'] == 'percentage'
            else f"₹{promotion['discount_amount']} off"
        )
        
        msg.body = f"""
        Dear {user_email},

        Congratulations! You have successfully claimed the following promotion:

        Promotion Details:
        Title: {promotion['title']}
        Description: {promotion['description']}
        Promo Code: {promotion['promo_code']}
        Discount: {discount_text}
        Minimum Order Amount: ₹{promotion['min_order_amount']}
        Valid Until: {promotion['valid_until']}
        
        To redeem this offer, use the promo code during checkout.

        Thank you for being a valued customer!

        Regards,
        HiFi Eats Team
        """
        
        mail.send(msg)
        flash('Promotion claimed successfully! Check your email for the promo code.', 'success')
    except Exception as e:
        print(f"Error sending email: {e}")
        flash('Promotion claimed but there was an error sending the email. Please contact support.', 'warning')
    
    return redirect(url_for('promotions'))


@app.route('/assign_role/<int:user_id>', methods=['GET', 'POST'])
def assign_role(user_id):
    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'POST':
        role_id = request.form['role']
        
        # Assign role to user
        cursor.execute('UPDATE Users SET role_id = ? WHERE user_id = ?', (role_id, user_id))
        conn.commit()
        conn.close()

        flash('Role assigned successfully.', 'success')
        return redirect(url_for('admin_dashboard'))
    
    else:
        # Retrieve user and role details to populate the form
        cursor.execute('SELECT * FROM Users WHERE user_id = ?', (user_id,))
        user = cursor.fetchone()
        
        cursor.execute('SELECT * FROM roles')
        roles = cursor.fetchall()
        conn.close()

        return render_template('assign_role.html', user=user, roles=roles)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if request.method == 'POST':
        # Process the form data and update the user
        email = request.form['email']
        full_name = request.form['full_name']
        phone_number = request.form['phone_number']
        is_active = request.form.get('is_active', False)

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('UPDATE Users SET email = ?, full_name = ?, phone_number = ?, is_active = ? WHERE user_id = ?',
                       (email, full_name, phone_number, is_active, user_id))
        conn.commit()
        conn.close()

        flash('User updated successfully.', 'success')
        return redirect(url_for('admin_dashboard'))
    else:
        # Retrieve user details to populate the form
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Users WHERE user_id = ?', (user_id,))
        user = cursor.fetchone()
        conn.close()

        return render_template('edit_user.html', user=user)

@app.route('/assign_role_page', methods=['GET', 'POST'])
def assign_role_page():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM Users')
    users = cursor.fetchall()
    
    cursor.execute('SELECT * FROM roles')
    roles = cursor.fetchall()
    
    conn.close()
    
    return render_template('assign_role_page.html', users=users, roles=roles)
@app.route('/user_list')
def user_list():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('index'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM Users')
    users = cursor.fetchall()
    conn.close()

    return render_template('user_list.html', users=users)



def get_most_sold_item(data):
    df = pd.DataFrame(data, columns=['name', 'total_quantity_sold'])
    most_sold_item = df.loc[df['total_quantity_sold'].idxmax()]
    return most_sold_item


@app.route('/admin/dashboard')
def admin_dashboard():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT Users.user_id, Users.email, Users.full_name, Users.phone_number, roles.role_name
        FROM Users
        LEFT JOIN roles ON Users.role_id = roles.role_id
    ''')
    users = cursor.fetchall()
    conn.close()

    return render_template('admin_dashboard.html', users=users)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/reports')
def reports():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    return render_template('reports.html')

@app.route('/admin/deactivate_user/<int:user_id>')
def deactivate_user(user_id):
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        print("hello")
        return redirect(url_for('index'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE Users SET is_active = 0 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    flash('User deactivated successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

# Google login route
@app.route('/google_login')
def google_login():
    nonce = secrets.token_urlsafe()
    session['nonce'] = nonce
    redirect_uri = url_for('google_auth', _external=True)
    return oauth.google.authorize_redirect(redirect_uri, nonce=nonce)

@app.route('/google/callback')
def google_auth():
    token = oauth.google.authorize_access_token()
    nonce = session.pop('nonce', None)
    user_info = oauth.google.parse_id_token(token, nonce=nonce)

    email = user_info['email']
    full_name = user_info.get('name', 'Google User')

    # Check if user already exists in the database
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM Users WHERE email = ?', (email,))
    user = cursor.fetchone()

    if user:
        # User exists, log them in
        session['user_id'] = user['user_id']
    else:
        # User doesn't exist, create a new account
        cursor.execute('INSERT INTO Users (email, full_name, is_active) VALUES (?, ?, ?)', (email, full_name, 1))
        conn.commit()
        user_id = cursor.lastrowid
        session['user_id'] = user_id

    conn.close()
    flash('You have successfully logged in with Google.', 'success')
    return redirect(url_for('dashboard'))

# Facebook login route
@app.route('/facebook_login')
def facebook_login():
    redirect_uri = url_for('facebook_auth', _external=True)
    return oauth.facebook.authorize_redirect(redirect_uri)

@app.route('/facebook/callback')
def facebook_auth():
    token = oauth.facebook.authorize_access_token()
    user_info = oauth.facebook.get('me?fields=id,name,email').json()

    email = user_info['email']
    full_name = user_info.get('name', 'Facebook User')

    # Check if user already exists in the database
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM Users WHERE email = ?', (email,))
    user = cursor.fetchone()

    if user:
        # User exists, log them in
        session['user_id'] = user['user_id']
    else:
        # User doesn't exist, create a new account
        cursor.execute('INSERT INTO Users (email, full_name, is_active) VALUES (?, ?, ?)', (email, full_name, 1))
        conn.commit()
        user_id = cursor.lastrowid
        session['user_id'] = user_id

    conn.close()
    flash('You have successfully logged in with Facebook.', 'success')
    return redirect(url_for('dashboard'))

# Twitter login route
@app.route('/twitter_login')
def twitter_login():
    redirect_uri = url_for('twitter_auth', _external=True)
    return oauth.twitter.authorize_redirect(redirect_uri)

@app.route('/twitter/callback')
def twitter_auth():
    token = oauth.twitter.authorize_access_token()
    user_info = oauth.twitter.get('account/verify_credentials.json').json()

    email = user_info.get('email', f"{user_info['screen_name']}@twitter.com")
    full_name = user_info.get('name', 'Twitter User')

    # Check if user already exists in the database
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM Users WHERE email = ?', (email,))
    user = cursor.fetchone()

    if user:
        # User exists, log them in
        session['user_id'] = user['user_id']
    else:
        # User doesn't exist, create a new account
        cursor.execute('INSERT INTO Users (email, full_name, is_active) VALUES (?, ?, ?)', (email, full_name, 1))
        conn.commit()
        user_id = cursor.lastrowid
        session['user_id'] = user_id

    conn.close()
    flash('You have successfully logged in with Twitter.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
        # Update user status to confirmed in the database
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('UPDATE Users SET is_active = 1 WHERE email = ?', (email,))
        conn.commit()
        conn.close()
    except SignatureExpired:
        flash('The confirmation link has expired.')
        return redirect(url_for('signup'))

    flash('Email confirmed successfully! You can now log in.')
    return redirect(url_for('signin'))

# @app.route('/dashboard')
# def dashboard():
#     if 'user' in session:
#         user_email = session['user']
#         if session.get('is_admin'):
#             print("Admin user detected, redirecting to admin dashboard")
#             return redirect(url_for('admin_dashboard'))
#         print("Regular user detected, rendering user dashboard")
#         return render_template('dashboard.html', user_email=user_email)
#     else:
#         flash('You need to log in first.', 'error')
#         return redirect(url_for('signin'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if not session.get('is_admin'):
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('index'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM Users WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()

    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

def fetch_delivery_data_for_agent(agent_id):
    conn = get_db()
    cursor = conn.cursor()
    
    query = '''
    SELECT Delivery_ID, Order_ID, Delivery_Agent_ID, Status, Pickup_time, Delivery_time
    FROM Delivery
    WHERE Delivery_Agent_ID = ?
    '''
    cursor.execute(query, (agent_id,))
    data = cursor.fetchall()
    conn.close()
    
    return data


def generate_average_delivery_time_chart(average_delivery_time):
    fig, ax = plt.subplots(figsize=(6, 3))
    ax.barh(['Average Delivery Time'], [average_delivery_time], color='skyblue')
    ax.set_xlim(0, max(60, average_delivery_time * 1.2))  # Ensure some padding on the right
    ax.set_xlabel('Time (minutes)')
    plt.title('Average Delivery Time')
    plt.tight_layout()
    
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png')
    img_buffer.seek(0)
    
    return img_buffer
def generate_on_time_delivery_rate_chart(on_time_rate):
    labels = ['On-Time', 'Late']
    sizes = [on_time_rate, 1 - on_time_rate]
    colors = ['lightgreen', 'lightcoral']
    explode = (0.1, 0)  # explode the On-Time slice
    
    fig, ax = plt.subplots(figsize=(6, 6))
    ax.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140)
    plt.title('On-Time Delivery Rate')
    plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png')
    img_buffer.seek(0)
    
    return img_buffer

def calculate_on_time_delivery_rate(data, on_time_threshold=30):
    df = pd.DataFrame(data, columns=['delivery_id', 'order_id', 'agent_id', 'status', 'pickup_time', 'delivery_time'])
    df['pickup_time'] = pd.to_datetime(df['pickup_time'])
    df['delivery_time'] = pd.to_datetime(df['delivery_time'])
    
    df['delivery_duration'] = (df['delivery_time'] - df['pickup_time']).dt.total_seconds() / 60  # Convert to minutes
    
    if len(df) == 0:
        return 0  # No deliveries, so on-time rate is 0
    
    on_time_deliveries = df[df['delivery_duration'] <= on_time_threshold]
    on_time_rate = len(on_time_deliveries) / len(df)
    
    return on_time_rate

def calculate_average_delivery_time(data):
    df = pd.DataFrame(data, columns=['delivery_id', 'order_id', 'agent_id', 'status', 'pickup_time', 'delivery_time'])
    df['pickup_time'] = pd.to_datetime(df['pickup_time'])
    df['delivery_time'] = pd.to_datetime(df['delivery_time'])
    
    df['delivery_duration'] = (df['delivery_time'] - df['pickup_time']).dt.total_seconds() / 60  # Convert to minutes
    
    if len(df) == 0:
        return 0  # No Delivery, so average delivery time is 0
    
    average_delivery_time = df['delivery_duration'].mean()
    
    return average_delivery_time

@app.route('/delivery_metrics', methods=['GET', 'POST'])
def delivery_metrics():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    if request.method == 'POST':
        agent_id = request.form.get('agent_id')
        data = fetch_delivery_data_for_agent(agent_id)
        average_delivery_time = calculate_average_delivery_time(data)
        on_time_rate = calculate_on_time_delivery_rate(data)
        
        if data:
            avg_time_img_buffer = generate_average_delivery_time_chart(average_delivery_time)
            on_time_rate_img_buffer = generate_on_time_delivery_rate_chart(on_time_rate)
            
            avg_time_plot_url = base64.b64encode(avg_time_img_buffer.getvalue()).decode()
            on_time_rate_plot_url = base64.b64encode(on_time_rate_img_buffer.getvalue()).decode()
        else:
            avg_time_plot_url = None
            on_time_rate_plot_url = None
        
        return render_template('delivery_metrics.html', 
                               avg_time_plot_url=avg_time_plot_url, 
                               on_time_rate_plot_url=on_time_rate_plot_url, 
                               agent_id=agent_id)
    
    return render_template('delivery_metrics.html', 
                           avg_time_plot_url=None, 
                           on_time_rate_plot_url=None, 
                           agent_id=None)

def update_delivery_status(delivery_id, status, delivery_time=None):
    conn = get_db()
    cursor = conn.cursor()
    
    if delivery_time:
        query = '''
        UPDATE Delivery
        SET Status = ?, Delivery_time = ?
        WHERE Delivery_ID = ?
        '''
        cursor.execute(query, (status, delivery_time, delivery_id))
    else:
        query = '''
        UPDATE Delivery
        SET Status = ?
        WHERE Delivery_ID = ?
        '''
        cursor.execute(query, (status, delivery_id))
    
    conn.commit()
    conn.close()

def add_delivery(order_id, agent_id, status, pickup_time, delivery_time):
    conn = get_db()
    cursor = conn.cursor()
    
    query = '''
    INSERT INTO Delivery (Order_ID, Delivery_Agent_ID, Status, Pickup_time, Delivery_time)
    VALUES (?, ?, ?, ?, ?)
    '''
    cursor.execute(query, (order_id, agent_id, status, pickup_time, delivery_time))
    conn.commit()
    conn.close()

@app.route('/restaurant_dashboard')
def restaurant_dashboard():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))

    urls = {
        'sales_trends': url_for('sales_trends'),
        'reports': url_for('reports'),
        'admin_notifications': url_for('admin_notifications'),
        'feedback_analysis': url_for('feedback_analysis'),
        'admin': url_for('admin'),
        'order_management': url_for('order_management'),
        'unassigned_orders': url_for('unassigned_orders'),
        'performance_metrics': url_for('performance_metrics'),
        'order_overview': url_for('order_overview'),
        'staff_list': url_for('staff_list'),
        'issues_reported': url_for('issues_reported'),
        'logout': url_for('signin')
    }
    return render_template('restaurant_dashboard.html', urls=urls)

@app.route('/admin_notifications')
def admin_notifications():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    return render_template('admin_notifications.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('You have been logged out.')
    return redirect(url_for('signin'))

@app.route('/sales_trends', methods=['GET', 'POST'])
def sales_trends():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    if request.method == 'POST':
        period = request.form.get('period', 'monthly')
        chart_type = request.form.get('chart_type', 'line')
        email = request.form.get('email')
        download = request.form.get('download', 'false')

        # Validate email
        if not is_valid_email(email):
            return "Invalid email address", 400

        # Generate the chart
        pdf_buffer, img_buffer = generate_sales_trend_line_chart(period)

        if pdf_buffer is None:
            return "Failed to generate chart", 500

        # Save the PDF to a temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp:
            tmp.write(pdf_buffer.getvalue())
            tmp_path = tmp.name

        # Send the email with the attachment
        send_email_with_attachment(email, tmp_path)

        # Check if the user clicked the download button
        if download == 'true':
            return send_file(io.BytesIO(pdf_buffer.getvalue()), 
                             mimetype='application/pdf',
                             as_attachment=True,
                             download_name='sales_trend_chart.pdf')

        # Otherwise, show the generated chart
        plot_url = base64.b64encode(img_buffer.getvalue()).decode()
        return render_template('sales_trends.html', plot_url=plot_url)

    # For GET requests, render the form
    return render_template('sales_trends.html')


def send_email_with_attachment(recipient_email, attachment_path):
    msg = MIMEMultipart()
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = recipient_email
    msg['Subject'] = "Sales Report"

    # Attach PDF file
    part = MIMEBase('application', 'octet-stream')
    with open(attachment_path, 'rb') as attachment:
        part.set_payload(attachment.read())
    encoders.encode_base64(part)
    part.add_header('Content-Disposition', f'attachment; filename="sales_report.pdf"')
    msg.attach(part)

    # Send email
    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)

@app.route('/download_sales_report')
def download_sales_report():
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    
    # Fetch sales data
    period = request.args.get('period', 'monthly')  # Get the period from query params (daily, weekly, monthly)
    chart_type = request.args.get('chart_type', 'line')  # Get the chart type from query params (line, bar)
    sales_data = fetch_sales_data(period)
    df = pd.DataFrame(sales_data, columns=['period', 'total_sales'])
    
    # Add title and sales data table to the PDF
    p.setFont("Helvetica", 14)
    p.drawString(30, height - 40, f"Sales Report ({period.capitalize()})")
    
    p.setFont("Helvetica", 10)
    x, y = 30, height - 60
    for index, row in df.iterrows():
        p.drawString(x, y, f"{row['period']}: {row['total_sales']}")
        y -= 12

    # Generate the chart and save as a temporary file
    plot_url, img_buffer = generate_sales_trend_chart_with_peaks(period, chart_type)
    temp_file_path = tempfile.NamedTemporaryFile(delete=False, suffix=".png").name
    with open(temp_file_path, 'wb') as f:
        f.write(img_buffer.getvalue())
    
    # Add the chart image to the PDF
    p.drawImage(temp_file_path, x, y - 200, width - 2 * x, 200)
    
    p.showPage()
    p.save()
    
    # Save the buffer content to a temporary PDF file
    pdf_temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    with open(pdf_temp_file.name, 'wb') as f:
        f.write(buffer.getvalue())
    
    # Send email with PDF attachment
    recipient_email = "recipient_email@gmail.com"  # Replace with recipient email address
    send_email_with_attachment(recipient_email, pdf_temp_file.name)
    
    # Clean up the temporary files
    buffer.seek(0)
    os.remove(temp_file_path)
    os.remove(pdf_temp_file.name)
    
    return send_file(buffer, as_attachment=True, download_name="sales_report.pdf", mimetype='application/pdf')

def highlight_peaks(df, ax):
    peak_threshold = df['total_sales'].mean() + df['total_sales'].std()  # Example threshold
    peaks = df[df['total_sales'] > peak_threshold]
    
    for idx, row in peaks.iterrows():
        ax.annotate('Peak', xy=(row['period'], row['total_sales']), xytext=(row['period'], row['total_sales'] + 5),
                    arrowprops=dict(facecolor='red', shrink=0.05),
                    horizontalalignment='center', verticalalignment='bottom')
        
def generate_sales_trend_chart_with_peaks(period='monthly', chart_type='line'):
    data = fetch_sales_data(period)
    
    df = pd.DataFrame(data, columns=['period', 'total_sales'])
    
    # Convert period to datetime
    try:
        if period == 'daily':
            df['period'] = pd.to_datetime(df['period'], format='%Y-%m-%d')
        elif period == 'weekly':
            df['period'] = pd.to_datetime(df['period'] + '-1', format='%Y-%W-%w')  # Monday as start of the week
        else:  # monthly
            df['period'] = pd.to_datetime(df['period'], format='%Y-%m')
    except ValueError as e:
        print(f"Error parsing dates: {e}")
        return None  # Handle the error gracefully
    
    plt.figure(figsize=(10, 6))
    
    if chart_type == 'bar':
        ax = df.plot(x='period', y='total_sales', kind='bar', color='skyblue')
    else:  # line chart
        ax = df.plot(x='period', y='total_sales', marker='o', linestyle='-', color='skyblue')
    
    highlight_peaks(df, ax)
    
    plt.xlabel('Period')
    plt.ylabel('Total Sales')
    plt.title(f'Sales Trends ({period.capitalize()})')
    plt.xticks(rotation=45)
    
    # Set date format on x-axis
    if period == 'daily':
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
    elif period == 'weekly':
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%W'))
    else:  # monthly
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m'))
    
    plt.tight_layout()
    
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png')
    img_buffer.seek(0)
    
    plot_url = base64.b64encode(img_buffer.getvalue()).decode()
    
    return plot_url, img_buffer


def generate_sales_trend_chart(period='monthly', chart_type='line'):
    data = fetch_sales_data(period)
    
    df = pd.DataFrame(data, columns=['period', 'total_sales'])
    
    plt.figure(figsize=(10, 6))
    if chart_type == 'bar':
        plt.bar(df['period'], df['total_sales'], color='skyblue')
    else:  # Default to line chart
        plt.plot(df['period'], df['total_sales'], marker='o', linestyle='-', color='skyblue')
    
    plt.xlabel('Period')
    plt.ylabel('Total Sales')
    plt.title(f'Sales Trends ({period.capitalize()})')
    plt.xticks(rotation=45)
    plt.tight_layout()
    
    img = io.BytesIO()
    plt.savefig(img, format='png')
    img.seek(0)
    plot_url = base64.b64encode(img.getvalue()).decode()
    
    return plot_url

def fetch_sales_data(period='monthly'):
    conn = get_db()
    cursor = conn.cursor()
    
    if period == 'daily':
        query = '''
        SELECT strftime('%Y-%m-%d', o.order_date) as period, SUM(o.total_price) as total_sales
        FROM Orders o
        GROUP BY period
        ORDER BY period;
        '''
    elif period == 'weekly':
        query = '''
        SELECT strftime('%Y-%W', o.order_date) as period, SUM(o.total_price) as total_sales
        FROM Orders o
        GROUP BY period
        ORDER BY period;
        '''
    else:  # Default to monthly
        query = '''
        SELECT strftime('%Y-%m', o.order_date) as period, SUM(o.total_price) as total_sales
        FROM Orders o
        GROUP BY period
        ORDER BY period;
        '''
    
    cursor.execute(query)
    data = cursor.fetchall()
    conn.close()
    
    return data

import pandas as pd
import matplotlib.pyplot as plt
import io
from matplotlib.backends.backend_pdf import PdfPages

def generate_sales_trend_line_chart(period='monthly'):
    data = fetch_sales_data(period)
    if not data:
        return None, None
    
    df = pd.DataFrame(data, columns=['period', 'total_sales'])
    try:
        if period == 'daily':
            df['period'] = pd.to_datetime(df['period'], format='%Y-%m-%d')
        elif period == 'weekly':
            df['period'] = pd.to_datetime(df['period'] + '-1', format='%Y-%W-%w')
        else:  # monthly
            df['period'] = pd.to_datetime(df['period'], format='%Y-%m')
    except ValueError as e:
        print(f"Error parsing dates: {e}")
        return None, None

    plt.figure(figsize=(10, 6))
    ax = df.plot(x='period', y='total_sales', marker='o', linestyle='-', color='skyblue')
    
    highlight_peaks(df, ax)
    
    plt.xlabel('Period')
    plt.ylabel('Total Sales')
    plt.title(f'Sales Trends ({period.capitalize()})')
    plt.xticks(rotation=45)
    
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png')
    img_buffer.seek(0)
    
    pdf_buffer = io.BytesIO()
    with PdfPages(pdf_buffer) as pdf:
        pdf.savefig(plt.gcf())
    pdf_buffer.seek(0)
    
    return pdf_buffer, img_buffer

import re

def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email) is not None

def fetch_top_selling_items_by_month(month):
    conn = sqlite3.connect('existing_database.db')
    cursor = conn.cursor()


    # Query to fetch top-selling items for the given month
    
    # Query to fetch top-selling items for the given month
    query = '''
    SELECT mi.Name, SUM(oi.quantity) as total_quantity_sold
    FROM order_items oi
    JOIN orders o ON oi.order_id = o.order_id
    JOIN MenuItems mi ON oi.item_id = mi.MenuItemID
    WHERE strftime('%Y-%m', o.order_date) = ?
    GROUP BY mi.name
    ORDER BY total_quantity_sold DESC
    '''
    cursor.execute(query, (month,))
    data = cursor.fetchall()
    conn.close()
    
    return [{'name': row[0], 'total_quantity_sold': row[1]} for row in data]

def generate_top_selling_items_bar_chart(items, quantities):
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(items, quantities, color='skyblue')
    plt.xlabel('Items')
    plt.ylabel('Total Quantity Sold')
    plt.title('Top Selling Items')
    plt.xticks(rotation=45)
    plt.tight_layout()
    
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png')
    img_buffer.seek(0)
    
    return img_buffer

@app.route('/top_selling_items', methods=['GET', 'POST'])
def top_selling_items():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    selected_month = request.form.get('month', datetime.now().strftime('%Y-%m'))
    
    top_selling_items_data = fetch_top_selling_items_by_month(selected_month)
    items = [row['name'] for row in top_selling_items_data]
    quantities = [row['total_quantity_sold'] for row in top_selling_items_data]
    
    top_selling_items_chart = generate_top_selling_items_bar_chart(items, quantities)
    top_selling_items_chart_url = base64.b64encode(top_selling_items_chart.getvalue()).decode()
    
    return render_template('top_selling_items.html', 
                           top_selling_items_chart_url=top_selling_items_chart_url, 
                           selected_month=selected_month)

@app.route('/download_top_selling_items', methods=['GET', 'POST'])
def download_top_selling_items():
    selected_month = request.form.get('month', datetime.now().strftime('%Y-%m'))
    
    top_selling_items_data = fetch_top_selling_items_by_month(selected_month)
    items = [row['name'] for row in top_selling_items_data]
    quantities = [row['total_quantity_sold'] for row in top_selling_items_data]
    
    top_selling_items_chart = generate_top_selling_items_bar_chart(items, quantities)
    
    return send_file(io.BytesIO(top_selling_items_chart.getvalue()), mimetype='image/png', as_attachment=True, download_name=f'top_selling_items_{selected_month}.png')

@app.route('/download_revenue_analysis', methods=['GET', 'POST'])
def download_revenue_analysis():
    selected_year = request.form.get('year', '2024')
    
    monthly_revenue_data = fetch_monthly_revenue_for_year(selected_year)
    months = [row['month'] for row in monthly_revenue_data]
    revenues = [row['revenue'] for row in monthly_revenue_data]
    
    revenue_chart = generate_revenue_bar_charts(months, revenues)
    
    return send_file(io.BytesIO(revenue_chart.getvalue()), mimetype='image/png', as_attachment=True, download_name=f'revenue_analysis_{selected_year}.png')

@app.route('/download_delivery_performance', methods=['GET', 'POST'])
def download_delivery_performance():
    agent_id = request.form.get('agent_id')
    data = fetch_delivery_data_for_agent(agent_id)
    average_delivery_time = calculate_average_delivery_time(data)
    on_time_rate = calculate_on_time_delivery_rate(data)
    
    avg_time_chart = generate_average_delivery_time_chart(average_delivery_time)
    on_time_rate_chart = generate_on_time_delivery_rate_chart(on_time_rate)
    
    return send_file(io.BytesIO(avg_time_chart.getvalue()), mimetype='image/png', as_attachment=True, download_name=f'delivery_performance_{agent_id}.png')

def fetch_monthly_revenue_for_year(year):
    conn = sqlite3.connect('existing_database.db')
    cursor = conn.cursor()
    
    query = '''
    SELECT strftime('%Y-%m', order_date) as month, SUM(total_price) as revenue
    FROM orders
    WHERE strftime('%Y', order_date) = ?
    GROUP BY month
    ORDER BY month;
    '''
    cursor.execute(query, (year,))
    data = cursor.fetchall()
    conn.close()
    
    return [{'month': row[0], 'revenue': row[1]} for row in data]

def calculate_average_delivery_time(data):
    df = pd.DataFrame(data, columns=['delivery_id', 'order_id', 'agent_id', 'status', 'pickup_time', 'delivery_time'])
    df['pickup_time'] = pd.to_datetime(df['pickup_time'])
    df['delivery_time'] = pd.to_datetime(df['delivery_time'])
    
    df['delivery_duration'] = (df['delivery_time'] - df['pickup_time']).dt.total_seconds() / 60  # Convert to minutes
    
    if len(df) == 0:
        return 0  # No deliveries, so average delivery time is 0
    
    average_delivery_time = df['delivery_duration'].mean()
    
    return average_delivery_time

def calculate_on_time_delivery_rate(data, on_time_threshold=30):
    df = pd.DataFrame(data, columns=['delivery_id', 'order_id', 'agent_id', 'status', 'pickup_time', 'delivery_time'])
    df['pickup_time'] = pd.to_datetime(df['pickup_time'])
    df['delivery_time'] = pd.to_datetime(df['delivery_time'])
    
    df['delivery_duration'] = (df['delivery_time'] - df['pickup_time']).dt.total_seconds() / 60  # Convert to minutes
    
    if len(df) == 0:
        return 0  # No deliveries, so on-time rate is 0
    
    on_time_deliveries = df[df['delivery_duration'] <= on_time_threshold]
    on_time_rate = len(on_time_deliveries) / len(df)
    
    return on_time_rate

def generate_average_delivery_time_chart(average_delivery_time):
    fig, ax = plt.subplots(figsize=(6, 3))
    ax.barh(['Average Delivery Time'], [average_delivery_time], color='skyblue')
    ax.set_xlim(0, max(60, average_delivery_time * 1.2))  # Ensure some padding on the right
    ax.set_xlabel('Time (minutes)')
    plt.title('Average Delivery Time')
    plt.tight_layout()
    
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png')
    img_buffer.seek(0)
    
    return img_buffer

def generate_on_time_delivery_rate_chart(on_time_rate):
    labels = ['On-Time', 'Late']
    sizes = [on_time_rate, 1 - on_time_rate]
    colors = ['lightgreen', 'lightcoral']
    explode = (0.1, 0)  # explode the On-Time slice
    
    fig, ax = plt.subplots(figsize=(6, 6))
    ax.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140)
    plt.title('On-Time Delivery Rate')
    plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png')
    img_buffer.seek(0)
    
    return img_buffer

def generate_revenue_bar_charts(months, revenues):
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(months, revenues, color='skyblue')
    plt.xlabel('Month')
    plt.ylabel('Revenue')
    plt.title('Revenue Analysis (Bar Chart)')
    plt.xticks(rotation=45)
    plt.tight_layout()
    
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png')
    img_buffer.seek(0)
    
    return img_buffer



def fetch_customer_data(year, month):
    conn = sqlite3.connect('existing_database.db')  # Update with your database path
    cursor = conn.cursor()

    query = '''
    SELECT order_date, COUNT(order_id) as order_count
    FROM orders
    WHERE strftime('%Y', order_date) = ? AND strftime('%m', order_date) = ?
    GROUP BY order_date;
    '''
    cursor.execute(query, (year, month.zfill(2)))
    data = cursor.fetchall()
    conn.close()
    return data

# Generate the plot for order frequency
def plot_order_frequency(year, month):
    data = fetch_customer_data(year, month)
    df = pd.DataFrame(data, columns=['order_date', 'order_count'])

    # Convert order_date to datetime
    df['order_date'] = pd.to_datetime(df['order_date'])

    # Create a figure
    fig = go.Figure()

    # Add bar plot for order frequency
    fig.add_trace(
        go.Bar(
            x=df['order_date'],
            y=df['order_count'],
            name='Order Frequency',
            marker=dict(color='blue'),
            opacity=0.6,
            width=[2] * len(df)  # Adjust width for thinner bars

        )
    )

    # Update layout
    fig.update_layout(
        title=f'Order Frequency in {year}-{month}',
        xaxis_title='Date',
        yaxis_title='Number of Orders',
        xaxis=dict(
            tickformat='%Y-%m-%d',  # Format x-axis for date display
            tickangle=-45,   # Angle for better readability
            tickvals=df['order_date']  # Show only specified dates
        
        ),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1
        )
    )

    return pio.to_html(fig, full_html=False)

def plot_order_statistics(year, month):
    data = fetch_customer_data(year, month)

    # Ensure the fetched data is changing for different inputs
    if not data or len(data) == 0:
        return "No data available for the selected period."

    # Create a DataFrame
    df = pd.DataFrame(data, columns=['order_date', 'order_count'])

    # Convert order_date to datetime
    df['order_date'] = pd.to_datetime(df['order_date'], format="%Y-%m-%d", errors="coerce")

    # Ensure no NaT values exist in 'order_date'
    df = df.dropna(subset=['order_date'])

    # Sort data to ensure correct plotting order
    df = df.sort_values(by='order_date')

    # Create the figure and the bar plot
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # Convert datetime to numerical values for plotting
    ax.bar(df['order_date'].map(mdates.date2num), df['order_count'], color='blue', alpha=0.6, width=0.8)

    # Format x-axis for better readability
    ax.xaxis.set_major_locator(mdates.DayLocator(interval=3))  # Show every 3rd day
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
    
    ax.set_title(f'Order Statistics in {year}-{month}')
    ax.set_xlabel('Date')
    ax.set_ylabel('Number of Orders')
    plt.xticks(rotation=45)
    plt.tight_layout()

    # Save the plot to a BytesIO object
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png')
    img_buffer.seek(0)

    # Convert the BytesIO object to a base64-encoded string
    img_data = base64.b64encode(img_buffer.getvalue()).decode()

    return img_data

@app.route('/order_statistics', methods=['GET', 'POST'])
def order_statistics():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    year = request.form.get('year') # Default to 2023 if not provided
    month = request.form.get('month') # Default to January if not provided

    # Ensure month is a two-digit string
    if month:
        month = month.zfill(2)

    chart_data = plot_order_statistics(year, month)
    return render_template('order_statistics.html', chart_data=chart_data, year=year, month=month)

@app.route('/download_order_statistics', methods=['GET', 'POST'])
def download_order_statistics():
    # year = request.form.get('year') 
    month = request.form.get('month')
    year = month[:4]
    month = month[-2:]
    print (month)
    # Ensure month is a two-digit string
    if month:
        month = month.zfill(2)

    data = fetch_customer_data(year, month)
    df = pd.DataFrame(data, columns=['order_date', 'order_count'])
    df['order_date'] = pd.to_datetime(df['order_date'])

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(df['order_date'], df['order_count'], color='blue', alpha=0.6, width=0.8)
    ax.set_title(f'Order Statistics in {year}-{month}')
    ax.set_xlabel('Date')
    ax.set_ylabel('Number of Orders')
    ax.xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter('%Y-%m-%d'))
    plt.xticks(rotation=45)
    plt.tight_layout()

    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png')
    img_buffer.seek(0)

    return send_file(img_buffer, mimetype='image/png', as_attachment=True, download_name=f'order_statistics_{year}-{month}.png')


def fetch_customers():
    conn = sqlite3.connect('existing_database.db')
    cursor = conn.cursor()
    query = 'SELECT DISTINCT customer_id FROM orders'
    cursor.execute(query)
    data = cursor.fetchall()
    conn.close()
    return [row[0] for row in data]

def fetch_customer_orders(customer_id):
    conn = sqlite3.connect('existing_database.db')
    cursor = conn.cursor()

    query = '''
    SELECT order_date, total_price
    FROM orders
    WHERE customer_id = ?
    ORDER BY order_date
    '''
    cursor.execute(query, (customer_id,))
    data = cursor.fetchall()
    conn.close()
    return data

def plot_customer_orders(customer_id):
    data = fetch_customer_orders(customer_id)
    df = pd.DataFrame(data, columns=['order_date', 'total_price'])

    # Convert order_date to datetime
    df['order_date'] = pd.to_datetime(df['order_date'])

    # Create the figure and the plot
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.plot(df['order_date'], df['total_price'], marker='o', linestyle='-', color='royalblue')
    ax.set_title(f'Order History for Customer {customer_id}')
    ax.set_xlabel('Order Date')
    ax.set_ylabel('Total Price')
    ax.xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter('%Y-%m-%d'))
    plt.xticks(rotation=45)
    plt.tight_layout()

    # Save the plot to a BytesIO object
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png')
    img_buffer.seek(0)

    # Convert the BytesIO object to a base64-encoded string
    img_data = base64.b64encode(img_buffer.getvalue()).decode()
    
    return img_data

@app.route('/customer_orders_history', methods=['GET', 'POST'])
def customer_orders_history():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    customers = fetch_customers()
    selected_customer = request.form.get('customer_id')
    chart_html = ''

    if request.method == 'POST' and selected_customer:
        chart_html = plot_customer_orders(selected_customer)

    return render_template('customer_orders_history.html', customers=customers, chart_html=chart_html)

@app.route('/download_customer_orders_history', methods=['POST'])
def download_customer_orders_history():
    selected_customer = request.form.get('customer_id')
    
    data = fetch_customer_orders(selected_customer)
    df = pd.DataFrame(data, columns=['order_date', 'total_price'])

    # Convert order_date to datetime
    df['order_date'] = pd.to_datetime(df['order_date'])

    # Create the figure and the plot
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.plot(df['order_date'], df['total_price'], marker='o', linestyle='-', color='royalblue')
    ax.set_title(f'Order History for Customer {selected_customer}')
    ax.set_xlabel('Order Date')
    ax.set_ylabel('Total Price')
    ax.xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter('%Y-%m-%d'))
    plt.xticks(rotation=45)
    plt.tight_layout()

    # Save the plot to a BytesIO object
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png')
    img_buffer.seek(0)

    return send_file(img_buffer, mimetype='image/png', as_attachment=True, download_name=f'customer_orders_history_{selected_customer}.png')

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

app.secret_key = 'ce2d0b836d67ded3da8d9170896a014d' 
def get_db():
    conn = sqlite3.connect('existing_database.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/feedback-analysis")
def feedback_analysis():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    db_path = 'existing_database.db'  # Update with your actual database path
    analysis_results = generate_feedback_analysis(db_path)
    
    return render_template(
        'feedback_visualization.html',
        average_rating=analysis_results['average_rating'],
        rating_plot_div=analysis_results['rating_plot_div'],
        sentiment_plot_div=analysis_results['sentiment_plot_div'],
        sentiment_pie_chart_path=analysis_results['sentiment_pie_chart_path']
    )

def get_sentiment_category(sentiment_polarity):
    if sentiment_polarity > 0:
        return 'Positive'
    elif sentiment_polarity < 0:
        return 'Negative'
    else:
        return 'Neutral'

def generate_feedback_analysis(db_path):
    conn = sqlite3.connect(db_path)
    feedback_df = pd.read_sql_query('SELECT * FROM feedback', conn)
    conn.close()

    # Calculate the average rating
    average_rating = feedback_df['rating'].mean()

    # Perform sentiment analysis on comments
    def get_sentiment(comment):
        analysis = TextBlob(comment)
        return analysis.sentiment.polarity

    feedback_df['sentiment'] = feedback_df['comment'].apply(get_sentiment)
    feedback_df['sentiment_category'] = feedback_df['sentiment'].apply(get_sentiment_category)

    # Plot rating distribution
    rating_counts = feedback_df['rating'].value_counts().sort_index()
    rating_distribution = go.Figure([go.Bar(x=rating_counts.index, y=rating_counts.values)])
    rating_distribution.update_layout(title='Rating Distribution', xaxis_title='Rating', yaxis_title='Count')
    rating_plot_div = pio.to_html(rating_distribution, full_html=False)

    # Plot sentiment distribution
    sentiment_distribution = go.Figure([go.Histogram(x=feedback_df['sentiment'], nbinsx=20)])
    sentiment_distribution.update_layout(title='Sentiment Distribution', xaxis_title='Sentiment', yaxis_title='Count')
    sentiment_plot_div = pio.to_html(sentiment_distribution, full_html=False)

    # Plot average sentiment per rating
    avg_sentiment_per_rating = feedback_df.groupby('rating')['sentiment'].mean()
    avg_sentiment_plot = go.Figure([go.Bar(x=avg_sentiment_per_rating.index, y=avg_sentiment_per_rating.values)])
    avg_sentiment_plot.update_layout(title='Average Sentiment per Rating', xaxis_title='Rating', yaxis_title='Average Sentiment')
    avg_sentiment_plot_div = pio.to_html(avg_sentiment_plot, full_html=False)

    # Plot pie chart for sentiment categories using Plotly
    sentiment_counts = feedback_df['sentiment_category'].value_counts()
    sentiment_pie_chart = go.Figure(data=[
        go.Pie(labels=sentiment_counts.index, values=sentiment_counts.values, 
               marker=dict(colors=['lightgreen', 'lightcoral', 'lightgrey']), 
               hoverinfo='label+percent', textinfo='value', textfont_size=20)
    ])
    sentiment_pie_chart.update_layout(title='Distribution of Sentiments in Feedback')
    sentiment_pie_chart_path = pio.to_html(sentiment_pie_chart, full_html=False)

    # Display the pie chart using Streamlit
    st.plotly_chart(sentiment_pie_chart)

    return {
        'average_rating': average_rating,
        'rating_plot_div': rating_plot_div,
        'sentiment_plot_div': sentiment_plot_div,
        'sentiment_pie_chart_path': sentiment_pie_chart_path
    }


def fetch_customer_datas():
    conn = sqlite3.connect('existing_database.db')  # Update with your database path
    cursor = conn.cursor()

    query = '''
    SELECT customer_id, order_date, COUNT(order_id) as order_count, SUM(total_price) as total_spent 
    FROM Orders 
    GROUP BY customer_id, order_date;
    '''
    cursor.execute(query)
    data = cursor.fetchall()
    conn.close()
    return data

def plot_order_frequency_spending():
    data = fetch_customer_datas()
    df = pd.DataFrame(data, columns=['customer_id', 'order_date', 'order_count', 'total_spent'])

    # Convert order_date to datetime
    df['order_date'] = pd.to_datetime(df['order_date'])

    # Group data by date to calculate daily totals for frequency and spending
    daily_data = df.groupby(df['order_date'].dt.date).agg(
        total_orders=('order_count', 'sum'),
        total_spent=('total_spent', 'sum')
    ).reset_index()

    daily_data['order_date'] = pd.to_datetime(daily_data['order_date'])

    # Create a figure
    fig = go.Figure()

    # Add bar plot for order frequency
    fig.add_trace(
        go.Bar(
            x=daily_data['order_date'],
            y=daily_data['total_orders'],
            name='Order Frequency',
            marker=dict(color='blue'),
            opacity=0.6
        )
    )

    # Add line plot for total spending
    fig.add_trace(
        go.Scatter(
            x=daily_data['order_date'],
            y=daily_data['total_spent'],
            mode='lines+markers',
            name='Total Spending',
            line=dict(color='orange')
        )
    )

    # Update layout
    fig.update_layout(
        title='Order Frequency and Total Spending Over Time',
        xaxis_title='Date',
        yaxis_title='Count / Spending',
        barmode='overlay',
        xaxis=dict(
            tickformat='%Y-%m-%d',  # Format x-axis for date display
            tickangle=-45           # Angle for better readability
        ),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1
        )
    )

    return pio.to_html(fig, full_html=False)


@app.route('/order_frequency_spending', methods=['GET'])
def order_frequency_spending():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    chart_html = plot_order_frequency_spending()
    return render_template('order_frequency_spending.html', chart_html=chart_html)

@app.route('/order_frequency', methods=['GET'])
def order_frequency():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    year = request.args.get('year') or '2023'  # Default to 2023 if not provided
    month = request.args.get('month') or '01'  # Default to January if not provided

    # Ensure month is a two-digit string
    if month:
        month = month.zfill(2)

    chart_html = plot_order_frequency(year, month)
    return render_template('order_frequency.html', chart_html=chart_html)


def fetch_customers():
    conn = sqlite3.connect('existing_database.db')
    cursor = conn.cursor()
    query = 'SELECT DISTINCT customer_id FROM orders'
    cursor.execute(query)
    data = cursor.fetchall()
    conn.close()
    return [row[0] for row in data]

def fetch_customer_purchases(customer_id):
    conn = sqlite3.connect('existing_database.db')
    cursor = conn.cursor()

    query = '''
    SELECT order_date, total_price
    FROM orders
    WHERE customer_id = ?
    ORDER BY order_date
    '''
    cursor.execute(query, (customer_id,))
    data = cursor.fetchall()
    conn.close()
    return data

def plot_customer_purchases(customer_id):
    data = fetch_customer_purchases(customer_id)
    df = pd.DataFrame(data, columns=['order_date', 'total_price'])

    fig = go.Figure()

    # Scatter plot for purchases over time
    fig.add_trace(go.Scatter(x=df['order_date'], y=df['total_price'], mode='lines+markers', 
                             name='Total Price', line=dict(color='royalblue')))

    fig.update_layout(title=f'Purchase History for Customer {customer_id}',
                      xaxis_title='Order Date',
                      yaxis_title='Total Price')

    return pio.to_html(fig, full_html=False)

@app.route('/customer_purchases', methods=['GET', 'POST'])
def customer_purchases():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    customers = fetch_customers()
    selected_customer = request.form.get('customer_id')
    chart_html = ''

    if request.method == 'POST' and selected_customer:
        chart_html = plot_customer_purchases(selected_customer)

    return render_template('customer_purchases.html', customers=customers, chart_html=chart_html)

app.jinja_env.filters['zfill'] = lambda s: str(s).zfill(2)

@app.route('/revenue_metrics', methods=['GET', 'POST'])
def revenue_metrics():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    selected_year = request.form.get('year', '2024')
    
    monthly_revenue_data = fetch_monthly_revenue_for_year(selected_year)
    months = [row['month'] for row in monthly_revenue_data]
    revenues = [row['revenue'] for row in monthly_revenue_data]
    
    gains, losses = calculate_revenue_metrics(revenues)

    # Generate bar and line charts
    revenue_line_chart = generate_revenue_line_chart(months, gains, losses)
    revenue_bar_chart = generate_revenue_bar_chart(months, gains, losses)
    
    revenue_line_chart_url = base64.b64encode(revenue_line_chart.getvalue()).decode()
    revenue_bar_chart_url = base64.b64encode(revenue_bar_chart.getvalue()).decode()
    
    return render_template('revenue_metrics.html', 
                           revenue_line_chart_url=revenue_line_chart_url, 
                           revenue_bar_chart_url=revenue_bar_chart_url, 
                           selected_year=selected_year)

def fetch_monthly_revenue_for_year(year):
    conn = get_db()
    cursor = conn.cursor()
    
    query = '''
    SELECT strftime('%Y-%m', order_date) as month, SUM(total_price) as revenue
    FROM Orders
    WHERE strftime('%Y', order_date) = ?
    GROUP BY month
    ORDER BY month;
    '''
    cursor.execute(query, (year,))
    data = cursor.fetchall()
    conn.close()
    
    return data

def calculate_revenue_metrics(revenues):
    average_revenue = sum(revenues) / len(revenues)
    gains = [revenue - average_revenue if revenue > average_revenue else 0 for revenue in revenues]
    losses = [average_revenue - revenue if revenue < average_revenue else 0 for revenue in revenues]
    return gains, losses

def generate_revenue_line_chart(months, gains, losses):
    fig, ax = plt.subplots(figsize=(10, 6))
    dates = pd.to_datetime(months, format='%Y-%m')
    
    ax.plot(dates, gains, marker='o', linestyle='-', color='green', label='Gain')
    ax.plot(dates, losses, marker='o', linestyle='-', color='red', label='Loss')
    
    plt.xlabel('Month')
    plt.ylabel('Revenue Difference')
    plt.title('Revenue Trend (Line Chart)')
    plt.legend()
    plt.xticks(rotation=45)
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m'))
    plt.tight_layout()
    
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png')
    img_buffer.seek(0)
    
    return img_buffer

def generate_revenue_bar_chart(months, gains, losses):
    fig, ax = plt.subplots(figsize=(10, 6))
    dates = pd.to_datetime(months, format='%Y-%m')
    
    ax.bar(dates, gains, color='green', label='Gain')
    ax.bar(dates, losses, color='red', label='Loss')
    
    plt.xlabel('Month')
    plt.ylabel('Revenue Difference')
    plt.title('Revenue Trend (Bar Chart)')
    plt.legend()
    plt.xticks(rotation=45)
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m'))
    plt.tight_layout()
    
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png')
    img_buffer.seek(0)
    
    return img_buffer

# Path to save the trained model
MODEL_PATH = 'feedback_anomaly_model.pkl'

# Function to create the database and feedback table
def create_database():
    conn = sqlite3.connect('existing_database.db')
    cursor = conn.cursor()

    # Create the feedback table if it doesn't exist
    cursor.execute(''' 
        CREATE TABLE IF NOT EXISTS feedback (
            feedback_id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER NOT NULL,
            customer_id INTEGER NOT NULL,
            rating INTEGER NOT NULL,
            comment TEXT
        )
    ''')

    conn.commit()
    conn.close()

# Function to analyze sentiment and classify food vs. service issues, including new scenarios
def analyze_sentiment(comment):
    food_sentiment = 0
    service_sentiment = 0
    order_issues = 0
    experience_sentiment = 0
    
    if not comment:
        return food_sentiment, service_sentiment, order_issues, experience_sentiment

    # Analyze the food sentiment
    if "good" in comment.lower() or "excellent" in comment.lower() or "tasty" in comment.lower() or "delicious" in comment.lower():
        food_sentiment = 1  # Positive sentiment about food
    elif "bad" in comment.lower() or "poor" in comment.lower() or "bland" in comment.lower():
        food_sentiment = -1  # Negative sentiment about food

    # Analyze the service sentiment (delivery)
    if "late" in comment.lower() or "delay" in comment.lower():
        service_sentiment = -1  # Negative sentiment about delivery service
    elif "fast" in comment.lower() or "on time" in comment.lower() or "quick" in comment.lower():
        service_sentiment = 1  # Positive sentiment about delivery service

    # Detect order issues like cancellation
    if "cancelled" in comment.lower() or "no notice" in comment.lower():
        order_issues = 1  # Indicates an issue with order cancellation

    # Detect average experience or neutral feedback
    if "average experience" in comment.lower() or "okay" in comment.lower() or "mediocre" in comment.lower():
        experience_sentiment = 0  # Neutral experience
    elif "good" in comment.lower() or "great" in comment.lower() or "satisfied" in comment.lower():
        experience_sentiment = 1  # Positive experience
    elif "bad" in comment.lower() or "poor" in comment.lower() or "dissatisfied" in comment.lower():
        experience_sentiment = -1  # Negative experience

    # Return sentiment scores for food, service, order issues, and overall experience
    return food_sentiment, service_sentiment, order_issues, experience_sentiment

# Function to fetch feedback data, group by customer, and detect anomalies
def detect_feedback_anomalies_ml():
    conn = sqlite3.connect('existing_database.db')
    cursor = conn.cursor()

    try:
        # Fetch feedback data grouped by customer_id
        cursor.execute(''' 
            SELECT feedback_id, order_id, customer_id, rating, comment 
            FROM feedback
        ''')
        feedback_data = cursor.fetchall()

        # Group feedback by customer_id
        grouped_feedback = {}
        for row in feedback_data:
            customer_id = row[2]
            if customer_id not in grouped_feedback:
                grouped_feedback[customer_id] = []
            grouped_feedback[customer_id].append({
                "feedback_id": row[0],
                "order_id": row[1],
                "customer_id":customer_id,
                "rating": row[3],
                "comment": row[4]
            })

        # Prepare data for ML (features will be rating and sentiment score)
        features = []
        feedback_list = []
        for customer_id, feedbacks in grouped_feedback.items():
            for feedback in feedbacks:
                food_sentiment, service_sentiment, order_issues, experience_sentiment = analyze_sentiment(feedback["comment"])  # Analyze sentiment
                features.append([feedback["rating"], food_sentiment, service_sentiment, order_issues, experience_sentiment])
                feedback["food_sentiment"] = food_sentiment
                feedback["service_sentiment"] = service_sentiment
                feedback["order_issues"] = order_issues
                feedback["experience_sentiment"] = experience_sentiment
                feedback_list.append(feedback)

        if not features:
            return []

        # Normalize data
        scaler = StandardScaler()
        features = scaler.fit_transform(features)

        # Apply K-Means clustering
        kmeans = KMeans(n_clusters=2, random_state=42)
        labels = kmeans.fit_predict(features)

        # Save the trained model
        if not os.path.exists(MODEL_PATH):
            joblib.dump(kmeans, MODEL_PATH)
            joblib.dump(scaler, 'scaler.pkl')

        # Mark anomalies based on clustering
        anomalies = []
        for i, label in enumerate(labels):
            if label == 1:  # Assuming 1 indicates anomalies
                anomaly = feedback_list[i]
                anomaly_type = "Unknown"
                
                # Identify anomaly based on rating, sentiment, order issues, and experience
                if anomaly["rating"] <= 2 and anomaly["service_sentiment"] < 0:
                    anomaly_type = "Service Issue (Late Delivery)"
                elif anomaly["service_sentiment"] < 0:
                    anomaly_type = "Negative Sentiment (Service)"
                elif anomaly["food_sentiment"] < 0:
                    anomaly_type = "Poor Food Quality"
                elif anomaly["rating"] <= 2:
                    anomaly_type = "Low Rating"
                elif anomaly["order_issues"] == 1:
                    anomaly_type = "Order Cancellation Issue"
                elif anomaly["experience_sentiment"] == 0:
                    anomaly_type = "Average Experience"

                anomaly["anomaly_type"] = anomaly_type
                anomalies.append(anomaly)

        return anomalies

    except Exception as e:
        print(f"Error: {e}")
        return []
    finally:
        conn.close()

# Flask route to display anomalies
@app.route('/anomalies')
def show_anomalies():
    anomalies = detect_feedback_anomalies_ml()

    # Prepare the anomalies for display in a table
    anomaly_data = []
    for anomaly in anomalies:
        anomaly_data.append({
            "feedback_id": anomaly["feedback_id"],
            "order_id": anomaly["order_id"],
            "customer_id": anomaly["customer_id"],
            "rating": anomaly["rating"],
            "comment": anomaly["comment"],
            "food_sentiment": anomaly["food_sentiment"],
            "service_sentiment": anomaly["service_sentiment"],
            "order_issues": anomaly["order_issues"],
            "experience_sentiment": anomaly["experience_sentiment"],
            "anomaly_type": anomaly["anomaly_type"]
        })

    return render_template('anomalies.html', anomalies=anomaly_data)


from flask import Flask, request, jsonify, render_template, send_file
from flask_mail import Mail,Message
import sqlite3
from datetime import datetime, timedelta, date
import statistics
from werkzeug.security import generate_password_hash
from dateutil.relativedelta import relativedelta # type: ignore
import os
from fpdf import FPDF # type: ignore

# Connects to SQLite3 database
def get_db_connection():
    conn = sqlite3.connect('existing_database.db')
    conn.row_factory = sqlite3.Row
    return conn


def send_order_confirmation_update(user_email, user_name, order_number, items, total_amount):
    try:
        items_str = "\n".join([f"{item['quantity']}x {item['Name']} - ${item['price']} each" for item in items])
        email_body = f"""Hello {user_name}, 
Thank you for placing your order with HiFi Delivery Eats. 
We're pleased to confirm receipt of your order (Order ID: #{order_number}), and it is now being prepared. 
Order Summary: 
{items_str} 
Total Amount: ${total_amount} 
You will receive a notification once your order has been shipped. 
If you have any questions or require assistance, please feel free to contact our support team at support@hifideliveryeats.com. 
We appreciate your trust in HiFi Delivery Eats and look forward to serving you again soon. 
With regards,
HiFi Delivery Eats Team"""
        
        msg = Message("Order Confirmation - HiFi Delivery Eats", recipients=[user_email])
        msg.body = email_body
        mail.send(msg)
        return True
    except Exception as e:
        print(f'An error occurred: {e}')
        return False
    

def send_order_out_for_delivery_update(user_email, user_name, order_number, items, total_amount):
    try:
        items_str = "\n".join([f"{item['quantity']}x {item['Name']} - ${item['price']} each" for item in items])
        email_body = f""" Hello {user_name},
We're excited to let you know that your order (Order ID: #{order_number}) is on its way to your delivery address!
Order Summary:
{items_str}
Total Amount: ${total_amount}
Please ensure someone is available to receive the order.
If you have any questions, feel free to contact us at support@hifideliveryeats.com.
Thank you for choosing HiFi Delivery Eats!
With regards,
HiFi Delivery Eats Team"""
        
        msg = Message("Order Confirmation - HiFi Delivery Eats", recipients=[user_email])
        msg.body = email_body
        mail.send(msg)
        return True
    except Exception as e:
        print(f'An error occurred: {e}')
        return False
    
def send_order_delivered_update(user_email, user_name, order_number, items, total_amount):
    try:
        items_str = "\n".join([f"{item['quantity']}x {item['Name']} - ${item['price']} each" for item in items])
        email_body = f""" Hello {user_name},
Thank you for ordering with HiFi Delivery Eats.
We're delighted to inform you that your order (Order ID: #{order_number}) has been successfully delivered.
Order Summary:
{items_str}
Total Amount: ${total_amount}
We hope you enjoy your meal!
For any feedback or inquiries, feel free to contact us at support@hifideliveryeats.com.
Looking forward to serving you again!
With regards,
HiFi Delivery Eats Team"""
        
        msg = Message("Order Confirmation - HiFi Delivery Eats", recipients=[user_email])
        msg.body = email_body
        mail.send(msg)
        return True
    except Exception as e:
        print(f'An error occurred: {e}')
        return False
    
def send_order_cancelled_update(user_email, user_name, order_number, items, reason):
    try:
        items_str = "\n".join([f"{item['quantity']}x {item['Name']} - ${item['price']} each" for item in items])
        email_body = f"""Hello {user_name},
We regret to inform you that your order (Order ID: #{order_number}) has been cancelled due to {reason}.
If this cancellation was in error or you need further assistance, please contact our support team at support@hifideliveryeats.com.
We sincerely apologize for any inconvenience caused and appreciate your understanding.
With regards,
HiFi Delivery Eats Team"""
        
        msg = Message("Order Confirmation - HiFi Delivery Eats", recipients=[user_email])
        msg.body = email_body
        mail.send(msg)
        return True
    except Exception as e:
        print(f'An error occurred: {e}')
        return False
    

# Route for Unassigned Orders page
@app.route('/unassigned-orders')
def unassigned_orders():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    db = get_db_connection()
    cur = db.cursor()
    cur.execute(""" SELECT d.Order_ID,o.total_price,o.delivery_location,u.full_name FROM Delivery d JOIN Orders o ON d.Order_ID = o.order_id
     JOIN Users u ON o.customer_id = u.user_id WHERE d.Status = 'Unassigned' LIMIT 5""")
    orders = cur.fetchall()
    return render_template('unassign_orders.html', orders=orders)

# View More Orders
@app.route('/unassigned-orders/view-more')
def view_more_orders():
    db = get_db_connection()
    cur = db.cursor()
    cur.execute(""" SELECT d.Order_ID,o.total_price,o.delivery_location,u.full_name FROM Delivery d JOIN Orders o ON d.Order_ID = o.order_id
     JOIN Users u ON o.customer_id = u.user_id WHERE d.Status = 'Unassigned'""")
    orders = cur.fetchall()
    return render_template('unassign_orders.html', orders=orders, view_more=True)

@app.route('/assign-dashboard/<int:order_id>')
def agent_assignment_dashboard(order_id):
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    db = get_db_connection()
    cur = db.cursor()

    #Fetch the order count of the agent
    cur.execute('''SELECT da.*,
    COALESCE((SELECT COUNT(*)
        FROM Delivery d
        WHERE d.Delivery_Agent_ID = da.id AND date(d.Delivery_time) = date('now')), 0) as today_orders
    FROM Delivery_agents da
    WHERE da.status = 'available';''')
    order_count = cur.fetchall()
    agents = [{"id":count[0], "name":count[1], "status":count[2], "order_count":count[3]}
                   for count in order_count]

    # Fetch recent activity
    cur.execute("""
        SELECT d.order_id, d.delivery_agent_id
        FROM Delivery d WHERE Status='Assigned'
        ORDER BY d.pickup_time DESC LIMIT 5
    """)
    recent_activities = cur.fetchall()

    recent_activities = [
        {"S_No": i + 1, "order_id": activity[0], "agent_id": activity[1] or "Unassigned"}
        for i, activity in enumerate(recent_activities)
    ]

    # Fetch analytics summary
    cur.execute("SELECT COUNT(*) FROM Delivery WHERE status = 'Unassigned'")
    unassigned_orders = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM Delivery_agents WHERE status = 'available'")
    idle_agents = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM Delivery WHERE status IN ('Assigned', 'Out for delivery')")
    active_deliveries = cur.fetchone()[0]

    analytics_summary = {
        'unassigned_orders': unassigned_orders,
        'idle_agents': idle_agents,
        'active_deliveries': active_deliveries
    }

    return render_template(
        'order_assignment.html',
        agents=agents,
        recent_activities=recent_activities,
        analytics_summary=analytics_summary,
        order_id=order_id
    )

@app.route('/assign_agent/<int:order_id>/<int:agent_id>', methods=['POST'])
def assign_agent(order_id, agent_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # First check if delivery record exists and get its status
        cur.execute("""
            SELECT status 
            FROM Delivery 
            WHERE order_id = ?;
        """, (order_id,))
        
        result = cur.fetchone()
        
        # If no delivery record exists or status is Unassigned
        if not result or result[0] == "Unassigned":
            # Update Delivery table
            cur.execute("""
                UPDATE Delivery
                SET delivery_agent_id = ?, 
                    status = 'Assigned', 
                    pickup_time = NULL, 
                    delivery_time = NULL
                WHERE order_id = ?;
            """, (agent_id, order_id))
            
            # If no rows were updated, we need to insert a new record
            if cur.rowcount == 0:
                cur.execute("""
                    INSERT INTO Delivery (order_id, delivery_agent_id, status, pickup_time, delivery_time)
                    VALUES (?, ?, 'Assigned', NULL, NULL);
                """, (order_id, agent_id))

            # Update Delivery_Agents table
            cur.execute("""
                UPDATE Delivery_Agents
                SET status = 'on delivery'
                WHERE id = ?;
            """, (agent_id,))

            conn.commit()
            conn.close()

            response = {
                "message": f"Agent {agent_id} is assigned to deliver Order {order_id} successfully."
            }
            return jsonify(response), 200
        else:
            conn.close()
            response = {
                "message": f"Agent is already assigned to Order #{order_id}."
            }
            return jsonify(response), 400  # Changed to 400 for better HTTP semantics

    except Exception as e:
        if conn:
            conn.close()
        return jsonify({'error': str(e)}), 500

@app.route('/order-overview')
def order_overview():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    return render_template('order_overview.html')

@app.route('/api/order-stats')
def get_order_stats():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get today's date
    today = datetime.now().date()
    
    # Total orders
    cursor.execute('SELECT COUNT(*) as count FROM Orders')
    total_orders = cursor.fetchone()['count']
    
    # Yearly orders
    cursor.execute('SELECT COUNT(*) as count FROM Orders WHERE order_date >= date("now", "-1 year")')
    yearly_orders = cursor.fetchone()['count']
    
    # Monthly orders
    cursor.execute('SELECT COUNT(*) as count FROM Orders WHERE order_date >= date("now", "-1 month")')
    monthly_orders = cursor.fetchone()['count']
    
    # Daily orders
    cursor.execute('SELECT COUNT(*) as count FROM Orders WHERE date(order_date) = date("now")')
    daily_orders = cursor.fetchone()['count']
    
    conn.close()
    
    return jsonify({
        'total_orders': total_orders,
        'yearly_orders': yearly_orders,
        'monthly_orders': monthly_orders,
        'daily_orders': daily_orders
    })

@app.route('/api/daily-status/<date>')
def get_daily_status(date):
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT 
            CASE 
                WHEN (julianday(Delivery_time) - julianday(Pickup_time)) * 24 * 60 <= 30 THEN 'On Time'
                WHEN (julianday(Delivery_time) - julianday(Pickup_time)) * 24 * 60 <= 45 THEN 'Slightly Delayed'
                WHEN (julianday(Delivery_time) - julianday(Pickup_time)) * 24 * 60 <= 60 THEN 'Delayed'
                ELSE 'Over Delayed'
            END as delivery_status,
            COUNT(*) as count
        FROM Delivery
        WHERE date(Pickup_time) = ?
        GROUP BY delivery_status
    ''', (date,))
    
    results = cursor.fetchall()
    conn.close()
    
    # Ensure all status types are represented
    status_types = ['On Time', 'Slightly Delayed', 'Delayed', 'Over Delayed']
    data = {status: 0 for status in status_types}
    for row in results:
        data[row['delivery_status']] = row['count']
    
    return jsonify({
        'labels': list(data.keys()),
        'data': list(data.values())
    })

@app.route('/api/weekly-status/<date>')
def get_weekly_status(date):
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    selected_date = datetime.strptime(date, '%Y-%m-%d')
    week_start = selected_date - timedelta(days=selected_date.weekday())
    current_date = datetime.now()
    dates = []
    days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    
    # Only include dates up to current date
    for i in range(7):
        day_date = week_start + timedelta(days=i)
        if day_date <= current_date:
            dates.append(day_date.strftime('%Y-%m-%d'))
        else:
            dates.append(None)
    
    status_types = ['On Time', 'Slightly Delayed', 'Delayed', 'Over Delayed']
    result_data = {status: [0] * 7 for status in status_types}
    
    for i, date in enumerate(dates):
        if date:  # Only query for non-future dates
            cursor.execute('''
                SELECT 
                    CASE 
                        WHEN (julianday(Delivery_time) - julianday(Pickup_time)) * 24 * 60 <= 30 THEN 'On Time'
                        WHEN (julianday(Delivery_time) - julianday(Pickup_time)) * 24 * 60 <= 45 THEN 'Slightly Delayed'
                        WHEN (julianday(Delivery_time) - julianday(Pickup_time)) * 24 * 60 <= 60 THEN 'Delayed'
                        ELSE 'Over Delayed'
                    END as delivery_status,
                    COUNT(*) as count
                FROM Delivery
                WHERE date(Pickup_time) = ?
                GROUP BY delivery_status
            ''', (date,))
            
            day_results = cursor.fetchall()
            for row in day_results:
                if row['delivery_status'] in status_types:
                    result_data[row['delivery_status']][i] = row['count']
    
    conn.close()
    
    return jsonify({
        'labels': days,
        'datasets': [
            {
                'label': status,
                'data': result_data[status],
                'fill': True
            } for status in status_types
        ]
    })

@app.route('/api/monthly-status/<month>')
def get_monthly_status(month):
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    year, month = map(int, month.split('-'))
    current_date = datetime.now()
    
    # Get the first and last day of the month
    first_day = datetime(year, month, 1)
    if month == 12:
        last_day = datetime(year + 1, 1, 1) - timedelta(days=1)
    else:
        last_day = datetime(year, month + 1, 1) - timedelta(days=1)
    
    # Only include dates up to current date
    if first_day > current_date:
        return jsonify({
            'labels': [],
            'datasets': []
        })
        
    last_day = min(last_day, current_date)
    
    # Generate all dates in the month up to today
    dates = []
    current = first_day
    while current <= last_day:
        dates.append(current.strftime('%Y-%m-%d'))
        current += timedelta(days=1)
    
    status_types = ['On Time', 'Slightly Delayed', 'Delayed', 'Over Delayed']
    result_data = {status: [0] * len(dates) for status in status_types}
    
    # Query data for each date
    for i, date in enumerate(dates):
        cursor.execute('''
            SELECT 
                CASE 
                    WHEN (julianday(Delivery_time) - julianday(Pickup_time)) * 24 * 60 <= 30 THEN 'On Time'
                    WHEN (julianday(Delivery_time) - julianday(Pickup_time)) * 24 * 60 <= 45 THEN 'Slightly Delayed'
                    WHEN (julianday(Delivery_time) - julianday(Pickup_time)) * 24 * 60 <= 60 THEN 'Delayed'
                    ELSE 'Over Delayed'
                END as delivery_status,
                COUNT(*) as count
            FROM Delivery
            WHERE date(Pickup_time) = ?
            GROUP BY delivery_status
        ''', (date,))
        
        day_results = cursor.fetchall()
        for row in day_results:
            status = row['delivery_status']
            if status in status_types:
                result_data[status][i] = row['count']
    
    conn.close()
    
    return jsonify({
        'labels': [d.split('-')[2] for d in dates],  # Only day numbers
        'datasets': [
            {
                'label': status,
                'data': result_data[status],
                'borderColor': get_status_color(status),
                'backgroundColor': get_status_background_color(status),
                'tension': 0.4,
                'fill': False
            } for status in status_types
        ]
    })

@app.route('/api/yearly-status/<year>')
def get_yearly_status(year):
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    status_types = ['On Time', 'Slightly Delayed', 'Delayed', 'Over Delayed']
    
    result_data = {status: [0] * 12 for status in status_types}
    
    for month in range(12):
        cursor.execute('''
            SELECT 
                CASE 
                    WHEN (julianday(Delivery_time) - julianday(Pickup_time)) * 24 * 60 <= 30 THEN 'On Time'
                    WHEN (julianday(Delivery_time) - julianday(Pickup_time)) * 24 * 60 <= 45 THEN 'Slightly Delayed'
                    WHEN (julianday(Delivery_time) - julianday(Pickup_time)) * 24 * 60 <= 60 THEN 'Delayed'
                    ELSE 'Over Delayed'
                END as delivery_status,
                COUNT(*) as count
            FROM Delivery
            WHERE strftime('%Y', Pickup_time) = ? 
            AND strftime('%m', Pickup_time) = ?
            GROUP BY delivery_status
        ''', (year, f"{month+1:02d}"))
        
        month_results = cursor.fetchall()
        for row in month_results:
            if row['delivery_status'] in status_types:
                result_data[row['delivery_status']][month] = row['count']
    
    conn.close()
    
    return jsonify({
        'labels': months,
        'datasets': [
            {
                'label': status,
                'data': result_data[status],
                'backgroundColor': get_status_color(status)
            } for status in status_types
        ]
    })

def get_status_color(status):
    colors = {
        'On Time': '#32CD32',
        'Slightly Delayed': '#FFD700',
        'Delayed': '#8A2BE2',
        'Over Delayed': '#FF0000'
    }
    return colors.get(status, '#000000')

def get_status_background_color(status):
    colors = {
        'On Time': 'rgba(50, 205, 50, 0.2)',
        'Slightly Delayed': 'rgba(255, 215, 0, 0.2)',
        'Delayed': 'rgba(138, 43, 226, 0.2)',
        'Over Delayed': 'rgba(255, 0, 0, 0.2)'
    }
    return colors.get(status, 'rgba(0, 0, 0, 0.2)')

@app.route('/performance-metrics')
def performance_metrics():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    return render_template('performance_metrics.html')

@app.route('/api/delivery_agents')
def get_delivery_agents():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    conn = get_db_connection()
    query = "SELECT id, name FROM Delivery_agents"
    agents = conn.execute(query).fetchall()
    conn.close()
    return jsonify([{'id': row['id'], 'name': row['name']} for row in agents])

@app.route('/api/performance_thresholds')
def get_performance_thresholds():
    """Get dynamic performance thresholds based on historical data"""
    conn = get_db_connection()
    query = '''
        SELECT 
            ROUND(julianday(d.Delivery_time) * 24 * 60 - 
                  julianday(d.Pickup_time) * 24 * 60) as delivery_minutes
        FROM Delivery d
        WHERE d.Status = 'Delivered on time'
        AND d.Pickup_time IS NOT NULL 
        AND d.Delivery_time IS NOT NULL
    '''
    delivery_times = [row['delivery_minutes'] for row in conn.execute(query).fetchall()]
    conn.close()

    if delivery_times:
        # Calculate thresholds based on actual delivery data
        on_time_threshold = statistics.median(delivery_times)
        slightly_delayed_threshold = on_time_threshold * 1.5
        return {
            'on_time': round(on_time_threshold),
            'slightly_delayed': round(slightly_delayed_threshold)
        }
    else:
        # Fallback default values if no data
        return {'on_time': 30, 'slightly_delayed': 45}

@app.route('/api/performance_data')
def get_performance_data():
    agent_id = request.args.get('agent_id', type=int)
    selected_week = request.args.get('week', type=str)
    selected_month = request.args.get('month', type=str)

    thresholds = get_performance_thresholds()
    
    data = {
        'thresholds': thresholds,
        'overall_performance': get_overall_performance(thresholds),
        'weekly_performance': get_weekly_performance(agent_id, selected_week, thresholds) if agent_id else None,
        'monthly_performance': get_monthly_performance(agent_id, selected_month, thresholds) if agent_id else None
    }
    return jsonify(data)

def calculate_performance_score(delivery_time, pickup_time, thresholds):
    if not delivery_time or not pickup_time:
        return 0
    
    delivery_duration = datetime.strptime(delivery_time, '%Y-%m-%d %H:%M:%S') - \
                       datetime.strptime(pickup_time, '%Y-%m-%d %H:%M:%S')
    minutes = delivery_duration.total_seconds() / 60

    if minutes <= thresholds['on_time']:
        return 100  # On time
    elif minutes <= thresholds['slightly_delayed']:
        return 70   # Slightly delayed
    else:
        return 40   # Over delayed

def get_overall_performance(thresholds):
    conn = get_db_connection()
    query = '''
        SELECT 
            da.id,
            da.name,
            d.Pickup_time,
            d.Delivery_time,
            strftime('%Y-%m', d.Delivery_time) as month,
            COUNT(*) as total_deliveries,
            ROUND(AVG(julianday(d.Delivery_time) * 24 * 60 - 
                     julianday(d.Pickup_time) * 24 * 60), 2) as avg_delivery_time
        FROM Delivery_agents da
        JOIN Delivery d ON da.id = d.Delivery_Agent_ID
        WHERE d.Status IN ('Delivered on time', 'Delivered delayed')
        AND d.Delivery_time IS NOT NULL
        GROUP BY da.id, month
        ORDER BY month;
    '''
    rows = conn.execute(query).fetchall()
    conn.close()

    performance_data = {}
    for row in rows:
        month = row['month']
        if month not in performance_data:
            performance_data[month] = {
                'total_deliveries': 0,
                'performance_scores': []
            }
        
        avg_delivery_time = row['avg_delivery_time']
        score = 100 if avg_delivery_time <= thresholds['on_time'] else \
                70 if avg_delivery_time <= thresholds['slightly_delayed'] else 40
                
        performance_data[month]['performance_scores'].append(score)
        performance_data[month]['total_deliveries'] += row['total_deliveries']

    months = sorted(performance_data.keys())
    avg_performance = [
        sum(performance_data[m]['performance_scores']) / len(performance_data[m]['performance_scores'])
        for m in months
    ]
    total_deliveries = [performance_data[m]['total_deliveries'] for m in months]

    return {
        'months': months,
        'performance': avg_performance,
        'deliveries': total_deliveries
    }

def get_weekly_performance(agent_id, selected_week, thresholds):
    conn = get_db_connection()
    query = '''
        SELECT 
            d.Pickup_time,
            d.Delivery_time,
            ROUND(julianday(d.Delivery_time) * 24 * 60 - 
                  julianday(d.Pickup_time) * 24 * 60) as delivery_minutes
        FROM Delivery d
        WHERE d.Delivery_Agent_ID = ?
        AND date(d.Delivery_time) >= date(?)
        AND date(d.Delivery_time) < date(?, '+7 days')
        AND d.Status IN ('Delivered on time', 'Delivered delayed');
    '''
    rows = conn.execute(query, (agent_id, selected_week, selected_week)).fetchall()
    conn.close()

    delivery_stats = {
        'On Time': 0,
        'Slightly Delayed': 0,
        'Over Delayed': 0,
        'avg_delivery_time': 0
    }
    
    total_deliveries = len(rows)
    if total_deliveries > 0:
        total_minutes = 0
        for row in rows:
            minutes = row['delivery_minutes']
            total_minutes += minutes
            
            if minutes <= thresholds['on_time']:
                delivery_stats['On Time'] += 1
            elif minutes <= thresholds['slightly_delayed']:
                delivery_stats['Slightly Delayed'] += 1
            else:
                delivery_stats['Over Delayed'] += 1
        
        delivery_stats['avg_delivery_time'] = round(total_minutes / total_deliveries, 2)

    return {
        'categories': list(delivery_stats.keys())[:-1],
        'counts': list(delivery_stats.values())[:-1],
        'avg_delivery_time': delivery_stats['avg_delivery_time']
    }

def get_monthly_performance(agent_id, selected_month, thresholds):
    conn = get_db_connection()
    query = '''
        SELECT 
            strftime('%Y-%m-%d', d.Delivery_time) as delivery_date,
            COUNT(*) as total_deliveries,
            ROUND(AVG(julianday(d.Delivery_time) * 24 * 60 - 
                     julianday(d.Pickup_time) * 24 * 60), 2) as avg_delivery_time
        FROM Delivery d
        WHERE d.Delivery_Agent_ID = ?
        AND strftime('%Y-%m', d.Delivery_time) = ?
        AND d.Status IN ('Delivered on time', 'Delivered delayed')
        GROUP BY delivery_date
        ORDER BY delivery_date;
    '''
    rows = conn.execute(query, (agent_id, selected_month)).fetchall()
    conn.close()

    dates = []
    scores = []
    deliveries = []
    
    for row in rows:
        dates.append(row['delivery_date'])
        avg_time = row['avg_delivery_time']
        score = 100 if avg_time <= thresholds['on_time'] else \
                70 if avg_time <= thresholds['slightly_delayed'] else 40
        scores.append(score)
        deliveries.append(row['total_deliveries'])

    return {
        'dates': dates,
        'scores': scores,
        'deliveries': deliveries
    }


@app.route('/order-management')
def order_management():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    return render_template('order_management.html')

@app.route('/api/orders', methods=['GET'])
def get_orders():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    search_query = request.args.get('search', '')
    status_filter = request.args.get('status', '')
    sort_price = request.args.get('sort') == 'true'
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))  # Default 20 for first load
    
    query = '''
        SELECT 
            o.order_id,
            u.full_name,
            u.user_id,
            o.total_price,
            o.order_status,
            o.delivery_location
        FROM Orders o
        JOIN Users u ON o.customer_id = u.user_id
        WHERE 1=1
    '''
    count_query = '''
        SELECT COUNT(*) as total
        FROM Orders o
        JOIN Users u ON o.customer_id = u.user_id
        WHERE 1=1
    '''
    
    params = []
    
    if search_query:
        query += ' AND o.order_id LIKE ?'
        count_query += ' AND o.order_id LIKE ?'
        params.append(f'%{search_query}%')
    
    if status_filter:
        if status_filter == 'delivered':
            query += " AND o.order_status = 'Completed'"
            count_query += " AND o.order_status = 'Delivered'"
        elif status_filter == 'progress':
            query += " AND (o.order_status = 'Out for Delivery')"
            count_query += " AND (o.order_status = 'Out for Delivery')"
        elif status_filter == 'cancelled':
            query += " AND o.order_status = 'Cancelled'"
            count_query += " AND o.order_status = 'Cancelled'"
        elif status_filter == 'preparing':
            query += " AND o.order_status = 'Preparing'"
            count_query += " AND o.order_status = 'Preparing'"
        elif status_filter == 'pending':
            query += " AND o.order_status = 'Pending'"
            count_query += " AND o.order_status = 'Pending'"
    
    if sort_price:
        query += ' ORDER BY o.total_price ASC'
    else:
        query += ' ORDER BY o.order_id DESC'
    
    # Add pagination
    offset = (page - 1) * per_page
    query += ' LIMIT ? OFFSET ?'
    params.extend([per_page, offset])
    
    # Get total count
    cursor.execute(count_query, params[:-2] if params else [])
    total_count = cursor.fetchone()['total']
    
    # Get paginated orders
    cursor.execute(query, params)
    orders = cursor.fetchall()
    
    orders_list = []
    for order in orders:
        orders_list.append({
            'order_id': order['order_id'],
            'customer_name': order['full_name'],
            'user_id': f'User ID: {order["user_id"]}',
            'amount': order['total_price'],
            'status': order['order_status'],
            'address': order['delivery_location']
        })
    
    response = {
        'orders': orders_list,
        'total_count': total_count,
        'has_more': (page * per_page) < total_count
    }
    
    conn.close()
    return jsonify(response)

@app.route('/admin/order/<int:order_id>', methods = ['GET','POST'])
def order_details(order_id):
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    conn = get_db_connection()
    
    # Get order details with customer information
    order = conn.execute('''
        SELECT Orders.*, Users.full_name, Users.email, Users.phone_number, Orders.delivery_location
        FROM Orders 
        JOIN Users ON Orders.customer_id = Users.user_id 
        WHERE order_id = ?
    ''', (order_id,)).fetchone()
    
    # Get order items with menu item details
    items = conn.execute('''
        SELECT Order_Items.*, MenuItems.Name, MenuItems.Description, MenuItems.ImageURL,
               round((Order_Items.quantity * Order_Items.price),2) as total_price
        FROM Order_Items 
        JOIN MenuItems ON Order_Items.item_id = MenuItems.MenuItemID
        WHERE order_id = ?
    ''', (order_id,)).fetchall()
    
    # Calculate order totals
    subtotal = sum(item['total_price'] for item in items)
    tax = subtotal * 0.1  # 10% tax
    delivery_fee = 100    # Fixed delivery fee
    total = round(subtotal + tax + delivery_fee,2)
    
    # Get delivery information
    delivery = conn.execute('''
        SELECT d.*, da.name as agent_name, da.status as agent_status
        FROM Delivery d
        LEFT JOIN Delivery_agents da ON d.Delivery_Agent_ID = da.id
        WHERE d.Order_ID = ?
    ''', (order_id,)).fetchone()
    
    # Get available delivery agents
    available_agents = conn.execute('''
        SELECT * FROM Delivery_agents WHERE status = 'available'
    ''').fetchall()
    
    conn.close()
    
    if request.method == 'GET':
        return render_template('order_status_endpoint.html',
                            order=order,
                            items=items,
                            delivery=delivery,
                            available_agents=available_agents,
                            subtotal=subtotal,
                            tax=tax,
                            delivery_fee=delivery_fee,
                            total=total)

    if request.method == 'POST':
        order_id = request.json.get('order_id')
        new_status = request.json.get('status')
        cancellation_reason = request.json.get('cancellation_reason')
        existing_status = order['order_status']
        
        conn = get_db_connection()
        try:
            if new_status:
                if new_status == 'out_for_delivery':
                    if existing_status == 'Completed':
                        return jsonify({'success': False, 'message': "Unable to update status as the order has already been delivered."})
                    # Updates Delivery table
                    conn.execute('''
                        UPDATE Delivery 
                        SET Status = ?, Pickup_time = ?, Delivery_time = ?
                        WHERE Order_ID = ?
                    ''', ("Out for Delivery", datetime.now(), None, order_id))
                    # Updates Order table
                    conn.execute('UPDATE Orders SET order_status = ? WHERE order_id = ?',
                        ("Out for Delivery", order_id))
                    conn.commit()
                    
                    #send update to the customer through email
                    if send_order_out_for_delivery_update(order['email'], order['full_name'], order_id, items, total):
                        return jsonify({'success': True, 'message': 'Status updated successfully and email update notification to user'})
                    else:
                        return jsonify({'success': True, 'message': "Order status updated successfully, but failed to send email notification"})
                        
                elif new_status == 'Delivered':
                    if existing_status == 'Completed':
                        return jsonify({'success': False, 'message': "Unable to update status as the order has already been delivered."})
                    
                    elif existing_status == 'Cancelled':
                        return jsonify({'success': False, 'message': "A canceled order cannot be directly updated to Delivered."})
                    # First, get the pickup time
                    pickup_time_result = conn.execute('''
                        SELECT Pickup_time 
                        FROM Delivery 
                        WHERE Order_ID = ?
                    ''', (order_id,)).fetchone()
                    
                    if pickup_time_result and pickup_time_result[0]:
                        # Convert string timestamp to datetime object if needed
                        pickup_time = datetime.fromisoformat(pickup_time_result[0]) if isinstance(pickup_time_result[0], str) else pickup_time_result[0]
                        current_time = datetime.now()
                        
                        # Calculate time difference in minutes
                        time_difference = (current_time - pickup_time).total_seconds() / 60
                        
                        # Set appropriate status based on delivery time
                        delivery_status = "Delivered on time" if time_difference <= 30 else "Delivered Delayed"
                        
                        conn.execute('''
                            UPDATE Delivery 
                            SET Status = ?, Delivery_time = ?
                            WHERE Order_ID = ?
                        ''', (delivery_status, current_time, order_id))
                        
                        conn.execute('UPDATE Orders SET order_status = ? WHERE order_id = ?',
                            ("Completed", order_id))
                        conn.commit()
                        
                        if send_order_delivered_update(order['email'], order['full_name'], order_id, items, total):
                            return jsonify({'success': True, 'message': 'Status updated successfully and email update notification to user'})
                        else:
                            return jsonify({'success': True, 'message': "Order status updated successfully, but failed to send email notification"})
                    
                    else:
                        return jsonify({'success': False, 'message': 'Pickup time not found'}), 400
                        
                elif new_status == 'cancelled':
                    if existing_status == 'Completed':
                        return jsonify({'success': False, 'message': "Unable to update status as the order has already been delivered."})

                    if not cancellation_reason:
                        return jsonify({'success': False, 'message': "Cancellation reason is required"})
                    
                    conn.execute('''UPDATE Delivery SET Status = ? WHERE Order_ID = ?''', 
                                ("Cancelled", order_id))
                    # Updates Order table
                    conn.execute('UPDATE Orders SET order_status = ? WHERE order_id = ?',
                        ("Cancelled", order_id))
                    conn.commit()
                    
                    if send_order_cancelled_update(order['email'], order['full_name'], order_id, items, cancellation_reason):
                            return jsonify({'success': True, 'message': 'Status updated successfully and email update notification to user'})
                    else:
                        return jsonify({'success': True, 'message': "Order status updated successfully, but failed to send email notification"})
                    
                        
                elif new_status == 'preparing':
                    if existing_status == 'Completed':
                        return jsonify({'success': False, 'message': "Unable to update status as the order has already been delivered."})

                    # Fetch delivery agent ID
                    result = conn.execute('''
                        SELECT Delivery_Agent_ID FROM Delivery WHERE Order_ID = ?
                    ''', (order_id,)).fetchone()
                    
                    # Set status based on delivery agent assignment
                    if result and result[0]:  # Check if delivery agent exists
                        delivery_status = "Assigned"
                    else:
                        delivery_status = "Unassigned"
                        
                    conn.execute('''UPDATE Delivery SET Status = ? WHERE Order_ID = ?''', (delivery_status, order_id))
                    
                    # Updates Order table
                    conn.execute('UPDATE Orders SET order_status = ? WHERE order_id = ?',
                        ("Preparing", order_id))
                    conn.commit()

                    return jsonify({'success': True, 'message': 'Status updated successfully'})
                    
                elif new_status == 'order_confirmed':
                    print('yes')
                    if existing_status == 'Completed':
                        return jsonify({'success': False, 'message': "Unable to update status as the order has already been delivered."})

                    conn.execute('''UPDATE Delivery SET Status = ? WHERE Order_ID = ?''', ("Unassigned", order_id))
                    
                    # Updates Order table
                    conn.execute('UPDATE Orders SET order_status = ? WHERE order_id = ?',
                        ("Order Confirmed", order_id))
                    conn.commit()
                    
                    if send_order_confirmation_update(order['email'], order['full_name'], order_id, items, total):
                        return jsonify({'success': True, 'message': 'Status updated successfully and email update notification to user'})
                    else:
                        return jsonify({'success': True, 'message': "Order status updated successfully, but failed to send email notification"})
                
                elif new_status == "pending":
                    if existing_status == 'Completed':
                        return jsonify({'success': False, 'message': "Unable to update status as the order has already been delivered."})

                    return jsonify({'success': False, 'message': 'Confirmed order cannot be update to pending'})
                
                else:
                    return jsonify({'success': False, 'message': 'There is no such status'})
                

        except Exception as e:
            return jsonify({'success': False, 'message': str(e)}), 500
        finally:
            conn.close()


@app.route('/api/available-agents', methods=['GET'])
def available_agents():
    conn = get_db_connection()
    cursor=conn.cursor()

    try:
        # Fetch available delivery agents
        cursor.execute('''SELECT da.*,
        COALESCE((SELECT COUNT(*)
            FROM Delivery d
            WHERE d.Delivery_Agent_ID = da.id AND date(d.Delivery_time) = date('now')), 0) as today_orders
        FROM Delivery_agents da
        WHERE da.status = 'available';''')

        agents = cursor.fetchall()

        agent = [{"id":count[0], "name":count[1], "status":count[2], "order_count":count[3]}
                    for count in agents]

        return jsonify(agent)
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/reassign-agent', methods=['POST'])
def reassign_agent():
    order_id = request.json.get('order_id')
    new_agent_id = request.json.get('agent_id')
    
    conn = get_db_connection()
    try:
        # Get current agent ID
        current_delivery = conn.execute('''
            SELECT Delivery_Agent_ID 
            FROM Delivery 
            WHERE Order_ID = ?
        ''', (order_id,)).fetchone()
        
        if current_delivery and current_delivery['Delivery_Agent_ID']:
            # Update old agent status to available
            conn.execute('''
                UPDATE Delivery_agents 
                SET status = 'available' 
                WHERE id = ?
            ''', (current_delivery['Delivery_Agent_ID'],))
        
        # Update delivery with new agent
        conn.execute('''UPDATE Delivery SET Delivery_Agent_ID = ? WHERE Order_ID = ?
        ''', (new_agent_id, order_id))
        
        # Update new agent status
        conn.execute('''UPDATE Delivery_agents SET status = 'On Delivery' WHERE id = ?
        ''', (new_agent_id,))
        
        conn.commit()
        return jsonify({'success': True,'message': 'Delivery agent reassigned successfully'})
    
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        conn.close()


@app.route('/staff-details')
def staff_list():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    conn = get_db_connection()
    staff_data = {}
    
    cursor = conn.execute('''
        SELECT da.id, da.name, da.status, u.email, u.phone_number as phone, u.created_at
        FROM Delivery_agents da
        JOIN Users u ON da.id = u.user_id''')
    
    staff_data = []
    for row in cursor:
        staff_data.append({
            'id': str(row['id']),
            'name': row['name'],
            'email': row['email'],
            'phone': row['phone'],
            'status': row['status']
        })
    conn.close()
    return render_template('staff_list.html', staff_data=staff_data)

@app.route('/api/staff/search')
def search_staff():
    query = request.args.get('q', '').strip()
    
    conn = get_db_connection()
    base_query = '''SELECT da.id, da.name, da.status, u.email, u.phone_number as phone
        FROM Delivery_agents da
        JOIN Users u ON da.id = u.user_id'''
    
    if query and query.isdigit():
        base_query += ' WHERE da.id = ?'
        cursor = conn.execute(base_query, [query])
    else:
        cursor = conn.execute(base_query + ' ORDER BY da.id ASC')
    
    staff_data = []
    for row in cursor:
        staff_data.append({
            'id': str(row['id']),
            'name': row['name'],
            'email': row['email'],
            'phone': row['phone'],
            'status': row['status']
        })
    
    conn.close()
    return jsonify({'success': True, 'data': staff_data})

@app.route('/api/staff/filter')
def filter_staff():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    filter_type = request.args.get('type', '')
    
    conn = get_db_connection()
    base_query = '''SELECT da.id, da.name, da.status, u.email, u.phone_number as phone
        FROM Delivery_agents da
        JOIN Users u ON da.id = u.user_id'''
    
    if filter_type == 'agent-id':
        base_query += ' ORDER BY da.id ASC'
    elif filter_type == 'agent-name':
        base_query += ' ORDER BY da.name ASC'
    elif filter_type == 'status':
        base_query += ''' ORDER BY 
            CASE da.status
                WHEN 'available' THEN 1
                WHEN 'in delivery' THEN 2
                WHEN 'off duty' THEN 3
                ELSE 4
            END'''
    
    cursor = conn.execute(base_query)
    staff_data = []
    for row in cursor:
        staff_data.append({
            'id': str(row['id']),
            'name': row['name'],
            'email': row['email'],
            'phone': row['phone'],
            'status': row['status']
        })
    
    conn.close()
    print(staff_data)
    return jsonify({'success': True, 'data': staff_data})

@app.route('/api/staff/add', methods=['POST'])
def add_staff():
    data = request.get_json()

    # Validate required fields
    required_fields = ['name', 'email', 'phone']
    if not all(field in data for field in required_fields):
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400
    
    conn = get_db_connection()
    try:
        existing_user= conn.execute(''' SELECT * FROM Users WHERE full_name = ? AND phone_number = ? AND email = ?''',
                                    (data['name'],data['phone'],data['email'])).fetchone()

        if existing_user:
            user_id=existing_user['user_id']
            name=existing_user['full_name']

            conn.execute('''INSERT INTO Delivery_agents (id, name, status) VALUES (?, ?, ?)''',
                         (user_id,name,"available"))
            conn.commit()
            return jsonify({'success': True, 'message': 'Staff added successfully'})
        
        elif not existing_user:
            conn.close()
            return jsonify({'success': False, 'message': 'No user found with these details. Please verify the information.'
            }), 404
        else:
            conn.close()
            return jsonify({'success': False, 'message': 'Issue in finding the agent'}), 404

    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        conn.close()

        
@app.route('/api/staff/remove', methods=['POST'])
def remove_staff():
    data = request.get_json()
    if 'agent_id' not in data:
        return jsonify({'success': False, 'message': 'Agent ID is required'}), 400
    
    conn = get_db_connection()
    try:
        # Check if agent exists and has no active deliveries
        active_deliveries = conn.execute('''SELECT COUNT(*) as count FROM Delivery WHERE Delivery_Agent_ID = ? AND Status NOT IN ('Delivered', 'Cancelled')
        ''', (data['agent_id'],)).fetchone()
        
        if active_deliveries['count'] > 0:
            return jsonify({'success': False, 'message': 'Cannot remove agent with active deliveries'}), 400
        
        available_agent_id = [id[0] for id in conn.execute("SELECT id FROM Delivery_agents").fetchall()]

        if int(data['agent_id']) in available_agent_id:
            # Remove agent from delivery_agents table
            conn.execute('DELETE FROM Delivery_agents WHERE id = ?', (data['agent_id'],))
            conn.commit()
            return jsonify({'success': True, 'message': 'Staff removed successfully'})
        
        elif int(data['agent_id']) not in available_agent_id:
            return jsonify({'success': False, 'message': 'Invalid agent ID: The provided ID does not correspond to an existing delivery agent'})
        
        else:
            return jsonify({'success': False, 'message': 'Error in removing an agent'})
    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        conn.close()

@app.route('/staff/<agent_id>')
def staff_details(agent_id):
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    conn = get_db_connection()
    
    # Get staff member details
    staff = conn.execute('''SELECT da.*, u.email, u.phone_number, u.created_at, da.name as full_name, u.user_id
        FROM Delivery_agents da
        JOIN Users u ON da.id = u.user_id
        WHERE da.id = ?''', (agent_id,)).fetchone()
    
    if not staff:
        conn.close()
        return "Staff member not found", 404
    
    # Calculate service years
    created_date = datetime.strptime(staff['created_at'], '%Y-%m-%d %H:%M:%S.%f')
    years_of_service = relativedelta(datetime.now(), created_date).years
    
    # Get total orders
    total_orders = conn.execute('''SELECT COUNT(*) as count FROM Delivery WHERE Delivery_Agent_ID = ?
    ''', (agent_id,)).fetchone()['count']
    
    # Get daily metrics
    selected_date = request.args.get('date', date.today().isoformat())
    
    metrics = conn.execute('''SELECT 
            COUNT(CASE WHEN Status = 'Cancelled' THEN 1 END) as cancelled_deliveries,
            COUNT(CASE WHEN Status IN ('Delivered on time', 'Delivered delayed') THEN 1 END) as completed_deliveries,
            COUNT(*) as total_deliveries
        FROM Delivery
        WHERE Delivery_Agent_ID = ?
        AND DATE(Pickup_time) = DATE(?)
    ''', (agent_id, selected_date)).fetchone()
    
    staff_dict = dict(staff)
    metrics_dict = dict(metrics)
    
    conn.close()
    
    return render_template('staff_details.html',user=staff_dict,years_of_service=years_of_service,total_orders=total_orders,
                         metrics=metrics_dict,selected_date=selected_date)


@app.route('/api/agent-metrics/<agent_id>')
def get_agent_metrics(agent_id):
    conn = get_db_connection()
    
    # Get total orders and metrics
    metrics = conn.execute('''SELECT 
            COUNT(DISTINCT d.Order_ID) as total_orders,
            ROUND(AVG(CASE 
                WHEN d.Status = 'Delivered on time' THEN 5
                WHEN d.Status = 'Delivered delayed' THEN 3
                ELSE 0 END), 1) as rating
        FROM Delivery d
        WHERE d.Delivery_Agent_ID = ?
        AND d.Status IN ('Delivered on time', 'Delivered delayed')
    ''', (agent_id,)).fetchone()
    
    # Get service years
    agent = conn.execute('''SELECT created_at FROM Users WHERE user_id = ?
    ''', (agent_id,)).fetchone()
    
    service_years = 0
    if agent:
        created_date = datetime.strptime(agent['created_at'], '%Y-%m-%d %H:%M:%S')
        service_years = relativedelta(datetime.now(), created_date).years
    
    conn.close()
    
    return jsonify({
        'success': True,
        'data': {'total_orders': metrics['total_orders'],'service_years': service_years,'rating': metrics['rating'],}})

@app.route('/api/agent-status/<agent_id>')
def get_agent_status(agent_id):
    conn = get_db_connection()
    
    # Get delivery metrics
    status = conn.execute('''SELECT 
            COUNT(CASE WHEN Status IN ('Assigned', 'Out for Delivery') THEN 1 END) as ongoing_deliveries,
            COUNT(CASE WHEN Status IN ('Delivered on time', 'Delivered delayed') THEN 1 END) as completed_deliveries,
            da.status as current_status
        FROM Delivery d
        JOIN Delivery_agents da ON da.id = d.Delivery_Agent_ID
        WHERE d.Delivery_Agent_ID = ?
        AND DATE(d.Pickup_time) = DATE('now')
    ''', (agent_id,)).fetchone()
    
    conn.close()
    
    return jsonify({'success': True,'data': {
            'ongoing_deliveries': status['ongoing_deliveries'],
            'completed_deliveries': status['completed_deliveries'],
            'total_deliveries': status['ongoing_deliveries'] + status['completed_deliveries'],
            'status': status['current_status']}})


@app.route('/admin')
def admin():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    return render_template('adminpanel.html')

@app.route('/api/menu_items', methods=['GET', 'POST'])
def menu_items():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method == 'GET':
        # Fetch menu items
        try:
            cursor.execute('''
                SELECT 
                    mi.MenuItemID, 
                    mi.Name, 
                    mi.Description, 
                    mi.Price, 
                    mi.ImageURL, 
                    mi.AvailabilityStatus,
                    c.CategoryName,
                    c.CategoryID,
                    GROUP_CONCAT(dp.PreferenceName, ', ') as DietaryPreferences
                FROM MenuItems mi
                LEFT JOIN Category c ON mi.CategoryID = c.CategoryID
                LEFT JOIN MenuItemDietaryPreferences midp ON mi.MenuItemID = midp.MenuItemID
                LEFT JOIN DietaryPreferences dp ON midp.PreferenceID = dp.PreferenceID
                GROUP BY mi.MenuItemID
            ''')
            menu_items = cursor.fetchall()
            return jsonify([dict(item) for item in menu_items])
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        finally:
            conn.close()

    elif request.method == 'POST':
        # Add new menu item
        data = request.json
        try:
            cursor.execute('''
                INSERT INTO MenuItems 
                (Name, Description, Price, CategoryID, AvailabilityStatus, ImageURL) 
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                data['Name'], 
                data['Description'], 
                float(data['Price']), 
                int(data['CategoryID']), 
                data.get('AvailabilityStatus', 1),
                data.get('ImageURL', '')
            ))
            menu_item_id = cursor.lastrowid

            if 'DietaryPreferences' in data and data['DietaryPreferences']:
                cursor.executemany('''
                    INSERT INTO MenuItemDietaryPreferences (MenuItemID, PreferenceID) 
                    VALUES (?, ?)
                ''', [(menu_item_id, pref_id) for pref_id in data['DietaryPreferences']])

            conn.commit()
            return jsonify({"message": "Menu item added successfully", "id": menu_item_id}), 201
        except Exception as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 400
        finally:
            conn.close()

# Update existing menu item
@app.route('/api/menu_items', methods=['PUT'])
def update_menu_item():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    try:
        data = request.json
        menu_item_id = data.get('MenuItemID')

        if not menu_item_id:
            return jsonify({"error": "MenuItemID is required"}), 400

        # Database connection
        conn = get_db_connection()
        cursor = conn.cursor()

        # Update query
        cursor.execute('''
            UPDATE MenuItems
            SET Name = ?, Description = ?, Price = ?, CategoryID = ?, ImageURL = ?, AvailabilityStatus = ?, ModifiedDate = CURRENT_TIMESTAMP
            WHERE MenuItemID = ?
        ''', (
            data.get('Name'),
            data.get('Description'),
            data.get('Price'),
            data.get('CategoryID'),
            data.get('ImageURL'),
            data.get('AvailabilityStatus'),
            menu_item_id
        ))

        conn.commit()
        conn.close()

        if cursor.rowcount == 0:
            return jsonify({"error": "No menu item found with the given ID"}), 404

        return jsonify({"message": "Menu item updated successfully"}), 200

    except Exception as e:
        # Log the error for debugging
        print(f"Error: {e}")
        return jsonify({"error": "An internal error occurred"}), 500

# Delete menu item
@app.route('/api/menu_items/<int:item_id>', methods=['DELETE'])
def modify_menu_item(item_id):
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'DELETE':
        # Delete menu item
        try:
            cursor.execute('DELETE FROM MenuItemDietaryPreferences WHERE MenuItemID=?', (item_id,))
            cursor.execute('DELETE FROM MenuItems WHERE MenuItemID=?', (item_id,))
            conn.commit()
            return jsonify({"message": "Menu item deleted successfully"}), 200
        except Exception as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 400
        finally:
            conn.close()

@app.route('/api/categories', methods=['GET'])
def get_categories():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT * FROM Category')
        categories = cursor.fetchall()
        return jsonify([dict(category) for category in categories])
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

#Export pdf
@app.route('/api/export_menu_items', methods=['GET'])
def export_menu_items():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            SELECT 
                mi.Name, 
                mi.Description, 
                mi.Price, 
                mi.ImageURL,
                c.CategoryName
            FROM MenuItems mi
            LEFT JOIN Category c ON mi.CategoryID = c.CategoryID
        ''')
        menu_items = cursor.fetchall()

        # Create PDF
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)

        pdf.cell(200, 10, txt="Menu Items", ln=True, align='C')
        pdf.ln(10)

        for item in menu_items:
            pdf.set_font("Arial", 'B', size=12)
            pdf.cell(0, 10, f"Name: {item['Name']}", 0, 1)
            pdf.set_font("Arial", size=12)
            pdf.cell(0, 10, f"Description: {item['Description']}", 0, 1)
            pdf.cell(0, 10, f"Price: ${item['Price']:.2f}", 0, 1)
            pdf.cell(0, 10, f"Category: {item['CategoryName']}", 0, 1)
            
            """Add Image
            image_path = item['ImageURL']
            if image_path:
                # Construct the absolute path to the image
                absolute_image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_path.lstrip('/'))
                print(f"Checking image path: {absolute_image_path}")  # Debugging line
                if os.path.exists(absolute_image_path):
                    pdf.cell(0, 10, 'Image:', 0, 1)
                    pdf.image(absolute_image_path, x=10, y=None, w=50, h=30)  # Adjust image size and position as needed
                else:
                    pdf.cell(0, 10, 'Image: N/A', 0, 1)
                    print(f"Image not found: {absolute_image_path}")  # Log missing or invalid images
            else:
                pdf.cell(0, 10, 'Image: N/A', 0, 1)
            """

            pdf.ln(5)

        # Save PDF to a temporary file
        pdf_file_path = 'static/uploads/menu_items.pdf'
        pdf.output(pdf_file_path)

        return send_file(pdf_file_path, as_attachment=True)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()
@app.route("/issues_reported")
def issues_reported():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('signin'))
    
    """
    Render the page showing all reported issues.
    """
    conn = get_db_connection()
    issues = conn.execute("SELECT * FROM Issues").fetchall()  # Fetch all issues from the database
    conn.close()
    return render_template("issuereported.html", issues=issues)


# Predefined list of available delivery pincodes in Andhra Pradesh (AP)
available_pincodes = [743376, 743329, 743363, 743355, 743611, 743337, 743502, 743372, 743384, 743387]

# Connects to SQLite3 database
def get_db_connection():
    conn = sqlite3.connect('Order_assignment.db')
    conn.row_factory = sqlite3.Row
    return conn

# Sends confirmation email to the customer
def send_order_confirmation_email(user_email, user_name, order_number, items, total_amount):
    try:
        items_str = "\n".join([f"{item['quantity']}x {item['item_name']} - ${item['price']} each" for item in items])
        email_body = f"""Hello {user_name}, 
Thank you for placing your order with HiFi Delivery Eats. 
We are pleased to confirm receipt of your order (Order ID: #{order_number}), and it is now being prepared. 
Order Summary: 
{items_str} 
Total Amount: ${total_amount} 
You will receive a notification once your order has been shipped. 
If you have any questions or require assistance, please feel free to contact our support team at support@hifideliveryeats.com. 
We appreciate your trust in HiFi Delivery Eats and look forward to serving you again soon. 
With regards,
HiFi Delivery Eats Team"""
        
        msg = Message("Order Confirmation - HiFi Delivery Eats", recipients=[user_email])
        msg.body = email_body
        mail.send(msg)
        print(f"Order confirmation email sent to {user_email}")
        return True
    except Exception as e:
        print(f'An error occurred: {e}')
        return False

# Sends confirmation email to the customer
def send_order_cancellation_email(user_email, user_name, order_number):
    try:
        email_body = f"""Hello {user_name},
Your order (Order ID: #{order_number}) has been successfully canceled as per your request.
If you have any questions or need further assistance, please feel free to contact our support team at support@hifideliveryeats.com.
We hope to serve you again in the future and thank you for choosing HiFi Delivery Eats.
With regards,
HiFi Delivery Eats Team"""
        
        msg = Message("Order cancellation - HiFi Delivery Eats", recipients=[user_email])
        msg.body = email_body
        mail.send(msg)
        print(f"Order cancellation email sent to {user_email}")
        return True
    except Exception as e:
        print(f'An error occurred: {e}')
        return False

@app.route('/menu/<int:user_id>')
def menu(user_id):
    if not is_customer():
        flash('Access denied. Users only.', 'error')
        return redirect(url_for('signin'))
    
    return render_template('menu.html',user_id=user_id)

@app.route('/api/dietary_preferences', methods=['GET'])
def get_dietary_preferences():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT * FROM DietaryPreferences')
        preferences = cursor.fetchall()
        return jsonify([dict(preference) for preference in preferences])
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# MENU PAGE: Fetch and render menu items or add items to the cart
@app.route('/api/menu_items/<int:user_id>', methods=['GET', 'POST'])
def render_or_add_to_cart(user_id):
    conn = get_db_connection()

    if request.method == 'GET':
        try:
            # Fetch menu items
            items = conn.execute('''
                SELECT mi.MenuItemID AS id, mi.Name AS name, mi.Description AS description, 
                       mi.Price AS price, mi.ImageURL AS image_url, mi.AvailabilityStatus AS availability, 
                       c.CategoryName AS category, c.CategoryID AS CategoryID,
                       GROUP_CONCAT(dp.PreferenceName, ', ') AS dietary_preferences
                FROM MenuItems mi
                LEFT JOIN Category c ON mi.CategoryID = c.CategoryID
                LEFT JOIN MenuItemDietaryPreferences midp ON mi.MenuItemID = midp.MenuItemID
                LEFT JOIN DietaryPreferences dp ON midp.PreferenceID = dp.PreferenceID
                WHERE mi.AvailabilityStatus = 1
                GROUP BY mi.MenuItemID
            ''').fetchall()
            
            menu_items = [dict(item) for item in items]

            # Fetch cart count
            cart_count = get_cart_count(user_id)

            # Return menu items and cart count as JSON
            return jsonify({
                "menu_items": menu_items,
                "cart_count": cart_count,
                "user_id": user_id
            }), 200
        except Exception as e:
            return jsonify({"error": f"An error occurred: {e}"}), 500
        finally:
            conn.close()

    elif request.method == 'POST':
        try:
            # Parse JSON data from the request
            data = request.get_json()

            if not data:
                return jsonify({"error": "Invalid JSON payload"}), 400

            item_id = data.get('item_id')
            quantity = data.get('quantity', 1)  # Default to 1
            price = data.get('price')

            if not all([item_id, price]):
                return jsonify({"error": "All fields are required"}), 400

            # Check if the item already exists in the cart
            existing_item = conn.execute(
            'SELECT quantity FROM Cart WHERE customer_id = ? AND item_id = ?',
            (user_id, item_id),
            ).fetchone()
            print("Existing item in cart:", existing_item)

            if existing_item:
                # Update the quantity if the item exists
                new_quantity = existing_item['quantity'] + quantity
                conn.execute(
                '''UPDATE Cart SET quantity = ? WHERE customer_id = ? AND item_id = ?''',
                (new_quantity, user_id, item_id),
                )
                print(f"Updated item quantity to {new_quantity}")
            else:
                # Insert a new item into the cart
                conn.execute(
                '''INSERT INTO Cart (customer_id, item_id, quantity, price) VALUES (?, ?, ?, ?)''',
                (user_id, item_id, quantity, price),
                )

            conn.commit()

            # Fetch the updated cart count
            cart_count = get_cart_count(user_id)

            return jsonify({"message": "Item added to cart successfully", "cart_count": cart_count}), 200
        except Exception as e:
            print(f"Error occurred: {e}")  # Debugging any errors
            return jsonify({"error": f"An error occurred: {e}"}), 500
        finally:
            conn.close()

def get_cart_count(user_id):
    conn = get_db_connection()
    cart_count = conn.execute(
        'SELECT SUM(quantity) FROM Cart WHERE customer_id = ?', (user_id,)
    ).fetchone()[0]  # Fetch the total quantity
    conn.close()
    # Return cart count in a JSON response
    return cart_count or 0

@app.route('/cart/count/<int:user_id>')
def get_cart_count_api(user_id):
    count = get_cart_count(user_id)
    return jsonify({'count': count})

# Render the cart items
@app.route('/cart/<int:user_id>', methods=['GET'])
def render_cart(user_id):
    if not is_customer():
        flash('Access denied. Users only.', 'error')
        return redirect(url_for('signin'))
    
    conn = get_db_connection()
    cart_items = conn.execute(
        ''' SELECT Cart.item_id, MenuItems.Name AS name, Cart.quantity, Cart.price, MenuItems.ImageURL as image_url
            FROM Cart
            JOIN MenuItems ON Cart.item_id = MenuItems.MenuItemID
            WHERE Cart.customer_id = ? ''', (user_id,)
    ).fetchall()

    total_price = round(sum(item['quantity'] * item['price'] for item in cart_items), 2)
    conn.close()
    return render_template('cart.html', cart_items=cart_items, total_price=total_price, user_id=user_id)

# fetch cart items
@app.route('/api/cart/<int:user_id>', methods=['GET'])
def fetch_cart(user_id):
    conn = get_db_connection()
    cart_items = conn.execute(
        ''' SELECT Cart.item_id, Cart.quantity, Cart.price, MenuItems.Name AS name, MenuItems.ImageURL AS image_url
            FROM Cart
            JOIN MenuItems ON Cart.item_id = MenuItems.MenuItemID
            WHERE Cart.customer_id = ? ''', (user_id,)
    ).fetchall()
    conn.close()

    # Format the response
    return jsonify([{"item_id": item["item_id"],"name": item["name"],"quantity": item["quantity"],"price": float(item["price"]),
                     "image_url": item["image_url"]} for item in cart_items])

@app.route('/cart/update', methods=['POST'])
def update_cart_quantity():
    try:
        data = request.get_json()
        item_id = data.get('item_id')
        quantity = data.get('quantity')

        # Validate input
        if not item_id or not isinstance(quantity, int) or quantity < 0:
            return jsonify({"error": "Invalid data"}), 400

        conn = get_db_connection()
        
        if quantity == 0:
            # Delete the item if quantity is 0
            conn.execute('''DELETE FROM Cart WHERE item_id = ?''',
                (item_id,))
        else:
            # Update the quantity if it's greater than 0
            conn.execute('''UPDATE Cart SET quantity = ? WHERE item_id = ?''',
                (quantity, item_id))
            
        conn.commit()
        conn.close()

        return jsonify({"message": "Cart updated successfully","new_quantity": quantity,"removed": quantity == 0}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

#updating total price in the cart
@app.route('/cart/total/<int:user_id>', methods=['GET'])
def fetch_cart_total(user_id):
    conn = get_db_connection()
    total_price = conn.execute(''' SELECT SUM(Cart.quantity * Cart.price) AS total_price FROM Cart WHERE Cart.customer_id = ? ''', (user_id,)).fetchone()[0]
    
    conn.close()
    return jsonify({"total_price": round(total_price or 0, 2)})


@app.route('/checkout/<int:user_id>', methods=['GET', 'POST'])
def render_checkout(user_id):
    if not is_customer():
        flash('Access denied. Users only.', 'error')
        return redirect(url_for('signin'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Initialize order_id as None at the start
        order_id = None

        # Fetch cart items for the user
        cart_items = conn.execute('''
            SELECT Cart.item_id, Cart.quantity, Cart.price, 
                   MenuItems.Name as "name", MenuItems.ImageURL as "image_url",
                   MenuItems.AvailabilityStatus as "availability"
            FROM Cart 
            JOIN MenuItems ON Cart.item_id = MenuItems.MenuItemID 
            WHERE Cart.customer_id = ?
        ''', (user_id,)).fetchall()

        if not cart_items:
            return render_template('checkout.html', message="Your cart is empty.", user_id=user_id, order_id=order_id)
        
        # Calculate subtotal and other charges
        sub_total = round(sum(item['quantity'] * item['price'] for item in cart_items), 2)
        gst = round(sub_total * 0.02, 2)  # 2% GST
        sales_tax = round(sub_total * 0.1, 2)  # 10% sales tax
        tax_amount = round(gst + sales_tax, 2)
        delivery_fee = 5.00
        total_price = round(sub_total + tax_amount + delivery_fee, 2)

        # Check for unavailable items
        unavailable_items = [item['name'] for item in cart_items if item['availability'] == 0]
        message = ""
        if unavailable_items:
            message = f"The following items are not available: {', '.join(unavailable_items)}"
        
        if request.method == 'POST':
            try:
                # Get form data
                delivery_location = request.form.get('delivery_location', '').strip()
                order_note = request.form.get('order_note')
                if order_note == "EMPTY":
                    order_note = None

                print(f"Received POST data: {request.form}")  # Debug print

                # Validate delivery location
                if not delivery_location:
                    raise ValueError("Please enter a valid delivery location.")

                # Create new order
                cursor.execute('''
                    INSERT INTO Orders (customer_id, total_price, order_status, delivery_location)
                    VALUES (?, ?, ?, ?)
                ''', (user_id, total_price, "Pending", delivery_location))
                
                conn.commit()
                order_id = cursor.lastrowid

                # Insert into Delivery table
                cursor.execute('''
                    INSERT INTO Delivery (Order_ID, Delivery_Agent_ID, Status, Pickup_time, Delivery_time)
                    VALUES (?, ?, ?, ?, ?)
                ''', (order_id, None, "Unassigned", None, None))

                # Insert order note
                cursor.execute('''
                    INSERT INTO Order_Note (Order_ID, User_ID, Description)
                    VALUES (?, ?, ?)
                ''', (order_id, user_id, order_note))

                # Insert items into Order_Items
                for item in cart_items:
                    cursor.execute('''
                        INSERT INTO Order_Items (order_id, item_id, quantity, price)
                        VALUES (?, ?, ?, ?)
                    ''', (order_id, item['item_id'], item['quantity'], item['price']))

                # Clear cart after successful order
                cursor.execute('DELETE FROM Cart WHERE customer_id = ?', (user_id,))
                
                conn.commit()
                print(1)
                return jsonify({"status": "success", "redirect_url": f'/place_order/{order_id}'}), 200

            except Exception as e:
                conn.rollback()
                return render_template('checkout.html',
                                    message=f"Error processing order: {str(e)}",
                                    cart_items=cart_items,
                                    sub_total=sub_total,
                                    gst=gst,
                                    sales_tax=sales_tax,
                                    tax_amount=tax_amount,
                                    delivery_fee=delivery_fee,
                                    total_price=total_price,
                                    user_id=user_id,
                                    order_id=order_id)

        # For GET requests, render the template
        return render_template('checkout.html',
                            message=message,
                            cart_items=cart_items,
                            sub_total=sub_total,
                            gst=gst,
                            sales_tax=sales_tax,
                            tax_amount=tax_amount,
                            delivery_fee=delivery_fee,
                            total_price=total_price,
                            user_id=user_id,
                            order_id=order_id)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    finally:
        if 'conn' in locals() and conn:
            conn.close()


@app.route('/coupons', methods=['POST'])
def add_coupon():
    if not request.is_json:
        return jsonify({'success': False, 'message': 'Invalid request format'}), 400
        
    try:
        data = request.get_json()
        
        if not data or 'coupon_code' not in data or 'total_price' not in data:
            return jsonify({'success': False, 'message': 'Missing required data'}), 400
        
        coupon_code = data['coupon_code']
        total_price = float(data['total_price'])
        
        # Find matching coupon
        matching_coupon = next(
            (coupon for coupon in PROMOTIONS['offers'] 
             if coupon['promo_code'] == coupon_code), 
            None
        )
        
        if not matching_coupon:
            return jsonify({'success': False, 'message': 'Invalid coupon code'}), 400
            
        # Check minimum order amount
        min_amount = matching_coupon.get('min_order_amount', 0)
        if total_price < min_amount:
            return jsonify({
                'success': False, 
                'message': f'Minimum order amount should be ${min_amount}'
            }), 400
            
        # Calculate discount
        if matching_coupon['discount_type'] == 'percentage':
            discount = (matching_coupon['discount_amount'] / 100) * total_price
        else:
            discount = matching_coupon['discount_amount']
            
        discounted_price = total_price - discount
        
        return jsonify({
            'success': True,
            'discounted_price': round(discounted_price, 2)
        }), 200
        
    except Exception as e:
        print(f"Error processing coupon: {str(e)}")  # For debugging
        return jsonify({
            'success': False,
            'message': 'Error processing coupon'
        }), 500


@app.route('/place_order/<int:order_id>', methods=['GET', 'POST'])
def place_order(order_id):
    if not is_customer():
        flash('Access denied. Users only.', 'error')
        return redirect(url_for('signin'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Find the order with 'Processing' status
        pending_order = cursor.execute(
            '''SELECT customer_id as user_id, total_price, delivery_location 
               FROM Orders 
               WHERE order_id = ? AND order_status = 'Pending' ''', 
            (order_id,)).fetchone()

        if not pending_order:
            return jsonify({"error": "No pending order found."}), 404

        user_id = pending_order['user_id']
        total_price = pending_order['total_price']
        delivery_location = pending_order['delivery_location']

        # Fetch user email and name
        user_info = cursor.execute(
            'SELECT email, full_name AS user_name FROM Users WHERE user_id = ?', 
            (user_id,)).fetchone()
        
        if not user_info:
            return jsonify({"error": "User not found"}), 404

        # Fetch the items in the completed order
        order_items = cursor.execute('''
            SELECT oi.quantity, m.Name AS item_name, m.Price AS item_price 
            FROM Order_Items oi 
            JOIN MenuItems m ON oi.item_id = m.MenuItemID 
            WHERE oi.order_id = ?''', 
            (order_id,)).fetchall()

        # Format items for email
        items = [{
            'item_name': item['item_name'],
            'quantity': item['quantity'],
            'price': item['item_price']
        } for item in order_items]

        # Send confirmation email
        send_order_confirmation_email(user_info['email'],user_info['user_name'],order_id,items,total_price)
        conn.commit()

        # Render confirmation page
        return render_template('order_confirmation.html', user_id=user_id,order_id=order_id)

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500

    finally:
        if 'conn' in locals() and conn:
            conn.close()


# ORDER SUMMARY PAGE: Render order summary details and allow cancellation
@app.route('/order-summary/<int:order_id>', methods=['GET'])
def render_order_summary(order_id):
    if not is_customer():
        flash('Access denied. Users only.', 'error')
        return redirect(url_for('signin'))
    
    conn = get_db_connection()
    
    try:
        # Fetch order details
        order = conn.execute('''SELECT * FROM Orders WHERE order_id = ?
        ''', (order_id,)).fetchone()
        
        if order is None:
            return jsonify({'error': 'No order found'}), 404
            
        user_id = order['customer_id']
        
        # Fetch order items with proper joins
        order_items = conn.execute('''SELECT oi.quantity,oi.price,m.Name as name,m.ImageURL as image_url,
            (oi.quantity * oi.price) as total 
            FROM Order_Items oi
            JOIN MenuItems m ON oi.item_id = m.MenuItemID
            WHERE oi.order_id = ?
        ''', (order_id,)).fetchall()
        
        # Calculate all totals
        subtotal = round(sum(item['quantity'] * item['price'] for item in order_items), 2)
        gst = round(subtotal * 0.02, 2)  # 2% GST
        sales_tax = round(subtotal * 0.1, 2)  # 10% sales tax
        tax_amount = round(gst + sales_tax, 2)
        delivery_fee = 5.00
        total_price = round(subtotal + tax_amount + delivery_fee , 2)
        result = conn.execute('''SELECT COALESCE(Description, 'No note found') FROM Order_Note WHERE Order_ID = ?''',
                                (order_id,)).fetchone()

        # Safely handle case where no row is found
        order_note = result[0] if result is not None else 'No note found'
        print(order_note)
        
        return render_template('order_summary.html',
            order=order,
            order_items=order_items,
            subtotal=subtotal,
            tax_amount=tax_amount,
            delivery_fee=delivery_fee,
            total_price=total_price,
            user_id=user_id,order_id=order_id,order_note=order_note
        )
        
    except Exception as e:
        app.logger.error(f"Error in order summary: {str(e)}")
        return jsonify({"error": "An error occurred while processing your request"}), 500
        
    finally:
        conn.close()

#get delivery agent details
def get_delivery_agent_details(order_id):
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row  # Ensure rows are returned as dictionaries
    cursor = conn.cursor()

    try:
        # Fetch the Delivery Agent ID for the given Order ID
        cursor.execute('''
            SELECT Delivery_Agent_ID 
            FROM Delivery 
            WHERE Order_ID = ?;
        ''', (order_id,))
        delivery_agent_row = cursor.fetchone()

        if not delivery_agent_row or delivery_agent_row["Delivery_Agent_ID"] is None:
            return {"error": True, "message": "No delivery agent assigned"}

        # Fetch Delivery Agent Details from the Users table
        cursor.execute('''
            SELECT full_name AS name, email, phone_number 
            FROM Users 
            WHERE user_id = ?;
        ''', (delivery_agent_row["Delivery_Agent_ID"],))
        agent_details = cursor.fetchone()

        if not agent_details:
            return {"error": True, "message": "Delivery agent details not found in Users table"}

        # Return the agent details as a dictionary
        return {
            "error": False,
            "Delivery_Agent_ID": delivery_agent_row["Delivery_Agent_ID"],
            "Name": agent_details["name"],
            "Email": agent_details["email"],
            "Phone Number": agent_details["phone_number"]
        }

    finally:
        conn.close()

@app.route('/get-delivery-agent/<int:order_id>', methods=['GET'])
def get_delivery_agent(order_id):
    agent_details = get_delivery_agent_details(order_id)
    return jsonify(agent_details)

# order section rendering page 
@app.route('/order-history/<int:user_id>')
def order_history(user_id):
    if not is_customer():
        flash('Access denied. Users only.', 'error')
        return redirect(url_for('signin'))
    
    conn = get_db_connection()
    
    # Updated query to include order_date and order_time
    query = """
    WITH OrderItems AS (
        SELECT 
            o.order_id,
            o.total_price,
            o.order_status,
            o.order_date,
            o.order_time,  -- Added order_time
            oi.item_id,
            oi.quantity,
            oi.price as item_price,
            m.Name as item_name,
            m.Description as item_description,
            m.ImageURL as item_image_url,
            ROW_NUMBER() OVER (PARTITION BY o.order_id ORDER BY oi.order_item_id) as item_rank
        FROM Orders o
        JOIN Order_Items oi ON o.order_id = oi.order_id
        JOIN MenuItems m ON oi.item_id = m.MenuItemID
        WHERE o.customer_id = ?
        ORDER BY o.order_id DESC
    )
    SELECT *
    FROM OrderItems
    WHERE item_rank <= 2
    """
    
    cursor = conn.execute(query, (user_id,))
    rows = cursor.fetchall()
    
    # Process the results into a nested structure
    orders = {}
    for row in rows:
        order_id = row['order_id']
        if order_id not in orders:
            # Format order_time to display only hour and minute
            order_time = row['order_time']
            # Parse the timestamp first (handles microseconds automatically)
            dt = datetime.strptime(order_time.split('.')[0], "%Y-%m-%d %H:%M:%S")
            formatted_time = dt.strftime("%H:%M")

            orders[order_id] = {
                'order_id': order_id,
                'order_date': row['order_date'],
                'order_time': formatted_time,  # Add formatted order_time
                'total_price': row['total_price'],
                'order_status': row['order_status'],
                'item_list': []
            }
        
        # Add item to order
        orders[order_id]['item_list'].append({
            'name': row['item_name'],
            'description': row['item_description'],
            'quantity': row['quantity'],
            'price': row['item_price'],
            'image_url': row['item_image_url']
        })
    
    # Convert orders dictionary to list
    orders_list = list(orders.values())
    
    conn.close()
    return render_template('order_section.html', orders=orders_list,user_id=user_id)

# CANCEL ORDER: Handle order cancellation
@app.route('/cancel_order/<int:order_id>', methods=['POST'])
def cancel_order(order_id):
    if not is_customer():
        flash('Access denied. Users only.', 'error')
        return redirect(url_for('signin'))
    
    try:
        conn = get_db_connection()
        #Get user_id from the Orders table
        user_id = conn.execute('''SELECT customer_id FROM Orders WHERE order_id=? ''',
            (order_id,)).fetchone()[0]
        # Update order status to 'Cancelled'
        conn.execute(''' UPDATE Orders SET order_status='Cancelled' WHERE order_id=? ''',
            (order_id,))
        # Update delivery status to 'Cancelled'
        conn.execute('''UPDATE Delivery SET Status ='Cancelled' WHERE order_id=? ''',
            (order_id,))

        conn.commit()

        user_info = conn.execute(
            'SELECT email, full_name AS user_name FROM Users WHERE user_id = ?', 
            (user_id,)).fetchone()

        send_order_cancellation_email(user_info['email'],user_info['user_name'],order_id)
        print(user_id)
        return render_template('order_cancelled.html',user_id=user_id)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

    finally:
        # Ensure the connection is always closed
        conn.close()

# Route to display feedback form
@app.route("/feedback-form/<int:order_id>", methods=['POST'])
def feedback_form(order_id):
    if not is_customer():
        flash('Access denied. Users only.', 'error')
        return redirect(url_for('signin'))
    
    return render_template("feedback_form.html", order_id=order_id)

# Route to handle form submission
@app.route("/submit-feedback/<int:order_id>", methods=["POST"])
def submit_feedback(order_id):
    rating = request.form.get("rating")
    comment = request.form.get("comment")

    if not (order_id and rating):
        return "<h1>Error: Missing required fields!</h1>"

    try:
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("SELECT customer_id FROM `Orders` WHERE order_id = ?", (order_id,))
        result = cursor.fetchone()

        if not result:
            return f"<h1>Error:Sorry Your Order ID {order_id} Not Found!</h1>"
        
        user_id = result["customer_id"]
        cursor.execute(
            "INSERT INTO feedback (order_id, customer_id, rating, comment) VALUES (?, ?, ?, ?)",
            (order_id, user_id, rating, comment)
        )
        db.commit()

        return redirect(f'/menu/{user_id}')
    except sqlite3.Error as e:
        return f"<h1>Error: Could not save feedback!</h1><p>{e}</p>"

def get_db_connection():
    """
    Establish a connection to the SQLite database and set the row factory for dict-like row access.
    """
    conn = sqlite3.connect("existing_database.db")
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/delivery_agent_dashboard/<int:agent_id>")
def delivery_agent_dashboard(agent_id):
    if not is_delivery_boy():
        flash('Access denied. Delivery agent only.', 'error')
        return redirect(url_for('signin'))
    
    """
    Render the dashboard page with orders and statistics.
    """
    conn = get_db_connection()
    orders = conn.execute("SELECT o.* FROM Orders o JOIN Delivery d ON d.Order_ID = o.order_id WHERE d.Delivery_Agent_ID = ?  ORDER BY order_id DESC", (agent_id,)).fetchall()
    stats = {
        "total_orders": conn.execute("SELECT COUNT(*) FROM Delivery WHERE Delivery_Agent_ID = ?",(agent_id,)).fetchone()[0],
        "completed_orders": conn.execute("SELECT COUNT(*) FROM Delivery WHERE Delivery_Agent_ID= ? AND Status IN ('Delivered on time', 'Delivered delayed')",(agent_id,)).fetchone()[0],
        "canceled_orders": conn.execute("SELECT COUNT(*) FROM Delivery WHERE Delivery_Agent_ID= ? AND Status='Canceled'",(agent_id,)).fetchone()[0],
        "delayed_orders": conn.execute("SELECT COUNT(*) FROM Delivery WHERE Delivery_Agent_ID= ? AND Status='Delivered delayed'",(agent_id,)).fetchone()[0],
    }
    conn.close()
    return render_template("dashboard.html", orders=orders, stats=stats,agent_id=agent_id)


@app.route("/orders/<int:agent_id>")
def orders(agent_id):
    if not is_delivery_boy():
        flash('Access denied. Delivery agent only.', 'error')
        return redirect(url_for('signin'))
    
    """
    Render the orders page.
    """
    conn = get_db_connection()
    orders = conn.execute("SELECT o.* FROM Orders o JOIN Delivery d ON d.Order_ID = o.order_id WHERE d.Delivery_Agent_ID = ? ORDER BY order_id DESC", (agent_id,)).fetchall()
    conn.close()
    return render_template("orders.html", orders=orders,agent_id=agent_id)


@app.route("/update_status/<int:order_id>", methods=["POST"])
def update_status(order_id):
    new_status = request.form["new_status"]
    conn = get_db_connection()
    agent_id = conn.execute("SELECT Delivery_Agent_ID FROM Delivery WHERE Order_ID = ?", (order_id,)).fetchone()[0]

    if new_status == "New":
        status_order = "Order Confirmed"
        status_delivery = "Assigned"
    elif new_status == "In Progress":
        status_order = "Out for Delivery"
        status_delivery = "Out for Delivery"
    elif new_status == "Completed":
        status_order = "Completed"
        status_delivery = "Delivered on time"
    elif new_status == "Delayed":
        status_order = "Completed"
        status_delivery = "Delviered Delayed"
    elif new_status == "Canceled":
        status_order = "Canceled"
        status_delivery = "Canceled"

    conn.execute("UPDATE Orders SET order_status = ? WHERE order_id = ?", (status_order, order_id))
    conn.execute("UPDATE Delivery SET status = ? WHERE order_id = ?", (status_delivery, order_id))
    conn.commit()
    conn.close()
    return redirect(url_for("delivery_agent_dashboard",agent_id=agent_id))



@app.route("/report_issue/<int:agent_id>", methods=["GET", "POST"])
def report_issue(agent_id):
    if not is_delivery_boy():
        flash('Access denied. Delivery agent only.', 'error')
        return redirect(url_for('signin'))
    
    """
    Handle the submission of a new issue report.
    """
    if request.method == "POST":
        order_id = request.form["order_id"]
        issue_type = request.form["issue_type"]
        description = request.form["description"]
        conn = get_db_connection()
        conn.execute("INSERT INTO issues (order_id, issue_type, description) VALUES (?, ?, ?)",
                     (order_id, issue_type, description))
        conn.commit()
        conn.close()

        flash("Issue reported successfully.", "success")
        return redirect(url_for("delivery_agent_dashboard",agent_id=agent_id))
    return render_template("report_issue.html",agent_id=agent_id)


@app.route("/resolve/<int:issue_id>", methods=["POST"])
def resolve_issue(issue_id):
    """
    Mark an issue as resolved by deleting it from the database.
    """
    conn = get_db_connection()
    conn.execute("DELETE FROM issues WHERE id = ?", (issue_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("issues_reported"))


@app.route("/route/<int:agent_id>")
def route_map(agent_id):
    if not is_delivery_boy():
        flash('Access denied. Delivery agent only.', 'error')
        return redirect(url_for('signin'))
    
    """
    Render the route map page.
    """
    return render_template("map.html",agent_id=agent_id)


@app.route("/performance/<int:agent_id>")
def performance(agent_id):
    if not is_delivery_boy():
        flash('Access denied. Delivery agent only.', 'error')
        return redirect(url_for('signin'))
    
    """
    Display order statistics and performance metrics.
    """
    conn = get_db_connection()
    stats = {
        "total_orders": conn.execute("SELECT COUNT(*) FROM Delivery WHERE Delivery_Agent_ID = ?",(agent_id,)).fetchone()[0],
        "completed_orders": conn.execute("SELECT COUNT(*) FROM Delivery WHERE Delivery_Agent_ID= ? AND Status IN ('Delivered on time', 'Delivered delayed')",(agent_id,)).fetchone()[0],
        "canceled_orders": conn.execute("SELECT COUNT(*) FROM Delivery WHERE Delivery_Agent_ID= ? AND Status='Canceled'",(agent_id,)).fetchone()[0],
        "delayed_orders": conn.execute("SELECT COUNT(*) FROM Delivery WHERE Delivery_Agent_ID= ? AND Status='Delivered delayed'",(agent_id,)).fetchone()[0],
    }
    performance_data = {
        "time_labels": ["Jan", "Feb", "Mar", "Apr"],
        "successful": [30, 40, 50, 60],
        "failed": [5, 10, 7, 8],
    }
    conn.close()
    return render_template("performance.html", stats=stats, performance_data=performance_data,agent_id=agent_id)


@app.route('/notifications', methods=['POST'])
def add_notification():
    if not is_delivery_boy():
        flash('Access denied. Delivery agent only.', 'error')
        return redirect(url_for('signin'))
    
    """
    Add a new notification for a delivery agent.
    """
    try:
        data = request.json
        agent_id = data.get('agent_id')
        message = data.get('message')
        notification_type = data.get('type', 'General')

        if not agent_id or not message:
            return jsonify({'error': 'agent_id and message are required'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO notifications (agent_id, message, type) VALUES (?, ?, ?)",
                       (agent_id, message, notification_type))
        conn.commit()
        conn.close()

        return jsonify({'message': 'Notification added successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/notifications/<int:agent_id>', methods=['GET'])
def fetch_notifications(agent_id):
    if not is_delivery_boy():
        flash('Access denied. Delivery agent only.', 'error')
        return redirect(url_for('signin'))
    
    """
    Fetch notifications for a specific delivery agent.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, agent_id, message, type, is_read, created_at FROM notifications WHERE agent_id = ?",
                       (agent_id,))
        notifications = cursor.fetchall()
        conn.close()

        notifications_list = [dict(row) for row in notifications]

        return render_template("notification.html", notifications=notifications_list)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route("/update_agent_status/<int:agent_id>", methods=["POST"])
def update_agent_status(agent_id):
    """
    Update the status of a delivery agent.
    """
    try:
        new_status = request.json.get("status")

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE delivery_agents SET status = ? WHERE id = ?", (new_status, agent_id))
        conn.commit()
        conn.close()

        return jsonify({"message": "Status updated successfully!", "new_status": new_status}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route("/switch_agent", methods=["POST"])
def switch_agent():
    """
    Switch a delivery agent for an order.
    """
    try:
        # Get data from the request
        order_id = request.json.get("order_id")
        new_agent_id = request.json.get("new_agent_id")

        # Get current assigned agent from the orders table
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT assigned_agent_id FROM orders WHERE order_id = ?", (order_id,))
        current_agent = cursor.fetchone()

        if not current_agent:
            return jsonify({"error": "Order not found"}), 404

        previous_agent_id = current_agent["assigned_agent_id"]

        # Insert a record into the order_assignments table to track the agent switch
        cursor.execute("""
            INSERT INTO order_assignments (order_id, previous_agent_id, new_agent_id)
            VALUES (?, ?, ?)
        """, (order_id, previous_agent_id, new_agent_id))

        # Update the orders table with the new assigned agent
        cursor.execute("UPDATE orders SET assigned_agent_id = ? WHERE order_id = ?", (new_agent_id, order_id))
        conn.commit()
        conn.close()

        return jsonify({"message": "Agent switched successfully!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def assign_delivery_agents():
    """
    Main function to assign delivery agents to unassigned orders.
    Runs periodically to check for unassigned deliveries and available agents.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get all unassigned deliveries
        unassigned_deliveries = cursor.execute('''
            SELECT d.Delivery_ID, d.Order_ID, o.delivery_location
            FROM Delivery d
            JOIN Orders o ON d.Order_ID = o.order_id
            WHERE d.Status = 'Unassigned'
            AND d.Delivery_Agent_ID IS NULL
            AND o.order_status = 'Order Confirmed'
            ORDER BY o.order_date, o.order_time
        ''').fetchall()

        if not unassigned_deliveries:
            print("No unassigned deliveries found.")
            return

        # Get available delivery agents
        available_agents = cursor.execute('''
            SELECT id, name
            FROM Delivery_agents
            WHERE status = 'available'
        ''').fetchall()

        if not available_agents:
            print("No available delivery agents found.")
            return

        # Assign orders to available agents
        agent_index = 0
        for delivery in unassigned_deliveries:
            if agent_index >= len(available_agents):
                break

            agent = available_agents[agent_index]
            current_time = datetime.now()

            try:
                # Update delivery record with assigned agent
                cursor.execute('''
                    UPDATE Delivery 
                    SET Delivery_Agent_ID = ?,
                        Status = 'Assigned'
                    WHERE Delivery_ID = ?
                ''', (agent['id'], delivery['Delivery_ID']))

                # Update agent status
                cursor.execute('''
                    UPDATE Delivery_agents 
                    SET status = 'on delivery' 
                    WHERE id = ?
                ''', (agent['id'],))

                print(f"Delivery {delivery['Delivery_ID']} for Order {delivery['Order_ID']} assigned to agent {agent['name']}")
                agent_index += 1

            except Exception as e:
                print(f"Error assigning delivery {delivery['Delivery_ID']}: {str(e)}")
                continue

        conn.commit()

    except Exception as e:
        print(f"Error in assign_delivery_agents: {str(e)}")

    finally:
        if 'conn' in locals():
            conn.close()

def init_delivery_scheduler():
    """
    Initialize the background scheduler for delivery assignments
    """
    scheduler = BackgroundScheduler()
    
    # Schedule delivery assignment task (runs every 30 seconds)
    scheduler.add_job(
        func=assign_delivery_agents,
        trigger=IntervalTrigger(seconds=300),
        id='delivery_assignment_task',
        name='Assign delivery agents to orders',
        replace_existing=True
    )
    
    scheduler.start()
    print("Delivery assignment scheduler initialized")

# Add this to your Flask app initialization
def initialize_delivery_system(app):
    with app.app_context():
        init_delivery_scheduler()

if __name__ == '__main__':
    initialize_delivery_system(app)
    app.run(debug=True)
