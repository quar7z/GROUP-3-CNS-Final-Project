# ===== IMPORTS =====
from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
import os
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import timedelta

# ===== LOAD ENVIRONMENT VARIABLES =====
load_dotenv()

# ===== INITIALIZE FLASK APP =====
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1) # <-- ADD THIS LINE
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')  # Railway (use later)
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///temp.db'  # Local (temporary)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ===== INITIALIZE EXTENSIONS =====
db = SQLAlchemy(app)      # Database
bcrypt = Bcrypt(app)      # Password hashing

# Rate limiter — limits login attempts per IP
limiter = Limiter(
    app=app,
    key_func=get_remote_address,  # Limit by IP address
    default_limits=["200 per day", "50 per hour"]
)
# Custom rate limit error message ← add here
@app.errorhandler(429)
def rate_limit_exceeded(e):
    flash('Too many requests. Please try again later.', 'error')
    return render_template('login.html'), 429

# Session timeout — auto logout after 15 minutes
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)

# ===== LOGIN MANAGER =====
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ===== NO CACHE HEADERS =====
# Prevents browser back button after logout
# Copied URLs won't work after session expires
@app.after_request
def add_no_cache(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# ===== USER MODEL (DATABASE TABLE) =====
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')
    failed_attempts = db.Column(db.Integer, default=0)        # Count failed attempts
    locked_until = db.Column(db.DateTime, nullable=True)      # Locked until this time


# ===== LOGIN LOG MODEL (DATABASE TABLE) =====
class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)           # Unique ID
    username = db.Column(db.String(80), nullable=False)    # Who tried to login
    status = db.Column(db.String(10), nullable=False)      # 'success' or 'failed'
    ip_address = db.Column(db.String(50), nullable=False)  # Where they logged in from
    timestamp = db.Column(db.DateTime, default=db.func.now()) # When it happened

# ===== IP BLOCK MODEL (DATABASE TABLE) =====
class IPBlock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), nullable=False)  # IP being tracked
    failed_attempts = db.Column(db.Integer, default=0)     # Failed attempts from this IP
    locked_until = db.Column(db.DateTime, nullable=True)   # IP locked until this time
    
# ===== CREATE DATABASE TABLES ===== ← moved here after User model
with app.app_context():
    db.create_all()

# ===== USER LOADER =====
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# ===== ROUTES =====

# Home — redirects to login
@app.route('/')
def home():
    return redirect(url_for('login'))

# Login — shows login form and handles login logic
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get form data from login form
        username = request.form['username'].lower().strip()  # Normalize — prevents case bypass
        password = request.form['password']
        ip_address = request.remote_addr  # Get IP address of requester

        # Find user in database by username
        user = db.session.execute(db.select(User).filter_by(username=username)).scalar()

        # Find IP block record
        ip_block = db.session.execute(
            db.select(IPBlock).filter_by(ip_address=ip_address)).scalar()

        # ===== STEP 1: CHECK IF IP IS BLOCKED =====
        # Blocks by IP — attacker cant bypass by trying different usernames
        if ip_block and ip_block.locked_until:
            from datetime import datetime
            now = datetime.utcnow().replace(tzinfo=None)
            lock_time = ip_block.locked_until.replace(tzinfo=None)
            if now < lock_time:
                log = LoginLog(username=username, status='failed', ip_address=ip_address)
                db.session.add(log)
                db.session.commit()
                flash('Account locked. Try again later.', 'error')
                return render_template('login.html')  # Stop here!
        # ===== STEP 2: CHECK IF USERNAME IS LOCKED =====
        # Blocks by username — prevents VPN bypass
        if user and user.locked_until:
            from datetime import datetime
            now = datetime.utcnow().replace(tzinfo=None)
            lock_time = user.locked_until.replace(tzinfo=None)
            if now < lock_time:
                log = LoginLog(username=username, status='failed', ip_address=ip_address)
                db.session.add(log)
                db.session.commit()
                flash('Account locked. Try again later.', 'error')
                return render_template('login.html')  # Stop here!

        # ===== STEP 3: CHECK PASSWORD =====
        # Only reaches here if both IP and username are NOT locked
        if user:
            # ===== SUCCESS =====
            # Reset both IP and username counters
            if ip_block:
                ip_block.failed_attempts = 0
                ip_block.locked_until = None
            user.failed_attempts = 0
            user.locked_until = None
            db.session.commit()

            login_user(user)            # Create session
            session.permanent = True    # Enable session timeout

            # Save success log
            log = LoginLog(username=username, status='success', ip_address=ip_address)
            db.session.add(log)
            db.session.commit()
            return redirect(url_for('dashboard'))

        else:
            # ===== WRONG PASSWORD =====
            # Save failed log
            log = LoginLog(username=username, status='failed', ip_address=ip_address)
            db.session.add(log)
            db.session.commit()

            from datetime import datetime, timedelta as td
            now = datetime.utcnow().replace(tzinfo=None)

            # ===== LOCK USERNAME =====
            if user:
                user.failed_attempts += 1
                if user.failed_attempts >= 9:
                    user.locked_until = now + td(days=365)  # 1 year
                elif user.failed_attempts >= 6:
                    user.locked_until = now + td(minutes=30)  # 30 mins
                elif user.failed_attempts >= 3:
                    user.locked_until = now + td(minutes=5)  # 5 mins

            # ===== LOCK IP =====
            if not ip_block:
                # First time this IP — create record
                ip_block = IPBlock(ip_address=ip_address, failed_attempts=0)
                db.session.add(ip_block)

            ip_block.failed_attempts += 1
            if ip_block.failed_attempts >= 9:
                ip_block.locked_until = now + td(days=365)  # 1 year
            elif ip_block.failed_attempts >= 6:
                ip_block.locked_until = now + td(minutes=30)  # 30 mins
            elif ip_block.failed_attempts >= 3:
                ip_block.locked_until = now + td(minutes=5)  # 5 mins

            db.session.commit()

            # Always same vague message — never reveal details
            flash('Invalid credentials!', 'error')

    return render_template('login.html')  # Show login page

# Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    # Regular users can only see camera feed
    if current_user.role == 'user':
        return redirect(url_for('camera'))

    # Admin sees full dashboard
    total_users = db.session.execute(db.select(User)).scalars().all()
    success_logs = db.session.execute(db.select(LoginLog).filter_by(status='success')).scalars().all()
    failed_logs = db.session.execute(db.select(LoginLog).filter_by(status='failed')).scalars().all()

    return render_template('dashboard.html',
        total_users=len(total_users),
        success_count=len(success_logs),
        failed_count=len(failed_logs)
    )

# Users — admin only
@app.route('/users')
@login_required
def users():
    # Only admin can access user management
    if current_user.role != 'admin':
        flash('Access denied! Admins only.', 'error')
        return redirect(url_for('dashboard'))
    all_users = db.session.execute(db.select(User)).scalars().all()
    return render_template('users.html', users=all_users)

# Add User — admin only
@app.route('/add-user', methods=['POST'])
@login_required
def add_user():
    # Only admin can add users
    if current_user.role != 'admin':
        flash('Access denied! Admins only.', 'error')
        return redirect(url_for('dashboard'))
    username = request.form['username'].lower().strip()
    password = request.form['password']
    role = request.form['role']
    existing = db.session.execute(db.select(User).filter_by(username=username)).scalar()
    if existing:
        flash(f'Username {username} already exists!', 'error')
        return redirect(url_for('users'))
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    user = User(username=username, password=hashed_password, role=role)
    db.session.add(user)
    db.session.commit()
    flash(f'User {username} added successfully!', 'success')
    return redirect(url_for('users'))

# Delete User — admin only
@app.route('/delete-user/<int:user_id>')
@login_required
def delete_user(user_id):
    # Only admin can delete users
    if current_user.role != 'admin':
        flash('Access denied! Admins only.', 'error')
        return redirect(url_for('dashboard'))
    user = db.session.get(User, user_id)
    if user:
        if user.username == current_user.username:
            flash('You cannot delete yourself!', 'error')
            return redirect(url_for('users'))
        db.session.delete(user)
        db.session.commit()
        flash(f'User {user.username} deleted!', 'success')
    return redirect(url_for('users'))

# Login Logs — admin only
@app.route('/logs')
@login_required
def logs():
    # Only admin can see login logs
    if current_user.role != 'admin':
        flash('Access denied! Admins only.', 'error')
        return redirect(url_for('dashboard'))
    all_logs = db.session.execute(
        db.select(LoginLog).order_by(LoginLog.timestamp.desc())
    ).scalars().all()
    return render_template('logs.html', logs=all_logs)

# Camera Feed — shows live camera feed
@app.route('/camera')
@login_required
def camera():
    return render_template('camera.html')

# Logout — clears session and redirects to login
@app.route('/logout')
@login_required
def logout():
    logout_user()  # Clear session
    return redirect(url_for('login'))  # Go back to login

# Temporary — Create test user (remove this later!)
@app.route('/create-test-user')
def create_test_user():
    existing = db.session.execute(db.select(User).filter_by(username='admin')).scalar()
    if existing:
        return 'Test user already exists!'
    hashed_password = bcrypt.generate_password_hash('admin123').decode('utf-8')
    user = User(username='admin', password=hashed_password, role='admin')
    db.session.add(user)
    db.session.commit()
    return 'Test user created! Username: admin, Password: admin123'

# ===== RUN APP =====
if __name__ == '__main__':
    # use_reloader=False needed later when adding camera  #debug=True, use_reloader=False
    app.run(debug=True)