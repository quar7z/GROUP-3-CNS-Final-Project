# ===== IMPORTS =====
from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
import os

# ===== LOAD ENVIRONMENT VARIABLES =====
load_dotenv()

# ===== INITIALIZE FLASK APP =====
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
# app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')  # Railway (use later)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///temp.db'  # Local (temporary)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ===== INITIALIZE EXTENSIONS =====
db = SQLAlchemy(app)      # Database
bcrypt = Bcrypt(app)      # Password hashing

# ===== LOGIN MANAGER =====
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ===== USER MODEL (DATABASE TABLE) =====
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')

# ===== LOGIN LOG MODEL (DATABASE TABLE) =====
class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)           # Unique ID
    username = db.Column(db.String(80), nullable=False)    # Who tried to login
    status = db.Column(db.String(10), nullable=False)      # 'success' or 'failed'
    ip_address = db.Column(db.String(50), nullable=False)  # Where they logged in from
    timestamp = db.Column(db.DateTime, default=db.func.now()) # When it happened
    
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
        username = request.form['username']
        password = request.form['password']
        ip_address = request.remote_addr  # Get IP address

        user = db.session.execute(db.select(User).filter_by(username=username)).scalar()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            # Save success log
            log = LoginLog(username=username, status='success', ip_address=ip_address)
            db.session.add(log)
            db.session.commit()
            return redirect(url_for('dashboard'))
        else:
            # Save failed log
            log = LoginLog(username=username, status='failed', ip_address=ip_address)
            db.session.add(log)
            db.session.commit()
            flash('Invalid credentials!', 'error')

    return render_template('login.html')

# Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    # Count total users
    total_users = db.session.execute(db.select(User)).scalars().all()
    
    # Count successful logins
    success_logs = db.session.execute(db.select(LoginLog).filter_by(status='success')).scalars().all()
    
    # Count failed attempts
    failed_logs = db.session.execute(db.select(LoginLog).filter_by(status='failed')).scalars().all()

    return render_template('dashboard.html',
        total_users=len(total_users),
        success_count=len(success_logs),
        failed_count=len(failed_logs)
    )
# Users — shows all users
@app.route('/users')
@login_required
def users():
    # Get all users from database
    all_users = db.session.execute(db.select(User)).scalars().all()
    return render_template('users.html', users=all_users)

# Delete User — removes a user from database
@app.route('/delete-user/<int:user_id>')
@login_required
def delete_user(user_id):
    # Find user by ID
    user = db.session.get(User, user_id)
    if user:
        # Cannot delete yourself
        if user.username == current_user.username:
            flash('You cannot delete yourself!', 'error')
            return redirect(url_for('users'))
        # Delete user
        db.session.delete(user)
        db.session.commit()
        flash(f'User {user.username} deleted!', 'success')
    return redirect(url_for('users'))

# Login Logs — shows all login attempts
@app.route('/logs')
@login_required
def logs():
    # Get all logs ordered by newest first
    all_logs = db.session.execute(
        db.select(LoginLog).order_by(LoginLog.timestamp.desc())
    ).scalars().all()
    return render_template('logs.html', logs=all_logs)

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