from flask import Flask, render_template, redirect, url_for, flash, request, session, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
import os
import cv2
import secrets
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import timedelta

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.errorhandler(429)
def rate_limit_exceeded(e):
    flash('Too many requests. Please try again later.', 'error')
    return render_template('login.html'), 429

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'error'

@app.after_request
def add_no_cache(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.before_request
def check_session_token():
    if current_user.is_authenticated:
        if request.endpoint in ('logout', 'static', 'video_feed'):
            return
        if session.get('session_token') != current_user.session_token:
            logout_user()
            session.clear()
            flash('Logged in from another device. Session ended.', 'warning')
            return redirect(url_for('login'))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')
    failed_attempts = db.Column(db.Integer, default=0)     
    locked_until = db.Column(db.DateTime, nullable=True)    
    session_token = db.Column(db.String(64), nullable=True)  

class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)   
    status = db.Column(db.String(10), nullable=False)      
    ip_address = db.Column(db.String(50), nullable=False)  
    timestamp = db.Column(db.DateTime, default=db.func.now())

class IPBlock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), nullable=False)  
    failed_attempts = db.Column(db.Integer, default=0)   
    locked_until = db.Column(db.DateTime, nullable=True)  

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

camera_instance = None

def get_camera():
    global camera_instance
    camera_url = os.getenv('CAMERA_URL', '0')
    if isinstance(camera_url, str) and camera_url.isdigit():
        camera_url = int(camera_url)
    if camera_instance is None or not camera_instance.isOpened():
        camera_instance = cv2.VideoCapture(camera_url)
    return camera_instance

def generate_frames():
    cap = get_camera()
    if not cap.isOpened():
        return
    try:
        while True:
            success, frame = cap.read()
            if not success:
                break
            ret, buffer = cv2.imencode('.jpg', frame)
            if not ret:
                continue
            frame = buffer.tobytes()
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
    except:
        pass

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].lower().strip()
        password = request.form['password']
        ip_address = request.remote_addr

        user = db.session.execute(db.select(User).filter_by(username=username)).scalar()
        ip_block = db.session.execute(db.select(IPBlock).filter_by(ip_address=ip_address)).scalar()

        if ip_block and ip_block.locked_until:
            from datetime import datetime
            now = datetime.utcnow().replace(tzinfo=None)
            lock_time = ip_block.locked_until.replace(tzinfo=None)
            if now < lock_time:
                log = LoginLog(username=username, status='failed', ip_address=ip_address)
                db.session.add(log)
                db.session.commit()
                flash('Account locked. Try again later.', 'error')
                return render_template('login.html')

        if user and user.locked_until:
            from datetime import datetime
            now = datetime.utcnow().replace(tzinfo=None)
            lock_time = user.locked_until.replace(tzinfo=None)
            if now < lock_time:
                log = LoginLog(username=username, status='failed', ip_address=ip_address)
                db.session.add(log)
                db.session.commit()
                flash('Account locked. Try again later.', 'error')
                return render_template('login.html')

        if user and bcrypt.check_password_hash(user.password, password):
            if ip_block:
                ip_block.failed_attempts = 0
                ip_block.locked_until = None
            user.failed_attempts = 0
            user.locked_until = None
            db.session.commit()

            token = secrets.token_hex(32)
            user.session_token = token
            db.session.commit()

            login_user(user)
            session['session_token'] = token
            session.permanent = True

            log = LoginLog(username=username, status='success', ip_address=ip_address)
            db.session.add(log)
            db.session.commit()
            return redirect(url_for('dashboard'))

        else:
            log = LoginLog(username=username, status='failed', ip_address=ip_address)
            db.session.add(log)
            db.session.commit()

            from datetime import datetime, timedelta as td
            now = datetime.utcnow().replace(tzinfo=None)

            if user:
                user.failed_attempts += 1
                if user.failed_attempts >= 9:
                    user.locked_until = now + td(days=365) 
                elif user.failed_attempts >= 6:
                    user.locked_until = now + td(minutes=30) 
                elif user.failed_attempts >= 3:
                    user.locked_until = now + td(minutes=5)  

            if not ip_block:
                ip_block = IPBlock(ip_address=ip_address, failed_attempts=0)
                db.session.add(ip_block)

            ip_block.failed_attempts += 1
            if ip_block.failed_attempts >= 9:
                ip_block.locked_until = now + td(days=365)
            elif ip_block.failed_attempts >= 6:
                ip_block.locked_until = now + td(minutes=30)
            elif ip_block.failed_attempts >= 3:
                ip_block.locked_until = now + td(minutes=5)

            db.session.commit()
            flash('Invalid credentials!', 'error')

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        cap = get_camera()
        camera_status = 'Online' if cap.isOpened() else 'Offline'
    except:
        camera_status = 'Offline'

    return render_template('dashboard.html',
        camera_status=camera_status
    )

@app.route('/video-feed')
@login_required
def video_feed():
    return Response(
        generate_frames(),
        mimetype='multipart/x-mixed-replace; boundary=frame'
    )

@app.route('/users')
@login_required
def users():
    if current_user.role != 'admin':
        flash('Access denied! Admins only.', 'error')
        return redirect(url_for('dashboard'))
    all_users = db.session.execute(db.select(User)).scalars().all()
    return render_template('users.html', users=all_users)

@app.route('/add-user', methods=['POST'])
@login_required
def add_user():
    if current_user.role != 'admin':
        flash('Access denied! Admins only.', 'error')
        return redirect(url_for('dashboard'))

    username = request.form['username'].lower().strip()
    password = request.form['password']
    role = request.form['role']

    if len(password) < 8:
        flash('Password must be at least 8 characters.', 'error')
        return redirect(url_for('users'))

    if len(password) > 72:
        flash('Password must not exceed 72 characters.', 'error')
        return redirect(url_for('users'))

    if not any(c.isupper() for c in password):
        flash('Password must contain at least 1 uppercase letter.', 'error')
        return redirect(url_for('users'))

    if not any(c.islower() for c in password):
        flash('Password must contain at least 1 lowercase letter.', 'error')
        return redirect(url_for('users'))

    if not any(c.isdigit() for c in password):
        flash('Password must contain at least 1 number.', 'error')
        return redirect(url_for('users'))

    if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
        flash('Password must contain at least 1 special character.', 'error')
        return redirect(url_for('users'))

    if len(username) < 3:
        flash('Username must be at least 3 characters.', 'error')
        return redirect(url_for('users'))

    existing = db.session.execute(db.select(User).filter_by(username=username)).scalar()
    if existing:
        flash(f'Username "{username}" already exists!', 'error')
        return redirect(url_for('users'))

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    user = User(username=username, password=hashed_password, role=role)
    db.session.add(user)
    db.session.commit()
    flash(f'User "{username}" added successfully!', 'success')
    return redirect(url_for('users'))

@app.route('/delete-user/<int:user_id>')
@login_required
def delete_user(user_id):
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
        flash(f'User "{user.username}" deleted!', 'success')
    return redirect(url_for('users'))

@app.route('/logs')
@login_required
def logs():
    if current_user.role != 'admin':
        flash('Access denied! Admins only.', 'error')
        return redirect(url_for('dashboard'))
    all_logs = db.session.execute(
        db.select(LoginLog).order_by(LoginLog.timestamp.desc())
    ).scalars().all()
    return render_template('logs.html', logs=all_logs)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', use_reloader=False)