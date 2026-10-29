import base64, io, os, re
from datetime import timedelta
from functools import wraps
from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import RequestEntityTooLarge
import bcrypt, pyotp, qrcode
from dotenv import load_dotenv

load_dotenv()
db = SQLAlchemy()
csrf = CSRFProtect()
USERNAME_RE = re.compile(r'^[A-Za-z0-9_.-]{3,30}$')
EMAIL_RE = re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False, index=True)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    totp_secret = db.Column(db.String(64), nullable=True)
    totp_enabled = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.now())
    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    def check_password(self, password):
        try: return bcrypt.checkpw(password.encode(), self.password_hash.encode())
        except (ValueError, TypeError, AttributeError): return False

def create_app(test_config=None):
    app = Flask(__name__)
    secret = os.getenv('SECRET_KEY')
    if not secret and not (test_config and test_config.get('TESTING')):
        raise RuntimeError('SECRET_KEY missing. Start with run_windows.bat or create a .env file from .env.example.')
    app.config.update(SECRET_KEY=secret or 'test-only-secret-key',
        SQLALCHEMY_DATABASE_URI=os.getenv('DATABASE_URL', 'sqlite:///secure_login.db'),
        SQLALCHEMY_TRACK_MODIFICATIONS=False, SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=os.getenv('COOKIE_SECURE','false').lower() == 'true',
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30), MAX_CONTENT_LENGTH=1024*1024,
        WTF_CSRF_TIME_LIMIT=3600)
    if test_config: app.config.update(test_config)
    db.init_app(app); csrf.init_app(app)
    limiter = Limiter(get_remote_address, app=app, default_limits=['200 per day','50 per hour'], storage_uri='memory://')
    @app.before_request
    def load_user():
        uid = session.get('user_id')
        g.user = db.session.get(User, uid) if uid else None
    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault('X-Content-Type-Options','nosniff')
        resp.headers.setdefault('X-Frame-Options','DENY')
        resp.headers.setdefault('Referrer-Policy','no-referrer')
        resp.headers.setdefault('Permissions-Policy','camera=(), microphone=(), geolocation=()')
        resp.headers.setdefault('Content-Security-Policy', "default-src 'self'; img-src 'self' data:; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'")
        return resp
    def login_required(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if g.user is None:
                flash('Please log in to view that page.','info'); return redirect(url_for('login'))
            return fn(*args, **kwargs)
        return wrapper
    @app.route('/')
    def index(): return render_template('index.html')
    @app.route('/register', methods=['GET','POST'])
    @limiter.limit('5 per hour')
    def register():
        if g.user: return redirect(url_for('dashboard'))
        username=email=''
        if request.method == 'POST':
            username=request.form.get('username','').strip(); email=request.form.get('email','').strip().lower()
            password=request.form.get('password',''); confirm=request.form.get('confirm_password','')
            error=None
            if not USERNAME_RE.fullmatch(username): error='Username must be 3–30 characters and contain only letters, numbers, dots, underscores, or hyphens.'
            elif len(email)>254 or not EMAIL_RE.fullmatch(email): error='Enter a valid email address.'
            elif len(password)<12: error='Password must be at least 12 characters long.'
            elif len(password)>128: error='Password must be 128 characters or fewer.'
            elif not re.search(r'[A-Za-z]',password) or not re.search(r'\d',password): error='Password must contain at least one letter and one number.'
            elif password != confirm: error='Password confirmation does not match.'
            if error:
                flash(error,'error'); return render_template('register.html',username=username,email=email),400
            user=User(username=username,email=email); user.set_password(password); db.session.add(user)
            try: db.session.commit()
            except IntegrityError:
                db.session.rollback(); flash('That username or email is already registered.','error')
                return render_template('register.html',username=username,email=email),409
            flash('Account created successfully. You can now log in.','success'); return redirect(url_for('login'))
        return render_template('register.html',username=username,email=email)
    @app.route('/login', methods=['GET','POST'])
    @limiter.limit('5 per minute')
    def login():
        if g.user: return redirect(url_for('dashboard'))
        identifier=''
        if request.method == 'POST':
            identifier=request.form.get('identifier','').strip(); password=request.form.get('password','')
            if not identifier or not password or len(identifier)>254:
                flash('Invalid username/email or password.','error'); return render_template('login.html',identifier=identifier),401
            user=User.query.filter(or_(User.username==identifier,User.email==identifier.lower())).first()
            if user is None or not user.check_password(password):
                flash('Invalid username/email or password.','error'); return render_template('login.html',identifier=identifier),401
            session.clear(); session.permanent=True
            if user.totp_enabled:
                session['pre_2fa_user_id']=user.id; return redirect(url_for('verify_2fa'))
            session['user_id']=user.id; flash('Welcome back!','success'); return redirect(url_for('dashboard'))
        return render_template('login.html',identifier=identifier)
    @app.route('/two-factor/verify', methods=['GET','POST'])
    @limiter.limit('8 per minute')
    def verify_2fa():
        uid=session.get('pre_2fa_user_id')
        if not uid: flash('Please log in first.','info'); return redirect(url_for('login'))
        user=db.session.get(User,uid)
        if not user or not user.totp_enabled or not user.totp_secret:
            session.clear(); flash('Two-factor verification could not be started. Log in again.','error'); return redirect(url_for('login'))
        if request.method=='POST':
            code=re.sub(r'\s+','',request.form.get('code',''))
            if code.isdigit() and pyotp.TOTP(user.totp_secret).verify(code,valid_window=1):
                session.clear(); session.permanent=True; session['user_id']=user.id
                flash('Two-factor verification successful.','success'); return redirect(url_for('dashboard'))
            flash('Invalid authentication code. Try again.','error')
        return render_template('verify_2fa.html')
    @app.route('/two-factor/setup', methods=['GET','POST'])
    @login_required
    def setup_2fa():
        user=g.user
        if user.totp_enabled: flash('Two-factor authentication is already enabled.','info'); return redirect(url_for('dashboard'))
        if not user.totp_secret: user.totp_secret=pyotp.random_base32(); db.session.commit()
        uri=pyotp.TOTP(user.totp_secret).provisioning_uri(name=user.email,issuer_name='Secure Login Demo')
        image=qrcode.make(uri); buff=io.BytesIO(); image.save(buff,format='PNG')
        qr_data='data:image/png;base64,'+base64.b64encode(buff.getvalue()).decode('ascii')
        if request.method=='POST':
            code=re.sub(r'\s+','',request.form.get('code',''))
            if code.isdigit() and pyotp.TOTP(user.totp_secret).verify(code,valid_window=1):
                user.totp_enabled=True; db.session.commit(); flash('Two-factor authentication is now enabled.','success'); return redirect(url_for('dashboard'))
            flash('Code not accepted. Scan the QR code and enter the current code.','error')
        return render_template('setup_2fa.html',qr_data=qr_data,secret=user.totp_secret)
    @app.route('/two-factor/disable', methods=['POST'])
    @login_required
    @limiter.limit('5 per minute')
    def disable_2fa():
        user=g.user; password=request.form.get('password',''); code=re.sub(r'\s+','',request.form.get('code',''))
        valid=user.totp_secret and code.isdigit() and pyotp.TOTP(user.totp_secret).verify(code,valid_window=1)
        if not user.check_password(password) or not valid:
            flash('Could not disable 2FA. Check your password and authenticator code.','error'); return redirect(url_for('dashboard'))
        user.totp_enabled=False; user.totp_secret=None; db.session.commit(); flash('Two-factor authentication disabled.','success'); return redirect(url_for('dashboard'))
    @app.route('/dashboard')
    @login_required
    def dashboard(): return render_template('dashboard.html')
    @app.route('/logout',methods=['POST'])
    def logout(): session.clear(); flash('You have been logged out.','success'); return redirect(url_for('index'))
    @app.errorhandler(RequestEntityTooLarge)
    def too_large(_): flash('Request is too large.','error'); return redirect(url_for('index'))
    with app.app_context(): db.create_all()
    return app

app=create_app()
if __name__=='__main__':
    # Local development only. Do not use Flask's development server for public production hosting.
    app.run(host='127.0.0.1',port=5000,debug=False)
