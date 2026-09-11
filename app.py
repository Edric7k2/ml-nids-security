from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime
import joblib
import numpy as np
import os
import gdown

def download_models():
    os.makedirs('models', exist_ok=True)

    if not os.path.exists('models/rf_model.pkl'):
        print("Downloading rf_model.pkl...")
        gdown.download(
            id='1gRrCh4z3bdng7nyfjGxCGUUjLiKC0nuC',
            output='models/rf_model.pkl',
            quiet=False
        )

    if not os.path.exists('models/gb_model.pkl'):
        print("Downloading gb_model.pkl...")
        gdown.download(
            id='1kixardA5ISlJTGT5QDULbGr0OLqofJJZ',
            output='models/gb_model.pkl',
            quiet=False
        )

    if not os.path.exists('models/scaler.pkl'):
        print("Downloading scaler.pkl...")
        gdown.download(
            id='1PqVvZBBYQp4eb1w8cjHSunA1KMw2v4Wl',
            output='models/scaler.pkl',
            quiet=False
        )

download_models()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'nids-secret-key-2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///nids.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Load ML Models
rf_model  = joblib.load('models/rf_model.pkl')
gb_model  = joblib.load('models/gb_model.pkl')
scaler    = joblib.load('models/scaler.pkl')

# ── Database Models ──
class User(db.Model, UserMixin):
    id         = db.Column(db.Integer, primary_key=True)
    name       = db.Column(db.String(100), nullable=False)
    email      = db.Column(db.String(120), unique=True, nullable=False)
    password   = db.Column(db.String(200), nullable=False)
    role       = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active  = db.Column(db.Boolean, default=True)
    scans      = db.relationship('ScanHistory', backref='user', lazy=True)

class ScanHistory(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    duration   = db.Column(db.Float)
    src_pkts   = db.Column(db.Float)
    dst_pkts   = db.Column(db.Float)
    src_bytes  = db.Column(db.Float)
    dst_bytes  = db.Column(db.Float)
    rate       = db.Column(db.Float)
    rf_result  = db.Column(db.String(20))
    gb_result  = db.Column(db.String(20))
    verdict    = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ── Routes ──
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name     = request.form.get('name')
        email    = request.form.get('email')
        password = request.form.get('password')

        if User.query.filter_by(email=email).first():
            flash('Email already exists!', 'danger')
            return redirect(url_for('register'))

        hashed = bcrypt.generate_password_hash(password).decode('utf-8')
        user   = User(name=name, email=email, password=hashed)
        db.session.add(user)
        db.session.commit()
        flash('Account created! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email    = request.form.get('email')
        password = request.form.get('password')
        user     = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            if not user.is_active:
                flash('Your account has been disabled.', 'danger')
                return redirect(url_for('login'))
            login_user(user)
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))

        flash('Invalid email or password.', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    scans = ScanHistory.query.filter_by(
        user_id=current_user.id
    ).order_by(ScanHistory.created_at.desc()).limit(10).all()
    return render_template('dashboard.html', scans=scans)

@app.route('/analyze', methods=['POST'])
@login_required
def analyze():
    data = request.get_json()

    inp = np.zeros((1, 43))
    inp[0][0] = float(data.get('duration', 0))
    inp[0][5] = float(data.get('src_pkts', 0))
    inp[0][6] = float(data.get('dst_pkts', 0))
    inp[0][7] = float(data.get('src_bytes', 0))
    inp[0][8] = float(data.get('dst_bytes', 0))
    inp[0][9] = float(data.get('rate', 0))

    inp_scaled = scaler.transform(inp)
    rf_res     = int(rf_model.predict(inp_scaled)[0])
    gb_res     = int(gb_model.predict(inp_scaled)[0])
    rf_prob    = rf_model.predict_proba(inp_scaled)[0]
    gb_prob    = gb_model.predict_proba(inp_scaled)[0]

    src_pkts  = float(data.get('src_pkts', 0))
    src_bytes = float(data.get('src_bytes', 0))
    dst_bytes = float(data.get('dst_bytes', 0))
    rate      = float(data.get('rate', 0))

    if src_pkts > 500 or rate > 1000:
        attack_type, mitre = "DoS Attack", "T1499"
    elif dst_bytes == 0 and src_pkts > 50:
        attack_type, mitre = "Reconnaissance", "T1595"
    elif src_bytes > 10000 and dst_bytes < 100:
        attack_type, mitre = "Exploit Attempt", "T1059"
    else:
        attack_type, mitre = "Generic Attack", "T1078"

    both = rf_res == 1 and gb_res == 1
    one  = rf_res == 1 or gb_res == 1
    if both:  verdict = "CRITICAL THREAT"
    elif one: verdict = "SUSPICIOUS"
    else:     verdict = "NORMAL"

    # Save to DB
    scan = ScanHistory(
        user_id   = current_user.id,
        duration  = float(data.get('duration', 0)),
        src_pkts  = src_pkts,
        dst_pkts  = float(data.get('dst_pkts', 0)),
        src_bytes = src_bytes,
        dst_bytes = dst_bytes,
        rate      = rate,
        rf_result = 'ATTACK' if rf_res == 1 else 'NORMAL',
        gb_result = 'ATTACK' if gb_res == 1 else 'NORMAL',
        verdict   = verdict
    )
    db.session.add(scan)
    db.session.commit()

    return jsonify({
        'rf_result':    'ATTACK' if rf_res == 1 else 'NORMAL',
        'gb_result':    'ATTACK' if gb_res == 1 else 'NORMAL',
        'rf_confidence': f"{(rf_prob[1] if rf_res==1 else rf_prob[0])*100:.1f}",
        'gb_confidence': f"{(gb_prob[1] if gb_res==1 else gb_prob[0])*100:.1f}",
        'attack_type':  attack_type if one else 'None',
        'mitre':        mitre if one else 'N/A',
        'verdict':      verdict
    })

@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    users      = User.query.all()
    scans      = ScanHistory.query.order_by(
                    ScanHistory.created_at.desc()).limit(20).all()
    total_scans  = ScanHistory.query.count()
    attack_scans = ScanHistory.query.filter(
                    ScanHistory.verdict != 'NORMAL').count()

    return render_template('admin.html',
        users=users, scans=scans,
        total_scans=total_scans, attack_scans=attack_scans)

@app.route('/admin/toggle/<int:user_id>')
@login_required
def toggle_user(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    flash(f"User {'enabled' if user.is_active else 'disabled'}.", 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete/<int:user_id>')
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted.', 'success')
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create admin if not exists
        admin = User.query.filter_by(email='admin@nids.com').first()
        if not admin:
            hashed = bcrypt.generate_password_hash('admin123').decode('utf-8')
            admin  = User(
                name='Admin',
                email='admin@nids.com',
                password=hashed,
                role='admin'
            )
            db.session.add(admin)
            db.session.commit()
            print("Admin created: admin@nids.com / admin123")
    app.run(debug=True)