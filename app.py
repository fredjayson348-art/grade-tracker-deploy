# Grade Tracker v3 - Flask + PostgreSQL + Auth + Google Login + 7 Day Trial
# By Fred (fredjayson348-art)

from flask import Flask, jsonify, request, render_template, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_dance.contrib.google import make_google_blueprint, google
import psycopg2
import psycopg2.extras
import os
from datetime import datetime, timedelta

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '0'

app = Flask(__name__)
app.secret_key = 'fred_secret_key_2025'

# Google OAuth setup
google_bp = make_google_blueprint(
    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    scope=['openid', 'https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email'],
    redirect_to="google_callback",
)
app.register_blueprint(google_bp, url_prefix='/auth')

DATABASE_URL = os.environ.get('DATABASE_URL')

def get_db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password TEXT,
            google_id TEXT,
            email TEXT,
            trial_start TIMESTAMP DEFAULT NOW(),
            is_premium INTEGER DEFAULT 0
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS grades (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            subject TEXT NOT NULL,
            score REAL NOT NULL,
            date TEXT DEFAULT CURRENT_DATE,
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id, subject)
        )
    ''')
    try:
        cur.execute('ALTER TABLE users ADD COLUMN google_id TEXT')
    except:
        conn.rollback()
    try:
        cur.execute('ALTER TABLE users ADD COLUMN email TEXT')
    except:
        conn.rollback()
    conn.commit()
    cur.close()
    conn.close()

def get_letter(score):
    if score >= 80: return 'A'
    elif score >= 70: return 'B'
    elif score >= 60: return 'C'
    elif score >= 50: return 'D'
    else: return 'F'

def get_gpa(score):
    if score >= 80: return 4.0
    elif score >= 70: return 3.0
    elif score >= 60: return 2.0
    elif score >= 50: return 1.0
    else: return 0.0

def is_trial_active(user):
    if user['is_premium']:
        return True
    if not user['trial_start']:
        return True
    trial_start = user['trial_start']
    if isinstance(trial_start, str):
        trial_start = datetime.fromisoformat(trial_start[:19])
    return datetime.now() < trial_start + timedelta(days=7)

def get_days_left(user):
    if user['is_premium']:
        return 999
    if not user['trial_start']:
        return 7
    trial_start = user['trial_start']
    if isinstance(trial_start, str):
        trial_start = datetime.fromisoformat(trial_start[:19])
    delta = (trial_start + timedelta(days=7)) - datetime.now()
    return max(0, delta.days)

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Login required'}), 401
        return f(*args, **kwargs)
    return decorated

def trial_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Login required'}), 401
        conn = get_db()
        cur = conn.cursor()
        cur.execute('SELECT * FROM users WHERE id = %s', (session['user_id'],))
        user = cur.fetchone()
        cur.close()
        conn.close()
        if not is_trial_active(user):
            return jsonify({'error': 'trial_expired'}), 403
        return f(*args, **kwargs)
    return decorated

ADMIN_PASSWORD = 'fredadmin2025'

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('is_admin'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT * FROM users WHERE id = %s', (session['user_id'],))
    user = cur.fetchone()
    cur.close()
    conn.close()
    if not is_trial_active(user):
        return redirect(url_for('upgrade_page'))
    days_left = get_days_left(user)
    return render_template('index.html', username=session['username'], days_left=days_left, is_premium=user['is_premium'])

@app.route('/auth/google/callback')
def google_callback():
    if not google.authorized:
        return redirect(url_for('google.login'))
    resp = google.get('/oauth2/v2/userinfo')
    if not resp.ok:
        return redirect(url_for('login_page'))
    info = resp.json()
    google_id = info['id']
    email = info.get('email', '')
    name = info.get('name', email.split('@')[0])
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT * FROM users WHERE google_id = %s', (google_id,))
    user = cur.fetchone()
    if not user:
        cur.execute('SELECT * FROM users WHERE email = %s', (email,))
        user = cur.fetchone()
    if not user:
        try:
            cur.execute('INSERT INTO users (username, google_id, email) VALUES (%s, %s, %s)',
                (name, google_id, email))
            conn.commit()
            cur.execute('SELECT * FROM users WHERE google_id = %s', (google_id,))
            user = cur.fetchone()
        except psycopg2.IntegrityError:
            conn.rollback()
            cur.execute('SELECT * FROM users WHERE email = %s', (email,))
            user = cur.fetchone()
    else:
        cur.execute('UPDATE users SET google_id = %s WHERE id = %s', (google_id, user['id']))
        conn.commit()
    session['user_id'] = user['id']
    session['username'] = user['username']
    cur.close()
    conn.close()
    if not is_trial_active(user):
        return redirect(url_for('upgrade_page'))
    return redirect(url_for('home'))

@app.route('/upgrade')
def upgrade_page():
    return render_template('upgrade.html', username=session.get('username', ''))

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    if len(password) < 4:
        return jsonify({'error': 'Password must be at least 4 characters'}), 400
    hashed = generate_password_hash(password)
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('INSERT INTO users (username, password) VALUES (%s, %s)', (username, hashed))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'message': 'Account created! Please login.'})
    except psycopg2.IntegrityError:
        return jsonify({'error': 'Username already taken'}), 400

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT * FROM users WHERE username = %s', (username,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    if user and user['password'] and check_password_hash(user['password'], password):
        session['user_id'] = user['id']
        session['username'] = user['username']
        if not is_trial_active(user):
            return jsonify({'trial_expired': True})
        return jsonify({'message': 'Login successful!'})
    return jsonify({'error': 'Invalid username or password'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out!'})

@app.route('/api/change-password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return jsonify({'error': 'Login required'}), 401
    data = request.get_json()
    old_password = data.get('old_password', '')
    new_password = data.get('new_password', '')
    if not old_password or not new_password:
        return jsonify({'error': 'All fields required'}), 400
    if len(new_password) < 4:
        return jsonify({'error': 'Password too short'}), 400
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT * FROM users WHERE id = %s', (session['user_id'],))
    user = cur.fetchone()
    if not user or not user['password'] or not check_password_hash(user['password'], old_password):
        cur.close()
        conn.close()
        return jsonify({'error': 'Current password is incorrect'}), 401
    cur.execute('UPDATE users SET password = %s WHERE id = %s',
        (generate_password_hash(new_password), session['user_id']))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'message': 'Password updated successfully!'})

@app.route('/grades', methods=['GET'])
@trial_required
def get_grades():
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT * FROM grades WHERE user_id = %s ORDER BY score DESC', (session['user_id'],))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    result = {}
    for row in rows:
        result[row['subject']] = {
            'score': row['score'],
            'letter': get_letter(row['score']),
            'gpa': get_gpa(row['score']),
            'date': row['date']
        }
    return jsonify(result)

@app.route('/grades', methods=['POST'])
@trial_required
def add_grade():
    data = request.get_json()
    subject = data.get('subject')
    score = data.get('score')
    if not subject or score is None:
        return jsonify({'error': 'Subject and score required'}), 400
    if score < 0 or score > 100:
        return jsonify({'error': 'Score must be between 0 and 100'}), 400
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('INSERT INTO grades (user_id, subject, score) VALUES (%s, %s, %s)',
            (session['user_id'], subject, score))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'message': 'Added!', 'subject': subject, 'score': score})
    except psycopg2.IntegrityError:
        return jsonify({'error': 'Subject already exists!'}), 400

@app.route('/grades/<subject>', methods=['DELETE'])
@trial_required
def delete_grade(subject):
    conn = get_db()
    cur = conn.cursor()
    cur.execute('DELETE FROM grades WHERE subject = %s AND user_id = %s', (subject, session['user_id']))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'message': 'Deleted!', 'subject': subject})

@app.route('/grades/<subject>', methods=['PUT'])
@trial_required
def update_grade(subject):
    data = request.get_json()
    score = data.get('score')
    if score is None or score < 0 or score > 100:
        return jsonify({'error': 'Valid score required'}), 400
    conn = get_db()
    cur = conn.cursor()
    cur.execute('UPDATE grades SET score = %s WHERE subject = %s AND user_id = %s',
        (score, subject, session['user_id']))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'message': 'Updated!', 'subject': subject, 'score': score})

@app.route('/report', methods=['GET'])
@trial_required
def report():
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT score FROM grades WHERE user_id = %s', (session['user_id'],))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    if not rows:
        return jsonify({'error': 'No grades yet'})
    scores = [row['score'] for row in rows]
    average = sum(scores) / len(scores)
    total_gpa = sum(get_gpa(s) for s in scores)
    return jsonify({
        'total_subjects': len(scores),
        'average': round(average, 2),
        'gpa': round(total_gpa / len(scores), 2),
        'overall_grade': get_letter(average)
    })

@app.route('/admin')
@admin_required
def admin_dashboard():
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT id, username, email, trial_start, is_premium FROM users ORDER BY id DESC')
    users = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('admin.html', users=users)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        password = request.form.get('password')
        if password == ADMIN_PASSWORD:
            session['is_admin'] = True
            return redirect(url_for('admin_dashboard'))
        return render_template('admin_login.html', error='Wrong password')
    return render_template('admin_login.html', error=None)

@app.route('/admin/logout')
def admin_logout():
    session.pop('is_admin', None)
    return redirect(url_for('admin_login'))

@app.route('/admin/upgrade/<int:user_id>')
@admin_required
def admin_upgrade(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute('UPDATE users SET is_premium = 1 WHERE id = %s', (user_id,))
    conn.commit()
    cur.close()
    conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/downgrade/<int:user_id>')
@admin_required
def admin_downgrade(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute('UPDATE users SET is_premium = 0 WHERE id = %s', (user_id,))
    conn.commit()
    cur.close()
    conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete/<int:user_id>')
@admin_required
def admin_delete(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute('DELETE FROM grades WHERE user_id = %s', (user_id,))
    cur.execute('DELETE FROM users WHERE id = %s', (user_id,))
    conn.commit()
    cur.close()
    conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/ping')
def ping():
    return 'OK', 200

init_db()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

@app.route('/report/pdf')
def download_pdf():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT * FROM users WHERE id = %s', (session['user_id'],))
    user = cur.fetchone()
    cur.execute('SELECT * FROM grades WHERE user_id = %s ORDER BY score DESC', (session['user_id'],))
    grades = cur.fetchall()
    cur.close()
    conn.close()
    if not grades:
        return jsonify({'error': 'No grades to export'}), 400
    from fpdf import FPDF
    scores = [g['score'] for g in grades]
    average = sum(scores) / len(scores)
    avg_gpa = sum(get_gpa(s) for s in scores) / len(scores)
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_fill_color(0, 212, 255)
    pdf.rect(0, 0, 210, 35, 'F')
    pdf.set_text_color(8, 12, 20)
    pdf.set_font('Helvetica', 'B', 22)
    pdf.set_xy(0, 8)
    pdf.cell(210, 10, 'grade.track', align='C')
    pdf.set_font('Helvetica', '', 11)
    pdf.set_xy(0, 20)
    pdf.cell(210, 10, f'Grade Report - {user["username"]}', align='C')
    pdf.set_text_color(100, 116, 139)
    pdf.set_font('Helvetica', '', 9)
    pdf.set_xy(0, 28)
    pdf.cell(210, 8, f'Generated: {datetime.now().strftime("%B %d, %Y")}', align='C')
    pdf.set_text_color(0, 0, 0)
    box_data = [('AVERAGE', f'{round(average, 1)}%'), ('GPA', str(round(avg_gpa, 2))), ('SUBJECTS', str(len(grades))), ('OVERALL', get_letter(average))]
    colors = [(0,212,255), (124,58,237), (16,185,129), (245,158,11)]
    for i, (label, value) in enumerate(box_data):
        x = 15 + i * 47
        r, g, b = colors[i]
        pdf.set_fill_color(r, g, b)
        pdf.rect(x, 45, 42, 25, 'F')
        pdf.set_text_color(255, 255, 255)
        pdf.set_font('Helvetica', 'B', 14)
        pdf.set_xy(x, 50)
        pdf.cell(42, 8, value, align='C')
        pdf.set_font('Helvetica', '', 8)
        pdf.set_xy(x, 60)
        pdf.cell(42, 6, label, align='C')
    pdf.set_y(80)
    pdf.set_fill_color(17, 24, 39)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font('Helvetica', 'B', 10)
    headers = ['Subject', 'Score', 'Grade', 'GPA', 'Date']
    widths = [75, 25, 20, 20, 40]
    for header, w in zip(headers, widths):
        pdf.cell(w, 10, header, border=1, fill=True, align='C')
    pdf.ln()
    pdf.set_font('Helvetica', '', 9)
    for i, g in enumerate(grades):
        if i % 2 == 0:
            pdf.set_fill_color(248, 249, 250)
        else:
            pdf.set_fill_color(255, 255, 255)
        pdf.set_text_color(0, 0, 0)
        row = [g['subject'], f"{g['score']}/100", get_letter(g['score']), str(get_gpa(g['score'])), str(g['date'])]
        for val, w in zip(row, widths):
            pdf.cell(w, 9, str(val), border=1, fill=True, align='C')
        pdf.ln()
    pdf.set_y(-20)
    pdf.set_text_color(150, 150, 150)
    pdf.set_font('Helvetica', '', 8)
    pdf.cell(0, 10, 'grade-tracker-hf4o.onrender.com', align='C')
    from flask import make_response
    response = make_response(bytes(pdf.output()))
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=grade_report_{user["username"]}.pdf'
    return response
