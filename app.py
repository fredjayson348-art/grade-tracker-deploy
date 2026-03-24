# Grade Tracker v2 - Flask + SQLite + Auth
# By Fred (fredjayson348-art)

from flask import Flask, jsonify, request, render_template, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'fred_secret_key_2025'
init_db()
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE_DIR, 'grades.db')
init_db()

init_db()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS grades (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            subject TEXT NOT NULL,
            score REAL NOT NULL,
            date TEXT DEFAULT CURRENT_DATE,
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id, subject)
        )
    ''')
    conn.commit()
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

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Login required'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('index.html', username=session['username'])

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
        conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Account created! Please login.'})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already taken'}), 400

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    if user and check_password_hash(user['password'], password):
        session['user_id'] = user['id']
        session['username'] = user['username']
        return jsonify({'message': 'Login successful!'})
    return jsonify({'error': 'Invalid username or password'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out!'})

@app.route('/grades', methods=['GET'])
@login_required
def get_grades():
    conn = get_db()
    rows = conn.execute('SELECT * FROM grades WHERE user_id = ? ORDER BY score DESC', (session['user_id'],)).fetchall()
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
@login_required
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
        conn.execute('INSERT INTO grades (user_id, subject, score) VALUES (?, ?, ?)', (session['user_id'], subject, score))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Added!', 'subject': subject, 'score': score})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Subject already exists!'}), 400

@app.route('/grades/<subject>', methods=['DELETE'])
@login_required
def delete_grade(subject):
    conn = get_db()
    conn.execute('DELETE FROM grades WHERE subject = ? AND user_id = ?', (subject, session['user_id']))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Deleted!', 'subject': subject})

@app.route('/grades/<subject>', methods=['PUT'])
@login_required
def update_grade(subject):
    data = request.get_json()
    score = data.get('score')
    if score is None or score < 0 or score > 100:
        return jsonify({'error': 'Valid score required'}), 400
    conn = get_db()
    conn.execute('UPDATE grades SET score = ? WHERE subject = ? AND user_id = ?', (score, subject, session['user_id']))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Updated!', 'subject': subject, 'score': score})

@app.route('/report', methods=['GET'])
@login_required
def report():
    conn = get_db()
    rows = conn.execute('SELECT score FROM grades WHERE user_id = ?', (session['user_id'],)).fetchall()
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

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
