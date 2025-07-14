from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import os

app = Flask(__name__)
# FIXED: Secret key should not be hardcoded in production
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev_secret')
# FIXED: Debug mode should not be enabled in production
# app.debug = True

import secrets
from flask import abort

@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.get('_csrf_token', None)
        form_token = request.form.get('_csrf_token')
        if not token or token != form_token:
            abort(403)

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(16)
    return session['_csrf_token']

# Register CSRF token generator in Jinja2
app.jinja_env.globals['csrf_token'] = generate_csrf_token

def get_db():
    conn = sqlite3.connect('mmh.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    db = get_db()
    comments = db.execute("SELECT * FROM comments").fetchall()
    username = session.get('username')
    return render_template('index.html', comments=comments, username=username)

@app.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        u = request.form['username']
        p = request.form['password']
        db = get_db()
        # FIXED: Use parameterized query to prevent SQL injection
        db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (u, p))
        db.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        u = request.form['username']
        p = request.form['password']

        db = get_db()
        # FIXED: Use parameterized query to prevent SQL injection
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        print("DEBUG:", query)
        user = db.execute(query, (u, p)).fetchone()

        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('index'))
        return 'Login failed'

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/comment', methods=('POST',))
def comment():
    text = request.form['comment']
    user = session.get('username', 'Anonymous')
    db = get_db()
    db.execute("INSERT INTO comments (username, comment) VALUES (?, ?)", (user, text))
    db.commit()
    return redirect(url_for('index'))

@app.route('/profile/<int:user_id>')
def profile(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    # FIXED: Prevent IDOR - Only allow access to own profile
    if not user or user['id'] != session.get('user_id'):
        return 'Unauthorized or not found', 403
    return render_template('profile.html', user=user)

@app.route('/delete-comment', methods=('POST',))
def delete_comment():
    cid = request.form['comment_id']
    db = get_db()
    session_user = session.get('username')

    if session_user != 'admin':
        return "Only admin can delete comments", 403

    db.execute("DELETE FROM comments WHERE id = ?", (cid,))
    db.commit()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run()
