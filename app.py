from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3

app = Flask(__name__)
app.secret_key = 'dev_secret'
app.debug = True

def get_db():
    conn = sqlite3.connect('mmh.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    db = get_db()
    comments = db.execute("SELECT * FROM comments").fetchall()
    return render_template('index.html', comments=comments)

@app.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        u = request.form['username']
        p = request.form['password']
        db = get_db()
        db.execute(f"INSERT INTO users (username, password) VALUES ('{u}','{p}')")
        db.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        u = request.form['username']
        p = request.form['password']
        db = get_db()
        user = db.execute(f"SELECT * FROM users WHERE username = '{u}' AND password = '{p}'").fetchone()
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('index'))
        return 'Login failed'
    return render_template('login.html')

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
    user = db.execute(f"SELECT * FROM users WHERE id = {user_id}").fetchone()
    if not user:
        return 'Not found'
    return render_template('profile.html', user=user)

@app.route('/delete-comment', methods=('POST',))
def delete_comment():
    cid = request.form['comment_id']
    db = get_db()
    db.execute(f"DELETE FROM comments WHERE id = {cid}")
    db.commit()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run()
