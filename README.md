
# MMH Vulnerable App

**Made Me Hackable (MMH)** is an educational Flask application intentionally built with **7 common web vulnerabilities**. It is designed to demonstrate, test, and fix security issues as part of a Secure Software Design and Development project.

---

## Secure Software Design and Development Project Report

**Project Title**: MMH — Demonstration and Mitigation of Vulnerabilities in Web Apps  
**Repository**: [https://github.com/syedayanzeeshan/MMH](https://github.com/syedayanzeeshan/MMH)

---

## Project Overview

This project demonstrates seven common web application vulnerabilities using a deliberately insecure Flask-based app called **MMH (Made Me Hackable)**.

- The `main` branch includes the **vulnerable version**
- The `fix-all` branch contains the **secure and patched version**

Each vulnerability is first demonstrated in the `main` branch and then mitigated in the `fix-all` branch using secure design principles.

---

## Application Stack

| Component  | Technology       |
|------------|------------------|
| Language   | Python (Flask)   |
| Database   | SQLite           |
| Frontend   | HTML, Jinja2     |
| Hosting    | Localhost (127.0.0.1:5000) |
| Branches   | `main` (vulnerable), `fix-all` (secure) |

---

## List of Vulnerabilities Demonstrated

| # | Vulnerability                  | Description |
|--|-------------------------------|-------------|
| 1 | **SQL Injection (SQLi)**       | Direct string interpolation in SQL queries allowed login bypass. |
| 2 | **Cross-Site Scripting (XSS)** | Malicious `<script>` tags in comments executed on page load. |
| 3 | **Cross-Site Request Forgery** | No CSRF token validation on forms allowed forged POST requests. |
| 4 | **Insecure Direct Object Reference (IDOR)** | Users could access other user profiles by modifying the URL. |
| 5 | **Sensitive Data Exposure**    | Profile page potentially exposed private user data. |
| 6 | **Debug Mode Enabled**         | Flask debug mode revealed traceback and system paths on crash. |
| 7 | **Hardcoded Secret Key**       | `app.secret_key` was hardcoded, allowing session tampering. |

---

## Detailed Vulnerability Breakdown

### 1. SQL Injection (SQLi)

- **Vulnerable Code**:
  ```python
  f"SELECT * FROM users WHERE username = '{u}' AND password = '{p}'"
  ```

- **Exploit**: Input `' OR 1=1 --` bypassed login

- **Fix**:
  ```python
  query = "SELECT * FROM users WHERE username = ? AND password = ?"
  user = db.execute(query, (u, p)).fetchone()
  ```

### 2. Cross-Site Scripting (XSS)

- **Exploit**: Posting `<script>alert(1)</script>` in comments executed JS on the page.

- **Fix**: Ensure no `|safe` filter is used. Autoescaping is enabled.
  ```html
  <p>{{ comment['comment'] }}</p> <!-- Safe rendering -->
  ```

### 3. Cross-Site Request Forgery (CSRF)

- **Exploit**: External sites could POST to the app and delete data.

- **Fix**: Added CSRF protection.
  ```python
  @app.before_request
  def csrf_protect():
      if request.method == "POST":
          token = session.get('_csrf_token')
          form_token = request.form.get('_csrf_token')
          if not token or token != form_token:
              abort(403)
  ```

  ```html
  <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
  ```

### 4. Insecure Direct Object Reference (IDOR)

- **Exploit**: Visiting `/profile/2` could expose another user's profile.

- **Fix**:
  ```python
  if not user or user['id'] != session.get('user_id'):
      return 'Unauthorized or not found', 403
  ```

### 5. Sensitive Data Exposure

- **Exploit**: Profiles could leak private or password fields.

- **Fix**: Removed sensitive fields from database queries and templates.

### 6. Debug Mode Enabled

- **Exploit**: Visiting `/crash` with debug mode enabled showed full traceback.

  ```python
  @app.route('/crash')
  def crash():
      return 1 / 0
  ```

- **Fix**: Removed `app.debug = True` from production code. Now it returns a clean 500 error page.

### 7. Hardcoded Secret Key

- **Exploit**: Hardcoded `'dev'` secret key risks cookie/session forgery.

- **Fix**:
  ```python
  app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(16))
  ```

---

## Demonstration Flow

### Vulnerable Version (`main`)

```bash
git clone https://github.com/syedayanzeeshan/MMH.git MMHV
cd MMHV
git checkout main
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
sqlite3 mmh.db < schema.sql
python app.py
```

### Secure Version (`fix-all`)

```bash
git clone https://github.com/syedayanzeeshan/MMH.git MMHF
cd MMHF
git checkout fix-all
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
sqlite3 mmh.db < schema.sql
python app.py
```

---

## Final Remarks

This project provides a hands-on demonstration of real-world web vulnerabilities and their secure fixes. All flaws were addressed using best practices, including:

- Parameterized queries
- CSRF protection
- Access control enforcement
- Secure session management
- Proper error handling

---

## Appendix

### Links

- **GitHub Repo**: [MMH on GitHub](https://github.com/syedayanzeeshan/MMH)

### Branches

| Branch    | Description                       |
|-----------|------------------------------------|
| `main`    | Insecure version with 7 flaws      |
| `fix-all` | Fully secured and patched version  |
