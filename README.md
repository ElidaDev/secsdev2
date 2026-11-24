
# OWASP Top 10 Security Assignment

This README contains vulnerable code examples and their corrected versions. Each example demonstrates a security vulnerability and how to address it.

## 1. Broken Access Control

### Example 1: Accessing Another User's Account

**Vulnerable Code:**

```python
@app.route("/account/<int:user_id>")
def account(user_id):
    user = User.query.get(user_id)
    return render_template("account.html", user=user)
```

**Corrected Code:**

```python
@app.route("/account/<int:user_id>")
@login_required
def account(user_id):
    if current_user.id != user_id:
        abort(403)

    user = User.query.get_or_404(user_id)
    return render_template("account.html", user=user)
```

The corrected code checks whether the logged-in user owns the account before allowing access.

### Example 2: Missing Authorization Check

**Vulnerable Code:**

```python
@app.route("/admin/delete/<int:user_id>")
def delete_user(user_id):
    User.query.filter_by(id=user_id).delete()
    db.session.commit()
    return "User deleted"
```

**Corrected Code:**

```python
@app.route("/admin/delete/<int:user_id>")
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        abort(403)

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()

    return "User deleted"
```

The corrected code verifies that the logged-in user has administrator permissions before deleting an account.

## 2. Cryptographic Failures

### Example 3: Storing Passwords as Plain Text

**Vulnerable Code:**

```python
password = request.form["password"]

db.execute(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    (username, password)
)
```

**Corrected Code:**

```python
from werkzeug.security import generate_password_hash

password = request.form["password"]
passwordHash = generate_password_hash(password)

db.execute(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    (username, passwordHash)
)
```

The corrected code hashes passwords before storing them.

### Example 4: Using Weak Encryption

**Vulnerable Code:**

```python
import hashlib

password = "userPassword123"
hashedPassword = hashlib.md5(password.encode()).hexdigest()
```

**Corrected Code:**

```python
from werkzeug.security import generate_password_hash

password = "userPassword123"
hashedPassword = generate_password_hash(password)
```

The corrected code uses a password-hashing function designed to make password cracking more difficult.

## 3. Injection

### Example 5: SQL Injection

**Vulnerable Code:**

```python
username = request.args.get("username")

query = "SELECT * FROM users WHERE username = '" + username + "'"
cursor.execute(query)
```

**Corrected Code:**

```python
username = request.args.get("username")

query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (username,))
```

The corrected code uses parameterized queries to prevent user input from changing the SQL statement.

### Example 6: NoSQL Injection

**Vulnerable Code:**

```python
username = request.json["username"]

user = db.users.find_one({"username": username})
```

**Corrected Code:**

```python
username = request.json["username"]

if not isinstance(username, str):
    abort(400)

user = db.users.find_one({"username": username})
```

The corrected code verifies that the username is a string before using it in the database query.

## 4. Insecure Design

### Example 7: Insecure Password Reset

**Vulnerable Code:**

```python
@app.route("/reset-password", methods=["POST"])
def reset_password():
    email = request.form["email"]
    newPassword = request.form["password"]

    user = User.query.filter_by(email=email).first()
    user.password = newPassword

    db.session.commit()
    return "Password changed"
```

**Corrected Code:**

```python
from werkzeug.security import generate_password_hash

@app.route("/reset-password", methods=["POST"])
def reset_password():
    token = request.form["token"]
    newPassword = request.form["password"]

    resetRequest = PasswordReset.query.filter_by(
        token=token,
        used=False
    ).first()

    if not resetRequest or resetRequest.expires_at < datetime.utcnow():
        abort(400)

    user = User.query.get_or_404(resetRequest.user_id)
    user.password = generate_password_hash(newPassword)

    resetRequest.used = True
    db.session.commit()

    return "Password changed"
```

The corrected code requires a valid, unused, unexpired password reset token before allowing a password change.

## 5. Software and Data Integrity Failures

### Example 8: Loading External JavaScript Without Integrity Verification

**Vulnerable Code:**

```html
<script src="https://cdn.example.com/lib.js"></script>
```

**Corrected Code:**

```html
<script
    src="https://cdn.example.com/lib.js"
    integrity="sha384-REPLACE_WITH_ACTUAL_HASH"
    crossorigin="anonymous">
</script>
```

The corrected code uses Subresource Integrity (SRI) to verify that the downloaded JavaScript file has not been modified.

## 6. Server-Side Request Forgery (SSRF)

### Example 9: Allowing User-Controlled URLs

**Vulnerable Code:**

```python
import requests

url = request.args.get("url")
response = requests.get(url)

return response.text
```

**Corrected Code:**

```python
import requests

allowedUrls = [
    "https://example.com",
    "https://api.example.com"
]

url = request.args.get("url")

if url not in allowedUrls:
    abort(403)

response = requests.get(
    url,
    timeout=5,
    allow_redirects=False
)

return response.text
```

The corrected code only allows requests to approved URLs and prevents automatic redirects.

## 7. Identification and Authentication Failures

### Example 10: Incorrect Password Verification

**Vulnerable Code:**

```python
username = request.form["username"]
password = request.form["password"]

user = User.query.filter_by(username=username).first()

if user and user.password == password:
    return "Login successful"
```

**Corrected Code:**

```python
from werkzeug.security import check_password_hash

username = request.form["username"]
password = request.form["password"]

user = User.query.filter_by(username=username).first()

if user and check_password_hash(user.password, password):
    return "Login successful"

abort(401)
```

The corrected code securely verifies the submitted password against its stored password hash.

## References

- [OWASP Top 10: 2021](https://owasp.org/Top10/)
- [OWASP A01: Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP A02: Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [OWASP A03: Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [OWASP A04: Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
- [OWASP A07: Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- [OWASP A08: Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
- [OWASP A10: Server-Side Request Forgery](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
