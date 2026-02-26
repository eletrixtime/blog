====

Auto Security Analysis of blog-eletrix-fr at 2025-01-24

CRITICAL - Stored Cross-Site Scripting (XSS)
The application allows users to create blog posts containing arbitrary HTML and JavaScript. When these posts are viewed, the content is rendered using the Jinja2 `|safe` filter, which disables auto-escaping. This allows an attacker to execute malicious scripts in the context of any user viewing the post, potentially leading to session hijacking or unauthorized actions.

PoC
```python
import requests

# Assuming the attacker has access to create a post (or via CSRF)
session = requests.Session()
# Login if necessary, or exploit missing CSRF
session.post("http://127.0.0.1:5000/login", data={"username": "admin", "password": "admin"})
session.post("http://127.0.0.1:5000/create_post", data={
    "title": "Malicious Post",
    "author": "Attacker",
    "tags": "test",
    "content": "<script>alert('XSS')</script>"
})

# When any user visits /post/Malicious%20Post, the script will execute.
r = requests.get("http://127.0.0.1:5000/post/Malicious%20Post")
if "<script>alert('XSS')</script>" in r.text:
    print("XSS Vulnerability Confirmed")
```

Fix
Remove the `|safe` filter from `html/post.html` and use a dedicated library like `bleach` to sanitize the HTML output of `markdown2` before passing it to the template.

---

MEDIUM - Missing CSRF Protection
The application lacks Cross-Site Request Forgery (CSRF) protection on state-changing routes such as `/login`, `/create_post`, and `/upload`. An attacker can trick a logged-in administrator into performing actions like creating a malicious post or uploading files by enticing them to visit a specially crafted website.

PoC
```python
# A simple HTML form hosted on an attacker's site can trigger a post creation
# <form action="http://victim-blog.com/create_post" method="POST">
#   <input type="hidden" name="title" value="CSRF Post">
#   ...
#   <input type="submit">
# </form>
# <script>document.forms[0].submit();</script>
```

Fix
Implement CSRF protection using a library like `Flask-WTF` or `Flask-SeaSurf`. Ensure every state-changing request (POST, PUT, DELETE) requires a valid CSRF token.

---

MEDIUM - Path Traversal
The `/post/<name>` route uses `os.path.join` with the user-controlled `name` parameter to construct a file path. While Flask's default routing may limit some traversal attempts, the code itself is vulnerable. If an attacker can bypass routing restrictions, they could potentially read any `.md` file on the filesystem that the application has access to.

PoC
```python
import requests
# Example attempt to read a file outside the articles directory
# This may depend on the server environment and routing configuration
r = requests.get("http://127.0.0.1:5000/post/..%2f..%2fetc%2fpasswd")
```

Fix
Validate that the requested `name` does not contain directory traversal sequences (like `..`) and ensure the resulting path stays within the intended directory. Use `werkzeug.utils.secure_filename` or verify the absolute path.

---

LOW - IP Spoofing via 'CF-Real-IP' Header
The application's context processor trusts the `CF-Real-IP` header to identify the user's IP address. If the application is not behind a Cloudflare proxy that strips this header from untrusted sources, an attacker can spoof their IP address by providing a custom `CF-Real-IP` header.

PoC
```python
import requests
headers = {'CF-Real-IP': '1.2.3.4'}
r = requests.get("http://127.0.0.1:5000/", headers=headers)
# The application will now believe the user's IP is 1.2.3.4
```

Fix
Only trust headers like `CF-Real-IP` or `X-Forwarded-For` if the application is known to be behind a trusted proxy. Configure the application to use a middleware like `ProxyFix` from Werkzeug with proper configuration.

====

Summary:

| Severity | Exploit Name |
| :--- | :--- |
| CRITICAL | Stored Cross-Site Scripting (XSS) |
| MEDIUM | Missing CSRF Protection |
| MEDIUM | Path Traversal |
| LOW | IP Spoofing via 'CF-Real-IP' Header |
