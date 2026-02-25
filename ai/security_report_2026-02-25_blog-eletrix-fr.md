====

Auto Security Analysis of blog-eletrix-fr at 2026-02-25

CRITICAL - Stored Cross-Site Scripting (XSS)
The application allows users (admins) to create blog posts with Markdown content. This content is converted to HTML using `markdown2.markdown()` and then rendered in the `post.html` template using the `|safe` filter. Because `markdown2` does not sanitize HTML by default and the template explicitly trusts the output, an attacker can inject arbitrary JavaScript into a post. This script will execute in the context of any user who views the post, potentially leading to session hijacking or other malicious actions.

PoC
```python
import requests

# 1. Login as admin (assuming default credentials or CSRF)
# 2. Create a post with malicious payload
payload = {
    "title": "XSS Test",
    "author": "attacker",
    "tags": "test",
    "content": "<script>alert('XSS vulnerability confirmed!')</script>"
}
# requests.post('http://localhost:5000/create_post', data=payload)
# 3. View the post at /post/XSS-Test to see the script execute.
```

Fix
Use a library like `bleach` to sanitize the HTML generated from Markdown before passing it to the template, or avoid using the `|safe` filter and instead use a Markdown-to-HTML converter that handles sanitization.

====

MEDIUM - Path Traversal in Post Route
The `/post/<name>` route uses `os.path.join` to construct a file path from a user-supplied `name` parameter without proper validation. While the application appends `.md` to the path, an attacker can use `../` sequences to traverse outside the `articles/` directory and read other `.md` files on the system. Furthermore, if combined with the file upload functionality, an attacker can upload a malicious `.md` file and then read it via this route.

PoC
```python
import requests

# Assuming a file named 'secrets.md' exists in the root directory
# An attacker can access it via:
# response = requests.get('http://localhost:5000/post/../secrets')
# print(response.text)
```

Fix
Use `os.path.basename()` on the `name` parameter to ensure only the filename is used, or validate that the resulting path is within the intended directory.

====

MEDIUM - Missing CSRF Protection
The application lacks Cross-Site Request Forgery (CSRF) protection on all state-changing routes, including `/login`, `/create_post`, and `/upload`. An attacker can create a malicious website that, when visited by a logged-in admin, silently sends requests to the blog to create posts, upload files, or perform other actions.

PoC
```html
<!-- Malicious attacker-controlled page -->
<body onload="document.forms[0].submit()">
  <form action="http://localhost:5000/create_post" method="POST">
    <input type="hidden" name="title" value="CSRF-Post" />
    <input type="hidden" name="author" value="attacker" />
    <input type="hidden" name="tags" value="csrf" />
    <input type="hidden" name="content" value="This post was created via CSRF!" />
  </form>
</body>
```

Fix
Implement a CSRF protection mechanism, such as Flask-WTF's CSRFProtect, which adds unique tokens to forms and verifies them on submission.

====

LOW - IP Spoofing via CF-Real-IP Header
The application trusts the `CF-Real-IP` header to identify the user's IP address in the `inject_variables` context processor. Since this header is not verified to come from a trusted proxy (like Cloudflare), any user can spoof their IP address by setting this header in their request.

PoC
```python
import requests

headers = {'CF-Real-IP': '1.2.3.4'}
response = requests.get('http://localhost:5000/', headers=headers)
# The application will now believe the user's IP is 1.2.3.4
```

Fix
Only trust `CF-Real-IP` if the request is confirmed to come from a known Cloudflare IP range, or better, use `request.remote_addr` and configure the production WSGI server/reverse proxy to set it correctly.

====

LOW - Temporary File Leakage (DoS)
In the `/upload` route, the application saves an uploaded file to a temporary directory before attempting to add a watermark. If the file is not a valid image, `utils.add_watermark` (using Pillow) will raise an exception, causing the function to exit before `os.remove(temp_path)` is called. This leaves the temporary file on disk, which can lead to disk space exhaustion if exploited repeatedly.

PoC
```python
import requests
import io

# Upload a non-image file
files = {'file': ('test.txt', io.BytesIO(b"not an image"), 'text/plain')}
# requests.post('http://localhost:5000/upload', files=files)
# The file 'test.txt' will remain in ./temp_uploads/ indefinitely.
```

Fix
Use a `try...finally` block to ensure that the temporary file is deleted regardless of whether the watermarking process succeeds or fails.

====

Summary
| Severity | Count |
| --- | --- |
| CRITICAL | 1 |
| MEDIUM | 2 |
| LOW | 2 |
