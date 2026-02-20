from flask import Flask, render_template, request, abort, session, redirect
import utils, os
from flask_caching import Cache

# === Configure app ===

app = Flask(__name__, template_folder='html')

# === Cache ===

app.config["CACHE_TYPE"] = "SimpleCache"
app.config["CACHE_DEFAULT_TIMEOUT"] = 300
app.config['SECRET_KEY'] = os.urandom(24)
cache = Cache(app)

# create cache folder
os.makedirs('cache', exist_ok=True)

# === Inject variables to templates ===

@app.context_processor
def inject_variables():
    return dict(
        user_ip=(request.headers.get('CF-Real-IP', request.remote_addr))
    )



@app.route('/')
@cache.cached(timeout=120) # 2 minutes
def index():
    posts = utils.get_posts()
    return render_template('index.html', posts=posts)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == utils.ADMIN_USERNAME and password == utils.ADMIN_PASSWORD:
            session['logged_in'] = True
            return redirect('/')
        else:
            return "Invalid credentials!", 401
    return render_template('login.html')

from routes import post, upload
app.register_blueprint(post.bp)
app.register_blueprint(upload.bp)

app.run(host='0.0.0.0', port=5000, debug=False)