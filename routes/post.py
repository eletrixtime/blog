
from flask import render_template, abort, Blueprint, session, request
import os
import frontmatter
import markdown2
import utils

bp = Blueprint('post', __name__)

from datetime import datetime
from werkzeug.utils import secure_filename



@bp.route('/post/<name>')
def post(name):
    filepath = os.path.join(utils.POSTS_DIR, f"{name}.md")
    if not os.path.exists(filepath):
        abort(404)
    post_file = frontmatter.load(filepath)
    html_content = markdown2.markdown(post_file.content)
    return render_template(
        'post.html',
        content=html_content,
        title=post_file.get("title", name),
        author=post_file.get("author", "Anonyme"),
        tags=post_file.get("tags", []),
        date=post_file.get("date", "1970-01-01")
    )

@bp.route('/create_post', methods=['GET', 'POST'])
def create_post():
    if not session.get('logged_in'):
        return abort(404)
    if request.method == 'POST':
        title = request.form['title']
        author = request.form['author']
        tags = request.form['tags']
        content = request.form['content']
        filepath = os.path.join(utils.POSTS_DIR, f"{title}.md")
        #sanitize filename
        filepath = os.path.join(utils.POSTS_DIR, secure_filename(f"{title}.md"))

        post = frontmatter.Post(
            content=content,
            **{
                "title": title,
                "author": author,
                "tags": tags.split(','),
                "date": datetime.now().strftime('%Y-%m-%d')
            }
        )

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(frontmatter.dumps(post))

    return render_template('create_post.html')
