from flask import render_template, abort, Blueprint, session, request
import os
import shutil
import uuid
import utils
from werkzeug.utils import secure_filename

bp = Blueprint('upload', __name__, url_prefix='/upload')
TEMP_DIR = "./temp_uploads"
FINAL_DIR = "./static/blog_content"

os.makedirs(TEMP_DIR, exist_ok=True)
os.makedirs(FINAL_DIR, exist_ok=True)

@bp.route('/', methods=['GET', 'POST'])
def upload():
    if not session.get('logged_in'):
        return abort(404)

    if request.method == 'POST':
        file = request.files['file']
        if not file:
            return "No file uploaded", 400

        temp_path = os.path.join(TEMP_DIR, secure_filename(file.filename))
        file.save(temp_path)

        final_filename = f"{uuid.uuid4()}{os.path.splitext(file.filename)[1]}"
        final_path = os.path.join(FINAL_DIR, final_filename)

        utils.add_watermark(temp_path, final_path, "static/watermark.png")

        os.remove(temp_path)

        return f"Done: {final_filename}"

    return render_template('upload.html')
