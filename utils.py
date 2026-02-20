import os, frontmatter

POSTS_DIR = os.environ.get("POSTS_DIR", "./articles")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")


def add_watermark(input_path, output_path, watermark_path):
    from PIL import Image

    img = Image.open(input_path).convert("RGBA")
    watermark = Image.open(watermark_path).convert("RGBA")

    wm_w, wm_h = watermark.size
    img_w, img_h = img.size

    x = img_w - wm_w - 15
    y = img_h - wm_h - 15

    alpha = watermark.split()[3].point(lambda i: int(i * 0.7))
    watermark.putalpha(alpha)

    img.paste(watermark, (x, y), watermark)
    img.convert("RGB").save(output_path)


def get_posts():
    posts = []
    for f in os.listdir(POSTS_DIR):
        if f.endswith(".md"):
            filepath = os.path.join(POSTS_DIR, f)
            post_file = frontmatter.load(filepath)
            posts.append({
                "title": post_file.get("title", f[:-3]),
                "author": post_file.get("author", "Anonyme"),
                "tags": post_file.get("tags", []),
                "filename": f[:-3],
                "date": post_file.get("date", "1970-01-01"),
                "content": post_file.content,
                "slug": f[:-3],
            })
    return posts