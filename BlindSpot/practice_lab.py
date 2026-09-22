"""
A tiny, deliberately vulnerable Flask site — for practicing with BlindSpot
without ever touching a real website.

Run it on its own, in a second terminal, while BlindSpot runs in the first:
    python practice_lab.py

Then scan http://127.0.0.1:5055 from BlindSpot's home page. You should see
it flag: no HTTPS, an exposed .env and .git/config, a fake exposed backup,
a directory listing at /backup/, a cookie missing security attributes, and
an error page that leaks technical details.

This is for local practice only — never deploy this file anywhere public.
"""
from flask import Flask, make_response

app = Flask(__name__)


@app.route("/")
def home():
    response = make_response("<h1>My Practice Shop</h1><p>Welcome!</p>")
    response.set_cookie("session_id", "abc123")  # intentionally insecure
    return response


@app.route("/.env")
def env_file():
    return "DB_PASSWORD=supersecret123\nAPI_KEY=sk-test-456\n"


@app.route("/.git/config")
def git_config():
    return "[remote \"origin\"]\n\turl = git@github.com:secret/repo.git\n"


@app.route("/backup.zip")
def backup():
    return "PK\x03\x04fake-backup-contents"


@app.route("/backup/")
def backup_dir():
    return (
        "<html><body><h1>Index of /backup/</h1>"
        "<ul><li>passwords.txt</li><li>admin_notes.txt</li><li>database_dump.sql</li></ul>"
        "</body></html>"
    )


@app.errorhandler(404)
def not_found(error):
    return (
        "<h1>Traceback (most recent call last)</h1>"
        "<p>File \"C:\\practice_app\\app.py\", line 42, in view</p>"
        "<p>sqlite3.OperationalError: no such table: users</p>",
        404,
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5055, debug=False)
