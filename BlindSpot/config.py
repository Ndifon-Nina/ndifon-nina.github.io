import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, ".env"))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-secret-key-change-this")
    DEBUG = os.environ.get("FLASK_DEBUG", "0") in ("1", "true", "True")
    PORT = int(os.environ.get("PORT", "8000"))
    DATABASE = os.path.join(basedir, "instance", "blindspot.db")
