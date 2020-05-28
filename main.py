import hashlib
import uuid
import sqlite3
import datetime

from flask import Flask, render_template, request, session, redirect, url_for, make_response, Blueprint

from utils import redis_helper

from handlers.auth import auth_handlers
from handlers.profile import profile_handlers
from handlers.contact import contact_handlers
from handlers.discover import discover_handlers
from handlers.landingpage import landingpage_handlers
from handlers.community import community_handlers
from handlers.classes import classes_handlers

from models.settings import db
from models.user import User
from models.contact import Contact
from models.profile_data import ProfileData

app = Flask(__name__)
app.register_blueprint(auth_handlers)
app.register_blueprint(profile_handlers)
app.register_blueprint(contact_handlers)
app.register_blueprint(discover_handlers)
app.register_blueprint(landingpage_handlers)
app.register_blueprint(community_handlers)
app.register_blueprint(classes_handlers)

db.create_all()

if __name__ == '__main__':
    app.run(debug=True)