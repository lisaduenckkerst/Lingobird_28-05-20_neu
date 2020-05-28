import hashlib
import uuid
import sqlite3
import datetime

from flask import Flask, render_template, request, redirect, session, url_for, make_response, Blueprint

from models.user import User
from models.settings import db

discover_handlers = Blueprint("discover", __name__)


@discover_handlers.route("/discover")  # CONTROLLER
def discover():
    session_token = request.cookies.get("session_token")
    user = db.query(User).filter_by(session_token=session_token).first()

    return render_template("discover.html", user=user)  # VIEW
