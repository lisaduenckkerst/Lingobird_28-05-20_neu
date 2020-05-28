import hashlib
import uuid
import sqlite3
import datetime

from flask import Flask, render_template, request, redirect, session, url_for, make_response, Blueprint

from models.user import User
from models.settings import db

landingpage_handlers = Blueprint("landingpage", __name__)


@landingpage_handlers.route("/")  # CONTROLLER
def index():
    session_token = request.cookies.get("session_token")
    user = db.query(User).filter_by(session_token=session_token).first()

    return render_template("index.html", user=user)  # VIEW


@landingpage_handlers.route("/about")  # CONTROLLER
def about():
    session_token = request.cookies.get("session_token")
    user = db.query(User).filter_by(session_token=session_token).first()

    return render_template("index.html", user=user)  # VIEW
