import hashlib
import uuid
import sqlite3
import datetime

from flask import Flask, render_template, request, redirect, session, url_for, make_response, Blueprint

community_handlers = Blueprint("community", __name__)


@community_handlers.route("/community")  # CONTROLLER
def community():
    return render_template("community.html")  # VIEW
