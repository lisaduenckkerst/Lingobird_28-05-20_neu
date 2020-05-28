import hashlib
import uuid
import sqlite3
import datetime

from flask import Flask, render_template, request, session, redirect, session, url_for, make_response, Blueprint

from models.user import User
from models.settings import db

auth_handlers = Blueprint("auth", __name__)


@auth_handlers.route("/login", methods=["GET", "POST"])  # CONTROLLER
def login():
    if request.method == "GET":
        return render_template("login.html")

    elif request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        # session_token = str(uuid.uuid4())

        # get password hash out of password
        password_hash = str(hashlib.sha256(password.encode()).hexdigest())

        # get user form database by username and password
        user = db.query(User).filter_by(username=username).first()

        if not user:
            return "User does not exist"
        else:
            if password_hash == user.password_hash:
                user.session_token = str(uuid.uuid4())
                db.add(user)
                db.commit()

                response = make_response(
                    redirect(url_for('profile.profile', user=user, username=user.username, password_hash=password_hash)))
                response.set_cookie("session_token", user.session_token, httponly=True, samesite='Strict')

               # response = redirect(url_for('profile.profile', user=user, username=user.username, password_hash=password_hash))
               # response.set_cookie("session_token", user.session_token, httponly=True, samesite='Strict')

                return response
            else:
                return "Invalid Username or Password"


# @auth_handlers.route("/profile", methods=["GET", "POST"])
# def profile():
  #  session_token = request.cookies.get("session_token")
   # user = db.query(User).filter_by(session_token=session_token).first()

    # if not user:
      #  return render_template("login.html")

   # else:
    #    return render_template("profile.html", user=user, username=user.username, session_token=session_token)


@auth_handlers.route("/signup", methods=["GET", "POST"])  # CONTROLLER
def signup():
    if request.method == "GET":
        return render_template("signup.html")

    elif request.method == "POST":

        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        repeat = request.form.get("repeat")

        if password != repeat:
            return "Passwords do not match! Go back and try again."

        user = User(username=username, password_hash=hashlib.sha256(password.encode()).hexdigest(),
                    session_token=str(uuid.uuid4()), email=email)

        db.add(user)
        db.commit()

        response = make_response(redirect(url_for('profile.profile', user=user, username=username)))
        response.set_cookie("session_token", user.session_token, httponly=True, samesite='Strict')

        if user:

            return response

        else:

            return render_template("signup.html")


@auth_handlers.route("/logout", methods=["GET", "POST"])  # CONTROLLER
def logout():
    if request.method == "GET":
        session_token = request.cookies.get("session_token")
        user = db.query(User).filter_by(session_token=session_token).first()

        user.session_token = None

        db.commit()

    return render_template("login.html")
