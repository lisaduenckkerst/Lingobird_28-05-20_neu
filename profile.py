import hashlib
import uuid
import sqlite3
import datetime

from flask import Flask, render_template, request, session, redirect, session, url_for, make_response, Blueprint

from models.user import User
from models.settings import db
from models.profile_data import ProfileData

profile_handlers = Blueprint("profile", __name__)


@profile_handlers.route("/profile", methods=["GET", "POST"])
def profile():
    session_token = request.cookies.get("session_token")
    user = db.query(User).filter_by(session_token=session_token).first()

    print(user.id)

    owner_id = user.id
    print(owner_id)
    profile_owner_data = db.query(ProfileData).filter_by(owner_id=owner_id).first()

    if profile_owner_data:
        firstname = profile_owner_data.firstname
        lastname = profile_owner_data.lastname

        print(profile_owner_data.firstname)
        print(profile_owner_data.lastname)

        if not user:
            return render_template("login.html")
        else:
            return render_template("profile.html", user=user, username=user.username, session_token=session_token,
                                   profile_owner_data=profile_owner_data, firstname=firstname, lastname=lastname,
                                   owner_id=owner_id)

    else:

        if not user:
            return render_template("login.html")
        else:
            return render_template("profile.html", user=user, username=user.username, session_token=session_token,
                                   profile_owner_data=profile_owner_data, owner_id=owner_id)

    # profile_data = db.query(ProfileData).filter_by(owner_id=owner_id).first()

    # profile_data = db.query(ProfileData).all()

    # get profile data
    # profile_data = db.query(ProfileData).all()
    # profile_owner_data = db.query(ProfileData).filter_by(id=profile_data.id).first()

    # profile_data = db.query(ProfileData).get(int(profile_id))
    # profile_data_id = db.query(ProfileData).get("profile_data.id")

    # owner_id = user.id
    # print(owner_id)
    # profile_data = ProfileData(owner_id=owner_id)
    # db.commit()

    # firstname = profile_data.firstname

    # user.firstname = ProfileData(profile_data=firstname, owner=user)
    # profile_data.firstname = ProfileData(firstname=profile_data.firstname, owner=user)


@profile_handlers.route("/profile-edit/<profile_id>", methods=["GET", "POST"])
def profile_edit(profile_id):
    # profile_owner_data = db.query(ProfileData).get(int(profile_id))

    if request.method == "GET":
        session_token = request.cookies.get("session_token")
        user = db.query(User).filter_by(session_token=session_token).first()

        # get profile data
        # profile_data = db.query(ProfileData).all()
        owner_id = user.id
        profile_owner_data = db.query(ProfileData).filter_by(owner_id=owner_id).first()

        return render_template("profile-edit.html", user=user, profile_owner_data=profile_owner_data,
                               profile_id=profile_id)

    elif request.method == "POST":

        firstname = request.form.get("firstname")
        lastname = request.form.get("lastname")

        # get owner
        session_token = request.cookies.get("session_token")
        user = db.query(User).filter_by(session_token=session_token).first()

        owner_id = user.id
        profile_owner_data = db.query(ProfileData).filter_by(owner_id=owner_id).first()

        profile_owner_data.firstname = firstname
        profile_owner_data.lastname = lastname
        db.add(profile_owner_data)
        db.commit()

        return redirect(url_for('profile.profile'))


@profile_handlers.route("/profile-add", methods=["GET", "POST"])
def profile_add():
    # session_token = request.cookies.get("session_token")
    # user = db.query(User).filter_by(session_token=session_token).first()

    if request.method == "GET":
        session_token = request.cookies.get("session_token")
        user = db.query(User).filter_by(session_token=session_token).first()

        # get profile data
        owner_id = user.id
        profile_owner_data = db.query(ProfileData).filter_by(owner_id=owner_id).first()

        return render_template("profile-add.html", user=user, profile_owner_data=profile_owner_data)

    elif request.method == "POST":

        firstname = request.form.get("firstname")
        lastname = request.form.get("lastname")

        # get owner
        session_token = request.cookies.get("session_token")
        user = db.query(User).filter_by(session_token=session_token).first()

        profile_owner_data = ProfileData.create(firstname=firstname, lastname=lastname, owner=user)
        # owner_id = user.id
        # profile_owner_data = db.query(ProfileData).filter_by(owner_id=owner_id).first()

        response = make_response(redirect(url_for('profile.profile', profile_owner_data=profile_owner_data)))

        return response
