from models.settings import db
from datetime import datetime


class ProfileData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String)
    lastname = db.Column(db.String)
    birthday = db.Column(db.DateTime)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    owner = db.relationship("User")

    # age = db.Column(db.Integer)

    @classmethod
    def create(cls, firstname, lastname, owner):
        profile_data = cls(firstname=firstname, lastname=lastname, owner=owner)
        db.add(profile_data)
        db.commit()

        return profile_data
