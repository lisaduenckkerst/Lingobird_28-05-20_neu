from models.settings import db
from datetime import datetime


class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    contact_name = db.Column(db.String, unique=True)  # a username must be unique!
    contact_email = db.Column(db.String, unique=True)
    contact_message = db.Column(db.String, unique=True)
    session_token = db.Column(db.String)
    created = db.Column(db.DateTime, default=datetime.utcnow)
