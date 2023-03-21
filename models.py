from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
from sqlalchemy import ForeignKey
from extensions import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

class Channel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    creator_id = db.Column(db.Integer, ForeignKey('user.id'), nullable=False)
    creator = relationship('User', backref='channels')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(256), nullable=False)
    user_id = db.Column(db.Integer, ForeignKey('user.id'), nullable=False)
    user = relationship('User', backref='messages')
    channel_id = db.Column(db.Integer, ForeignKey('channel.id'), nullable=False)
    channel = relationship('Channel', backref='messages')