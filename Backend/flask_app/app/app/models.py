from app import db
from datetime import datetime
from time import time
from app import Config
import jwt
from flask import url_for
from werkzeug.security import check_password_hash
from flask_login import UserMixin
from app import login
import onetimepass


class PaginatedAPIMixin(object):
    @staticmethod
    def to_collection_dict_paginated(query, page, per_page, endpoint, **kwargs):
        resources = query.paginate(page, per_page, False)
        data = {
            'items': [item.to_dict() for item in resources.items],
            '_meta': {
                'page': page,
                'per_page': per_page,
                'total_pages': resources.pages,
                'total_items': resources.total
            },
            '_links': {
                'self': url_for(endpoint, page=page, per_page=per_page,
                                **kwargs),
                'next': url_for(endpoint, page=page + 1, per_page=per_page,
                                **kwargs) if resources.has_next else None,
                'prev': url_for(endpoint, page=page - 1, per_page=per_page,
                                **kwargs) if resources.has_prev else None
            }
        }
        return data

    @staticmethod
    def to_collection_dict_raw(query):

        return [item.to_dict() for item in query.all()]


class Target(PaginatedAPIMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), index=True, unique=True)
    status = db.relationship('Status', backref='target', lazy='dynamic')
    message = db.relationship('Message', backref='target', lazy='dynamic')
    #progress = db.Column(db.Integer, default=0)
    progress_t = db.Column(db.String(256), default="0")
    progress_update = db.Column(db.DateTime, index=True)
    ip = db.Column(db.String(15), index=True)

    def generate_token(self, exp_time):
        return jwt.encode({'target_id': self.id, 'exp': time() + exp_time}, Config.SECRET_KEY, algorithm='HS256').decode('utf-8')

    def set_status(self, msg, msg_type):
        if msg_type == "process":
            self.progress_t = msg
            self.progress_update = datetime.utcnow()
            db.session.commit()
        else:
            status = Status(body=msg, target_id=self.id, type=msg_type)
            db.session.add(status)
            db.session.commit()
            return status

    def set_message(self, msg, created_by_target):
        message = Message(body=msg, target_id=self.id, created_by_target=created_by_target)
        db.session.add(message)
        db.session.commit()
        return message

    def to_dict(self):
        data = {
            "id": self.id,
            "name": self.name,
            "progress": self.progress_t,
            "progress_update": self.progress_update
        }
        return data

    def from_dict(self, data):
        for field in ['name']:
            if field in data:
                setattr(self, field, data[field])

    def __repr__(self):
        return '<Target {}>'.format(self.name)


class Status(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(140))
    type = db.Column(db.String(20))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    target_id = db.Column(db.Integer, db.ForeignKey('target.id'))

    def to_dict(self):
        data = {
            "id" : self.id,
            "body": self.body,
            "type": self.type,
            "timestamp": self.timestamp
        }
        return data

    def __repr__(self):
        return '<Status {}>'.format(self.body)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(200))
    created_by_target = db.Column(db.Boolean)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    target_id = db.Column(db.Integer, db.ForeignKey('target.id'))

    def to_dict(self):
        data = {
            "id" : self.id,
            "body": self.body,
            "timestamp": self.timestamp,
            "created_by_target": self.created_by_target
        }
        return data

    def __repr__(self):
        return '<Message {}>'.format(self.body)


class Admin(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    password_hash = db.Column(db.String(128))
    username = 'admin'
    otp_secret = db.Column(db.String(16))

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_token(self, exp_time=86400):
        return jwt.encode({'user': self.username, 'exp': time() + exp_time}, Config.SECRET_KEY, algorithm='HS256').decode('utf-8')

    @staticmethod
    def check_token(token):
        return 'admin' == jwt.decode(token, Config.SECRET_KEY, algorithms=['HS256'])['user']

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def get_totp_uri(self):
        return 'otpauth://totp/Lev-3:{0}?secret={1}&issuer=Lev-3' \
            .format(self.username, self.otp_secret)

    def verify_totp(self, token):
        return onetimepass.valid_totp(token, self.otp_secret)


@login.user_loader
def load_user(id):
    return Admin.query.get(int(id))