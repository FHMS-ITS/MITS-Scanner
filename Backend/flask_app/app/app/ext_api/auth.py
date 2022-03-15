import jwt
from jwt.exceptions import ExpiredSignatureError
from jwt.exceptions import DecodeError

from app import Config
from app.models import Target
from flask_httpauth import HTTPTokenAuth
from app.errors import error_response
from flask import g, request
from flask_socketio import disconnect
import functools

token_auth = HTTPTokenAuth()

def ver_token(token):
    if not token:
        print("No token")
        return False
    try:
        g.current_target = jwt.decode(token, Config.SECRET_KEY, algorithms=['HS256'])
    except ExpiredSignatureError:
        print("Expired")
        return False
    except DecodeError:
        print("Decode Error")
        return False
    return True


@token_auth.verify_token
def verify_token(token):
    if ver_token(token):
        return Target.query.filter_by(id=g.current_target['target_id']).first() is not None
    else:
        return False


@token_auth.error_handler
def token_auth_error():
    print("Token error")
    return error_response(401)


def authenticated_token(f):
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not ver_token(auth_header.split(" ")[1]):
            disconnect()
        else:
            return f(*args, **kwargs)
    return wrapped