from app.errors import error_response
from app.models import Admin
from flask_httpauth import HTTPTokenAuth
from jwt.exceptions import ExpiredSignatureError
from jwt.exceptions import DecodeError

token_auth = HTTPTokenAuth()


@token_auth.verify_token
def verify_token(token):

    try:
        verify = Admin.check_token(token) if token else False
    except ExpiredSignatureError:
        return False
    except DecodeError:
        return False
    return verify


@token_auth.error_handler
def token_auth_error():
    return error_response(401)