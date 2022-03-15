from flask import Blueprint

bp = Blueprint('ext_api', __name__)

from app.ext_api import api
