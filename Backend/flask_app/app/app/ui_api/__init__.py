from flask import Blueprint

bp = Blueprint('ui_api', __name__)

from app.ui_api import api