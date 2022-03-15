from flask import Flask, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from config import Config
from flask_cors import CORS
from flask_socketio import SocketIO
from flask_bootstrap import Bootstrap
from flask_login import LoginManager

app = Flask(__name__)
app.config.from_object(Config)
cors = CORS(app, resources={r"/api/*": {"origins": "*"}})
db = SQLAlchemy(app)
migrate = Migrate(app, db)
socketio = SocketIO(app)
bootstrap = Bootstrap(app)

login = LoginManager(app)
login.login_view = 'ui_api.login_front'

from app.ext_api import bp as ext_api_bp
from app.ui_api import bp as ui_api_bp


app.register_blueprint(ext_api_bp, url_prefix='/api/ext')
app.register_blueprint(ui_api_bp, url_prefix='/api/ui')


from app import models, errors#, amqp_communication

@app.route('/')
def targets_redirect():
    return redirect(url_for('ui_api.get_targets_front'), code=302)