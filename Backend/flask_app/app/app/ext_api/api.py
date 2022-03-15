from app.ext_api import bp
from flask import request, jsonify, g
from app.errors import bad_request, error_response
from app.ext_api.auth import token_auth, authenticated_token
from app import Config, socketio
from app.models import Target
from werkzeug.utils import secure_filename
import os, pathlib, jwt
from werkzeug.exceptions import BadRequestKeyError
from datetime import datetime
from flask_socketio import emit
from flask_socketio import disconnect



@bp.route('/process-status', methods=['POST'])
@token_auth.login_required
def process_status():
    """
    View to Receive status messages from client and save them to database
    Returns:
        Status message -> JSON
    """
    try:
        status_msg = request.form['status_msg']
        msg_type = request.form['msg_type']
    except BadRequestKeyError:
        return error_response(401, "Bad request key")
    if not status_msg:
        return bad_request(message="No message")

    target = Target.query.get_or_404(g.current_target['target_id'])
    target.set_status(status_msg, msg_type)

    return jsonify({status_msg: msg_type})


def allowed_file(filename):
    """
    Args:
        filename -> str
    Returns:
        If file extension is JSON -> bool

    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() == 'json'


@bp.route('/process-report', methods=['POST'])
@token_auth.login_required
def process_report():
    """
    View to Receive JSON report from client and save it
    Returns:
        JSON Success Message
    """
    try:
        report = request.files['report-json']
    except BadRequestKeyError:
        return error_response(401, "Bad request key")
    if report and allowed_file(report.filename):
        target = Target.query.get_or_404(g.current_target['target_id'])
        filename = target.name + secure_filename(report.filename)
        pathlib.Path(Config.REPORT_FOLDER, str(g.current_target['target_id'])).mkdir(exist_ok=True)
        report.save(os.path.join(Config.REPORT_FOLDER, str(g.current_target['target_id']), filename))
        return {"status": "ok"}
    error_response(401)


clients = {}


@socketio.on('connect')
@authenticated_token
def test_connect():
    """
    View to connect client via Websocket

    Append connected clients to list
    """
    target = Target.query.get_or_404(g.current_target['target_id'])
    clients[target.id] = request.sid


@socketio.on('disconnect')
@authenticated_token
def test_disconnect():
    """
    View to connect client via Websocket

    Remove clients from list
    """
    key_list = list(clients.keys())
    val_list = list(clients.values())
    client_id = val_list.index(request.sid)
    if not client_id is None:
        client_id = key_list[client_id]
        del clients[client_id]


@socketio.on('message')
@authenticated_token
def proc_soc_message(message):
    """
    View to receive WebSocket messages by client and save them in database
    Args:
        message: Message sent by client -> dict
    """
    target = Target.query.get_or_404(g.current_target['target_id'])
    # If message is a JWT save expiration time
    if message.get("success") and isinstance(message.get("success"), str) and message.get("success").startswith("ey"):
        try:
            exp_time = jwt.decode(message["success"], Config.SECRET_KEY, algorithms=['HS256'])
            date = datetime.fromtimestamp(exp_time["exp"])
            message = str(date)
        except:
            pass

    target.set_message(str(message), True)


def emit_message(msg, client_id):
    """
    Send message msg to client with client_id via Websocket

    Args:
        msg: Message to send -> str
        client_id: id of client which receives message -> int/str
    Returns:
        If message was sent successfully or None
    """
    if int(client_id) in clients:
        target = Target.query.get_or_404(client_id)
        target.set_message(msg, False)
        socketio.emit('message', {'data:': msg}, room=clients[int(client_id)])
        return 1
    return None



