from flask import jsonify
from werkzeug.http import HTTP_STATUS_CODES


def error_response(status_code, message=None):
    """
    Args:
        status_code -> int
        message -> str
    Returns:
        JSON dict with error response

    """
    payload = {'error': HTTP_STATUS_CODES.get(status_code, 'Unknown error')}
    if message:
        payload['message'] = message
    response = jsonify(payload)
    response.status_code = status_code
    return response


def bad_request(message):
    """
    Args:
        message -> str
    Returns:
        Error response with status code 400
    """

    return error_response(400, message)

