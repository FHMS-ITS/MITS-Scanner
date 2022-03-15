import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app-db/app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.environ.get('SECRET_KEY') or "7fa0bdc2cce1456097d0e50fd3857720"
    CORS_HEADERS = 'Content-Type'
    REPORT_FOLDER = os.environ.get('REPORT_FOLDER') or 'reports'
    PDF_REPORT_FOLDER = os.environ.get('PDF_REPORT_FOLDER') or 'pdf_reports'
    MAX_CONTENT_LENGTH = 1024 * 1024
    UPLOAD_EXTENSIONS = ['.txt']
    IMAGES = "images"
    REDIS = "redis://redisq:6379"

