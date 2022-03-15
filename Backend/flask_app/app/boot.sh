#!/bin/sh

source venv/bin/activate
#source /app/venv/bin/activate
#exec gunicorn -b :5000 --access-logfile - --error-logfile - errors:app
rq worker pdf-gen &
exec gunicorn main:app --worker-class eventlet -w 1 --bind 0.0.0.0:5000 --reload
service nginx reload
