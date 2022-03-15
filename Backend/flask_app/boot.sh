#!/bin/sh
#source venv/bin/activate
rq worker -u redis://redisq:6379 pdf-gen &
exec gunicorn main:app --worker-class eventlet -w 1 --bind 0.0.0.0:5000 --reload
