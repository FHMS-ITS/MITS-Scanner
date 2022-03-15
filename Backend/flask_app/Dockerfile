FROM ubuntu:latest
FROM python:3.6

COPY ./app /app
COPY ./boot.sh /app

WORKDIR /app

RUN apt-get -y update
RUN apt-get -y install texlive texlive-lang-german texlive-latex-extra 
RUN pip install --upgrade pip
RUN pip install gunicorn
RUN pip install -r requirements.txt

ENV FLASK_APP main.py


ENTRYPOINT ["./boot.sh"]

