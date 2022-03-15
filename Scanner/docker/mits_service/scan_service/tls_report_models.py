from config import Config as conf
from peewee import *

db = SqliteDatabase(conf.TLS.PATH_DATABASE)


class BaseModel(Model):
    class Meta:
        database = db


class Report(BaseModel):
    text = CharField()
    json_rep = CharField()
