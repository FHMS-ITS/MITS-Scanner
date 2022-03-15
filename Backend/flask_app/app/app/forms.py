from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, HiddenField
from wtforms.validators import DataRequired, Length
from wtforms.fields.html5 import DateField
from flask_wtf.file import FileField, FileRequired


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    token = StringField('Token', validators=[DataRequired(), Length(6, 6)])
    submit = SubmitField('Sign In')


class CommunicationForm(FlaskForm):
    message = TextAreaField(validators=[DataRequired()])
    submit = SubmitField('Send')


class TokenForm(FlaskForm):
    expiration = DateField(validators=[DataRequired()], format="%Y-%m-%d")
    submit = SubmitField('Generate')
    update = SubmitField('Update')

class TargetForm(FlaskForm):
    name = StringField('Target Name', validators=[DataRequired()])
    submit = SubmitField('Create')


class IpsForm(FlaskForm):
    file = FileField('IPs', validators=[FileRequired()])
    submit = SubmitField('Submit')


class ExIpsForm(FlaskForm):
    fileex = FileField('Exclude IPs', validators=[FileRequired()])
    submit = SubmitField('Submit')


class LogPfdReportForm(FlaskForm):
    report_name_log = HiddenField("")
    submit = SubmitField('Log')


class LowPfdReportForm(FlaskForm):
    report_name_low = HiddenField("")
    submit = SubmitField('Low')


class MediumPfdReportForm(FlaskForm):
    report_name_medium = HiddenField("")
    submit = SubmitField('Medium')


class HighPfdReportForm(FlaskForm):
    report_name_high = HiddenField("")
    submit = SubmitField('High')

