from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, TextAreaField, SubmitField, EmailField, BooleanField
from wtforms.validators import DataRequired


class RegisterForm(FlaskForm):
    email = EmailField('Email adress', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    password_again = PasswordField('Repeat the password', validators=[DataRequired()])
    name = StringField('Username', validators=[DataRequired()])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    email = EmailField('Email Adress', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember me')
    submit = SubmitField('Log in')


class EditForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    hashed_password = StringField("Password", validators=[DataRequired()])
    created_date = StringField('Created Date', validators=[DataRequired()])
    admin = BooleanField("Admin")
    archived = BooleanField("Archived")
    submit = SubmitField('Submit')
