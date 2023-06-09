from functools import wraps

from flask import Flask, redirect, render_template
from flask_login import LoginManager, login_required, login_user, logout_user, current_user

import hashing
from data import db_session
from data.users import User
from forms.user import LoginForm, RegisterForm


def unregistered_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            return redirect('/success')
        return f(*args, **kwargs)

    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        db_sess = db_session.create_session()
        user = db_sess.query(User).filter(User.id == kwargs.get('user_id')).first()
        #print(user, not not user)
        #print(user.admin, not not user.admin)
        if not user.admin: #FIXME
            return redirect('/notadmin')
        return f(*args, **kwargs)

    return decorated_function

def password_check(password):
    if len(password) < 8:
        return "Password is too short. It should be at least 8 characters long."

    if not any(char.isupper() for char in password):
        return "Password should contain at least one uppercase letter."

    if not any(char.islower() for char in password):
        return "Password should contain at least one lowercase letter."

    if not any(char.isdigit() for char in password):
        return "Password should contain at least one digit."

    special_characters = "!@#$%^&*()-_=+[]}{;:,.<>/?"
    if not any(char in special_characters for char in password):
        return "Password should contain at least one special character."

    return "Password is strong"

def email_check(email):
    if '@' in email and '.' in email:
        at_index = email.index('@')
        dot_index = email.index('.')
        if at_index < dot_index - 1 and email and email[-1] != '.':
            return True
    return False

app = Flask(__name__)
app.config['SECRET_KEY'] = '9@K#3jP!2dR$5sF6gV%1hL&8kM4nT7bY*0cX2zQ1wE4'

login_manager = LoginManager()
login_manager.init_app(app)

db_session.global_init("db/users.db")


@login_manager.user_loader
def load_user(user_id):
    db_sess = db_session.create_session()
    return db_sess.query(User).get(user_id)


@app.route('/')
def start():
    return redirect('/login')


@app.route('/login', methods=['GET', 'POST'])
@unregistered_required
def login():
    form = LoginForm()
    if form.validate_on_submit():
        db_sess = db_session.create_session()
        user = db_sess.query(User).filter(User.email == form.email.data).first()
        if user and user.hashed_password == hashing.myhash(form.password.data):
            login_user(user, remember=form.remember_me.data)
            return redirect("/success")
        return render_template('login.html', message="Incorrect login or password", form=form)
    return render_template('login.html', title='Authorisation', form=form)


@app.route('/register', methods=['GET', 'POST'])
@unregistered_required
def reqister():
    form = RegisterForm()
    if form.validate_on_submit():
        if not email_check(form.email.data):
            return render_template('register.html', form=form, message='Invalid email adress')
        if form.password.data != form.password_again.data:
            return render_template('register.html', form=form, message="Passwords don't match")
        if password_check(form.password.data) != "Password is strong":
            return render_template('register.html', form=form, message=password_check(form.password.data))
        db_sess = db_session.create_session()
        if db_sess.query(User).filter(User.email == form.email.data).first():
            return render_template('register.html', form=form, message="User already exists")
        user = User(name=form.name.data, email=form.email.data)
        user.hashed_password = hashing.myhash(form.password.data)
        db_sess.add(user)
        db_sess.commit()
        return redirect('/login')
    return render_template('register.html', title='Registration', form=form)


@app.route('/success')
@login_required
def success():
    return render_template("success.html")


@app.route('/admin')
@admin_required
def admin_page():
    return "<h1>ADMIN!!!!!!</h1>"


@app.route('/notadmin')
def notadmin_page():
    return "<h1>YOU ARE NOT ADMIN!!!!!!</h1>"


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')


if __name__ == '__main__':
    app.run(port=5000, host='127.0.0.1')

