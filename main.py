from flask import Flask, redirect, render_template
from flask_login import LoginManager, current_user, login_required, login_user, logout_user

import hashing
from data import db_session
from data.users import User
from forms.user import AddForm, LoginForm, RegisterForm
from utils import *

# TODO:
#    ~ Fix frontend
#    ~ Check usual user access
# ------------------------------------
#    ~ Archive users
#    ~ Clear code snippets

app = Flask(__name__)
app.config['SECRET_KEY'] = '9@K#3jP!2dR$5sF6gV%1hL&8kM4nT7bY*0cX2zQ1wE4'

login_manager = LoginManager()
login_manager.init_app(app)

db_session.global_init('db/users.db')


@login_manager.user_loader
def load_user(user_id):
    db_sess = db_session.create_session()
    return db_sess.query(User).get(user_id)


@app.route('/')
def start():
    return redirect('/login')


@unregistered_required
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        db_sess = db_session.create_session()
        user = db_sess.query(User).filter(User.email == form.email.data).first()
        if user and user.hashed_password == hashing.myhash(form.password.data):
            login_user(user, remember=form.remember_me.data)
            return redirect('/success')
        return render_template('login.html', message='Incorrect login or password', form=form)
    return render_template('login.html', title='Authorisation', form=form)


@unregistered_required
@app.route('/register', methods=['GET', 'POST'])
def reqister():
    form = RegisterForm()
    if form.validate_on_submit():
        if not email_check(form.email.data):
            return render_template('register.html', form=form, message='Invalid email adress')
        if form.password.data != form.password_again.data:
            return render_template('register.html', form=form, message='Passwords don\'t match')
        if password_check(form.password.data) != 'Password is strong':
            return render_template('register.html', form=form, message=password_check(form.password.data))
        db_sess = db_session.create_session()
        if db_sess.query(User).filter(User.email == form.email.data).first():
            return render_template('register.html', form=form, message='User already exists')
        user = User(name=form.name.data, email=form.email.data)
        user.hashed_password = hashing.myhash(form.password.data)
        db_sess.add(user)
        db_sess.commit()
        return redirect('/login')
    return render_template('register.html', title='Registration', form=form)


@login_required
@admin_required
@app.route('/adduser', methods=['GET', 'POST'])
def add_user():
    form = AddForm()
    if form.validate_on_submit():
        db_sess = db_session.create_session()
        user = User()
        user.name = form.name.data
        user.email = form.email.data
        user.hashed_password = form.hashed_password.data
        user.admin = form.admin.data
        user.archived = form.archived.data
        db_sess.add(user)
        db_sess.commit()
        return redirect('/')
    return render_template('add.html', title='Add user', form=form)


@login_required
@app.route('/success')
def success():
    return render_template('success.html')


@login_required
@admin_required
@app.route('/admin')
def admin_page():
    db_sess = db_session.create_session()
    users = db_sess.query(User)
    return render_template('admin.html', users=users)


@app.route('/notadmin')
def notadmin_page():
    return render_template('notadmin.html')


@login_required
@app.route('/logout')
def logout():
    logout_user()
    return redirect('/login')


if __name__ == '__main__':
    app.run(port=5000, host='127.0.0.1')
