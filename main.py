from functools import wraps

from flask import Flask, redirect, render_template
from flask_login import LoginManager, login_required, login_user, logout_user, current_user

from data import db_session
from data.news import News
from data.users import User
from forms.user import LoginForm, RegisterForm

def unregistered_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            return redirect('/success')
        return f(*args, **kwargs)
    return decorated_function

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key'

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
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            return redirect("/success")
        return render_template('login.html', message="Incorrect login or password", form=form)
    return render_template('login.html', title='Authorisation', form=form)

@app.route('/register', methods=['GET', 'POST'])
@unregistered_required
def reqister():
    form = RegisterForm()
    if form.validate_on_submit():
        if form.password.data != form.password_again.data:
            return render_template('register.html', form=form, message="Passwords don't match")
        db_sess = db_session.create_session()
        if db_sess.query(User).filter(User.email == form.email.data).first():
            return render_template('register.html', form=form, message="User already exists")
        user = User(name=form.name.data, email=form.email.data)
        user.set_password(form.password.data)
        db_sess.add(user)
        db_sess.commit()
        return redirect('/login')
    return render_template('register.html', title='Registration', form=form)

@app.route('/success')
@login_required
def success():
    return render_template("success.html")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')


if __name__ == '__main__':
    app.run(port=5000, host='127.0.0.1')

