from functools import wraps


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
        user = db_sess.query(User).filter(User.id == current_user.id, User.name == current_user.name).first()
        if not user.admin:
            return redirect('/notadmin')
        return f(*args, **kwargs)

    return decorated_function


def password_check(password):
    if len(password) < 8:
        return 'Password is too short. It should be at least 8 characters long.'

    if not any(char.isupper() for char in password):
        return 'Password should contain at least one uppercase letter.'

    if not any(char.islower() for char in password):
        return 'Password should contain at least one lowercase letter.'

    if not any(char.isdigit() for char in password):
        return 'Password should contain at least one digit.'

    special_characters = '!@#$%^&*()-_=+[]}{;:,.<>/?'
    if not any(char in special_characters for char in password):
        return 'Password should contain at least one special character.'

    return 'Password is strong'


def email_check(email):
    if '@' in email and '.' in email:
        at_index = email.index('@')
        dot_index = email.index('.')
        if at_index < dot_index - 1 and email and email[-1] != '.':
            return True
    return False