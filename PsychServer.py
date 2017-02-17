from flask import Flask, render_template, redirect, url_for, request
from flask_login import login_required, LoginManager, UserMixin, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from Utilities import generate_confirmation_token, confirm_token, send_email,generate_timed_confirmation_token, confirm_timed_token
from hashlib import sha256
import Constants
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://{}:{}@{}:{}/{}'\
    .format(Constants.DB_USERNAME, Constants.DB_PASSWORD, Constants.DB_IP, Constants.DB_PORT, Constants.DB_NAME)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


# Database Table Models --------------------------------------------------------------


class Role(db.Model):
    __tablename__ = 'Role'
    role_id = db.Column('RoleID', db.BIGINT, nullable=False, autoincrement=True, primary_key=True)
    role_name = db.Column('RoleName', db.VARCHAR, nullable=False)

    def __init__(self, role_name):
        self.role_name = role_name


class Users(db.Model):
    __tablename__ = 'Users'
    user_id = db.Column('UserID', db.BIGINT, nullable=False, autoincrement=True, primary_key=True)
    user_email = db.Column('UserEmail', db.VARCHAR, nullable=False)
    user_pw_hash = db.Column('UserPWHash', db.VARCHAR, nullable=False)
    user_salt = db.Column('UserSalt', db.VARCHAR, nullable=False)
    user_role = db.Column('UserRole', db.BIGINT, db.ForeignKey(Role.role_id), nullable=False)
    user_psych_major = db.Column('UserPsychMajor', db.BOOLEAN, nullable=False)
    user_psych_minor = db.Column('UserPsychMinor', db.BOOLEAN, nullable=False)
    created_on = db.Column('CreatedOn', db.DATETIME)

    def __init__(self, email, pw_hash, salt, role, psych_major, psych_minor):
        self.user_email = email
        self.user_pw_hash = pw_hash
        self.user_salt = salt
        self.user_role = role
        self.user_psych_major = psych_major
        self.user_psych_minor = psych_minor


class Research(db.Model):
    __tablename__ = 'Research'
    research_id = db.Column('ResearchID', db.BIGINT, nullable=False, autoincrement=True, primary_key=True)
    research_name = db.Column('ResearchName', db.VARCHAR, nullable=False)
    research_facilitator = db.Column('ResearchFacilitator', db.BIGINT, db.ForeignKey(Users.user_id), nullable=False)
    research_description = db.Column('ResearchDescription', db.VARCHAR, nullable=False)
    research_credits = db.Column('ResearchCredits', db.INTEGER, nullable=False)
    research_openings = db.Column('ResearchOpenings', db.INTEGER, nullable=False)
    is_visible = db.Column('IsVisible', db.BOOLEAN, nullable=False)
    is_deleted = db.Column('IsDeleted', db.BOOLEAN, nullable=False)
    created_on = db.Column('CreatedOn', db.DATETIME)

    def __init__(self, name, facilitator, description, credits, openings, visible, deleted):
        self.research_name = name
        self.research_facilitator = facilitator
        self.research_description = description
        self.research_credits = credits
        self.research_openings = openings
        self.is_visible = visible
        self.is_deleted = deleted


class ResearchSlot(db.Model):
    __tablename__ = 'ResearchSlot'
    research_slot_id = db.Column('ResearchSlotID', db.BIGINT, nullable=False, autoincrement=True, primary_key=True)
    research_id = db.Column('ResearchID', db.BIGINT, db.ForeignKey(Research.research_id), nullable=False)
    start_time = db.Column('StartTime', db.DATETIME, nullable=False)
    end_time = db.Column('EndTime', db.DATETIME, nullable=False)
    created_on = db.Column('CreatedOn', db.DATETIME)

    def __init__(self, rid, start, end):
        self.research_id = rid
        self.start_time = start
        self.end_time = end


class StudentResearch(db.Model):
    __tablename__ = 'StudentResearch'
    student_research_id = db.Column('StudentResearchID', db.BIGINT, nullable=False, autoincrement=True, primary_key=True)
    user_id = db.Column('UserID', db.BIGINT, db.ForeignKey(Users.user_id), nullable=False)
    research_slot_id = db.Column('ResearchSlotID', db.BIGINT, db.ForeignKey(ResearchSlot.research_id), nullable=False)
    is_completed = db.Column('IsCompleted', db.BOOLEAN, nullable=False)
    created_on = db.Column('CreatedOn', db.DATETIME)

    def __init__(self, uid, slot_id, completed):
        self.user_id = uid
        self.research_slot_id = slot_id
        self.is_completed = completed


# Login Handlers ---------------------------------------------------------------------


class User(UserMixin):
    role = ''
    pass


@login_manager.user_loader
def user_loader(email):
    if db.session.query(Users.user_email).filter_by(user_email=email).count() != 1:
        return

    user = User()
    user.id = email
    user_lookup = db.session.query(Users.user_role).filter_by(user_email=email).first()
    role_lookup = db.session.query(Role.role_name).filter_by(role_id=user_lookup[0]).first()
    user.role = role_lookup[0]
    return user


@login_manager.request_loader
def request_loader(req):
    email = req.form.get('email')
    if db.session.query(Users.user_email).filter_by(user_email=email).count() != 1:
        return

    user = User()
    user.id = email
    user_lookup = db.session.query(Users.user_role).filter_by(user_email=email).first()
    role_lookup = db.session.query(Role.role_name).filter_by(role_id=user_lookup[0]).first()
    user.role = role_lookup[0]

    return user


@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect(url_for('login'))


# Page Routes/Logic ------------------------------------------------------------------


@app.route('/')
@login_required
def index():
    roles = db.session.query(Role.role_name)
    token = generate_confirmation_token('test@test.com', app.secret_key, app.secret_key)
    return render_template('index.html', roles=roles, test_token=token)


@app.route('/login', methods=['GET', 'POST'])
def login():
    flashes = []
    if request.method == 'GET':
        return render_template('login.html', flashes=flashes)
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        salt = db.session.query(Users.user_salt).filter_by(user_email=email).first()
        if salt is None:
            flashes.append('Incorrect Login Information!')
            return render_template('login.html', flashes=flashes)
        current_password = sha256((password + salt[0]).encode('utf-8')).hexdigest()
        stored_password = db.session.query(Users.user_pw_hash).filter_by(user_email=email).first()
        if stored_password is None:
            flashes.append('Incorrect Login Information!')
            return render_template('login.html', flashes=flashes)
        elif current_password == stored_password[0]:
            user = User()
            user.id = email.lower()
            user_lookup = db.session.query(Users.user_role).filter_by(user_email=email).first()
            role_lookup = db.session.query(Role.role_name).filter_by(role_id=user_lookup[0]).first()
            user.role = role_lookup[0]
            login_user(user)
            return redirect(url_for('index'))
        else:
            flashes.append('Incorrect Login Information!')
            return render_template('login.html', flashes=flashes)
    return render_template('login.html', flashes=flashes)


@app.route('/confirm', methods=['GET', 'POST'])
def confirm():
    flashes = []
    if request.method == 'GET':
        return render_template('confirm.html')
    if request.method == 'POST':
        email = request.form.get('email')
        if email.endswith('@stu.jsu.edu'):
            if db.session.query(Users.user_email).filter_by(user_email=email).count() < 1:
                token = generate_confirmation_token(email, Constants.CONFIRM_SALT, app.secret_key)
                from_address = Constants.DEFAULT_EMAIL
                to_address = email
                subject = 'JSU Psychology Research Account Setup'
                body = 'Click the link below to setup your account:\n\n' \
                       'http://{}/signup/{}' \
                       '\n\nDo not reply to this email. It is not monitored and all replies will be deleted.'\
                    .format(Constants.SERVER_IP, token)
                email_text = 'From: {}\n' \
                             'To: {}\n' \
                             'Subject: {}\n\n' \
                             '{}'.format(from_address, to_address, subject, body)
                send_email(from_address, to_address, email_text)
                return redirect(url_for('login'))
            else:
                flashes.append('That email is already being used.')
                return render_template('confirm.html', flashes=flashes)
        else:
            flashes.append('You must use a JSU student email.')
            return render_template('confirm.html', flashes=flashes)

    return render_template('confirm.html', flashes=flashes)


@app.route('/signup/<token>', methods=['GET', 'POST'])
def signup(token):
    flashes = []
    if request.method == 'GET':
        email = confirm_token(token, Constants.CONFIRM_SALT, app.secret_key)
        if not email:
            return redirect(url_for('confirm'))
        else:
            if db.session.query(Users.user_email).filter_by(user_email=email).count() == 1:
                return redirect(url_for('login'))
            else:
                return render_template('signup.html', reg_email=email)
    if request.method == 'POST':
        email = confirm_token(token, Constants.CONFIRM_SALT, app.secret_key)
        if not email:
            return redirect(url_for('login'))
        else:
            if db.session.query(Users.user_email).filter_by(user_email=email).count() == 1:
                return redirect(url_for('login'))
            else:
                password = request.form.get('password')
                confirm_password = request.form.get('confirm-password')
                major_minor = request.form.get('major-minor')
                if password != confirm_password:
                    flashes.append('Your passwords did not match.')
                if major_minor is None:
                    flashes.append('You must pick Psychology Major, Psychology Minor, or Other Major.')
                if len(flashes) > 0:
                    return render_template('signup.html', flashes=flashes)
                else:
                    psych_major = False
                    psych_minor = False
                    if major_minor == 'major':
                        psych_major = True
                    elif major_minor == 'minor':
                        psych_minor = True
                    salt = sha256(email.encode('utf-8')).hexdigest()
                    password_hash = sha256((confirm_password + salt).encode('utf-8')).hexdigest()
                    user = Users(email, password_hash, salt, 1, psych_major, psych_minor)
                    db.session.add(user)
                    db.session.commit()
                    return redirect(url_for('login'))
    return render_template('signup.html', flashes=flashes)


@app.route('/reset/password', methods=['GET', 'POST'])
def send_reset():
    flashes = []
    if request.method == 'GET':
        return render_template('send_reset.html', flashes=flashes)
    if request.method == 'POST':
        email = request.form.get('email')
        if db.session.query(Users.user_email).filter_by(user_email=email).count() == 1:
            token = generate_timed_confirmation_token(email, app.secret_key)
            from_address = Constants.DEFAULT_EMAIL
            to_address = email
            subject = 'JSU Psychology Research Password Reset'
            body = 'Click the link below to reset your password:\n\n' \
                   'http://{}/reset/password/{}' \
                   '\n\nDo not reply to this email. It is not monitored and all replies will be deleted.' \
                .format(Constants.SERVER_IP, token)
            email_text = 'From: {}\n' \
                         'To: {}\n' \
                         'Subject: {}\n\n' \
                         '{}'.format(from_address, to_address, subject, body)
            send_email(from_address, to_address, email_text)
            return redirect(url_for('login'))
        else:
            flashes.append('That email is not registered.')
            return render_template('send_reset.html', flashes=flashes)
    return render_template('send_reset.html', flashes=flashes)


@app.route('/reset/password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    flashes = []
    if request.method == 'GET':
        email = confirm_timed_token(token, app.secret_key)
        print(email)
        if not email:
            return redirect(url_for('send_reset'))
        else:
            if db.session.query(Users.user_email).filter_by(user_email=email).count() < 1:
                return redirect(url_for('login'))
            else:
                return render_template('reset_password.html', flashes=flashes)
    if request.method == 'POST':
        email = confirm_token(token, Constants.RESET_SALT, app.secret_key)
        if not email:
            return redirect(url_for('reset_password'))
        else:
            if db.session.query(Users.user_email).filter_by(user_email=email).count() == 1:
                password = request.form.get('password')
                confirm_password = request.form.get('confirm-password')
                if password != confirm_password:
                    flashes.append('Your passwords did not match.')
                if len(flashes) > 0:
                    return render_template('signup.html', flashes=flashes)
                else:
                    salt = sha256(email.encode('utf-8')).hexdigest()
                    password_hash = sha256((confirm_password + salt).encode('utf-8')).hexdigest()
                    db.session.query(Users.user_email).filter_by(user_email=email).update({'user_pw_hash': password_hash})
                    db.session.commit()
                    return redirect(url_for('login'))
    return render_template('reset_password.html', flashes=flashes)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


# App Start --------------------------------------------------------------------------

if __name__ == '__main__':
    app.secret_key = os.urandom(32)
    app.run(port=80)
