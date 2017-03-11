from flask import Flask, render_template, redirect, url_for, request
from flask_login import login_required, LoginManager, UserMixin, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from Utilities import generate_confirmation_token, confirm_token, send_email, generate_timed_confirmation_token, \
    confirm_timed_token
from hashlib import sha256
from DatabaseModels import Role, Users, Research, ResearchSlot, StudentResearch
import Constants
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://{}:{}@{}:{}/{}' \
    .format(Constants.DB_USERNAME, Constants.DB_PASSWORD, Constants.DB_IP, Constants.DB_PORT, Constants.DB_NAME)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


# Login Handlers ---------------------------------------------------------------------


class User(UserMixin):
    role = ''
    pass


@login_manager.user_loader
def user_loader(email):
    if db.session.query(Users.user_email).filter(Users.user_email == email).count() != 1:
        return

    user = User()
    user.id = email
    role_lookup = db.session.query(Role.role_name) \
        .filter(Users.user_email == email) \
        .filter(Role.role_id == Users.user_role).scalar()
    user.role = role_lookup

    return user


@login_manager.request_loader
def request_loader(req):
    email = req.form.get('email')
    if db.session.query(Users.user_email).filter(Users.user_email == email).count() != 1:
        return

    user = User()
    user.id = email
    role_lookup = db.session.query(Role.role_name) \
        .filter(Users.user_email == email) \
        .filter(Role.role_id == Users.user_role).scalar()
    user.role = role_lookup

    return user


@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect(url_for('login'))


# Page Routes/Logic ------------------------------------------------------------------

@app.route('/')
@login_required
def index():
    return redirect(url_for('user_profile'))


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def user_profile():
    flashes = []
    if request.method == 'GET':
        if current_user.role == 'student':
            initial_enrolled_listings = db.session.query(Research.research_name, Research.research_facilitator,
                                                Research.research_description, Research.research_credits,
                                                ResearchSlot.start_time, ResearchSlot.end_time,
                                                StudentResearch.is_completed) \
                .filter(Users.user_id == StudentResearch.user_id) \
                .filter(Users.user_email == current_user.id) \
                .filter(StudentResearch.research_slot_id == ResearchSlot.research_slot_id) \
                .filter(ResearchSlot.research_id == Research.research_id) \
                .filter(StudentResearch.is_completed == False) \
                .subquery()
            enrolled_listings = db.session.query(Users.user_email, initial_enrolled_listings) \
                .join(initial_enrolled_listings, Users.user_id == initial_enrolled_listings.c.ResearchFacilitator) \
                .all()
            initial_completed_listings = db.session.query(Research.research_name, Research.research_facilitator,
                                                Research.research_description, Research.research_credits,
                                                ResearchSlot.start_time, ResearchSlot.end_time,
                                                StudentResearch.is_completed) \
                .filter(Users.user_id == StudentResearch.user_id) \
                .filter(Users.user_email == current_user.id) \
                .filter(StudentResearch.research_slot_id == ResearchSlot.research_slot_id) \
                .filter(ResearchSlot.research_id == Research.research_id) \
                .filter(StudentResearch.is_completed == True) \
                .subquery()
            completed_listings = db.session.query(Users.user_email, initial_completed_listings) \
                .join(initial_completed_listings, Users.user_id == initial_completed_listings.c.ResearchFacilitator) \
                .all()
            student_credits = db.session.query(Users.user_id, Research.research_credits) \
                .filter(Users.user_id == StudentResearch.user_id) \
                .filter(StudentResearch.research_slot_id == ResearchSlot.research_slot_id) \
                .filter(ResearchSlot.research_id == Research.research_id) \
                .filter(StudentResearch.is_completed) \
                .group_by(StudentResearch.student_research_id) \
                .subquery()
            credits_completed = db.session.query(db.func.sum(student_credits.c.ResearchCredits)) \
                .filter(Users.user_id == student_credits.c.UserID) \
                .filter(Users.user_role == 1) \
                .filter(Users.user_email == current_user.id)\
                .group_by(Users.user_id) \
                .scalar()
            return render_template('user_profile.html', credits_completed=credits_completed, listings=enrolled_listings,
                                   completed_listings=completed_listings, flashes=flashes)
        elif current_user.role == 'professor':
            counts = db.session.query(StudentResearch.research_slot_id,
                                      db.func.count(StudentResearch.student_research_id).label('Openings')) \
                .group_by(StudentResearch.research_slot_id).subquery()
            final_listings = db.session.query(Research.research_name, Research.research_description,
                                              Research.research_credits, ResearchSlot.research_slot_openings - counts.c.Openings,
                                              ResearchSlot.start_time, ResearchSlot.end_time)\
                .filter(Research.research_facilitator == Users.user_id) \
                .filter(Research.research_id == ResearchSlot.research_id) \
                .filter(ResearchSlot.research_slot_id == counts.c.ResearchSlotID) \
                .filter(Users.user_email == current_user.id) \
                .all()
            return render_template('user_profile.html', listings=final_listings, flashes=flashes)
        elif current_user.role == 'admin':
            counts = db.session.query(StudentResearch.research_slot_id,
                                      db.func.count(StudentResearch.student_research_id).label('Openings')) \
                .group_by(StudentResearch.research_slot_id).subquery()
            final_listings = db.session.query(Research.research_name, Research.research_description,
                                              Research.research_credits,
                                              ResearchSlot.research_slot_openings - counts.c.Openings,
                                              ResearchSlot.start_time, ResearchSlot.end_time) \
                .filter(Research.research_facilitator == Users.user_id) \
                .filter(Research.research_id == ResearchSlot.research_id) \
                .filter(ResearchSlot.research_slot_id == counts.c.ResearchSlotID) \
                .filter(Users.user_email == current_user.id) \
                .all()
            other_listings = db.session.query(Research.research_name, Research.research_description,
                                              Research.research_credits,
                                              ResearchSlot.research_slot_openings - counts.c.Openings,
                                              ResearchSlot.start_time, ResearchSlot.end_time) \
                .filter(Research.research_facilitator == Users.user_id) \
                .filter(Research.research_id == ResearchSlot.research_id) \
                .filter(ResearchSlot.research_slot_id == counts.c.ResearchSlotID) \
                .filter(Users.user_email != current_user.id) \
                .all()
            return render_template('user_profile.html', listings=final_listings, other_listings=other_listings, flashes=flashes)
    if request.method == 'POST':
        return render_template('user_profile.html', flashes=flashes)
    return render_template('user_profile.html', flashes=flashes)


@app.route('/listings', methods=['GET', 'POST'])
@login_required
def listings():
    flashes = []
    if request.method == 'GET':
        counts = db.session.query(StudentResearch.research_slot_id,
                                  db.func.count(StudentResearch.student_research_id).label('Openings')) \
            .group_by(StudentResearch.research_slot_id).subquery()
        final_listings = db.session.query(Research.research_name, Research.research_description,
                                          Research.research_credits, Users.user_email,
                                          ResearchSlot.start_time, ResearchSlot.end_time,
                                          ResearchSlot.research_slot_openings - counts.c.Openings) \
            .filter(Research.research_facilitator == Users.user_id) \
            .filter(Research.research_id == ResearchSlot.research_id) \
            .filter(ResearchSlot.research_slot_id == counts.c.ResearchSlotID) \
            .all()
        return render_template('listings.html', flashes=flashes, listings=final_listings)
    if request.method == 'POST':
        return render_template('listings.html', flashes=flashes)

    return render_template('listings.html', flashes=flashes)


@app.route('/students', methods=['GET', 'POST'])
@login_required
def all_students():
    flashes = []
    if request.method == 'GET':
        if current_user.role == 'student':
            return redirect(url_for('listings'))
        else:
            student_credits = db.session.query(Users.user_id, Research.research_credits) \
                .filter(Users.user_id == StudentResearch.user_id) \
                .filter(StudentResearch.research_slot_id == ResearchSlot.research_slot_id) \
                .filter(ResearchSlot.research_id == Research.research_id) \
                .filter(StudentResearch.is_completed == True) \
                .group_by(StudentResearch.student_research_id) \
                .subquery()
            students = db.session.query(Users.user_email, db.func.sum(student_credits.c.ResearchCredits)) \
                .filter(Users.user_id == student_credits.c.UserID) \
                .filter(Users.user_role == 1) \
                .group_by(Users.user_id) \
                .all()
            return render_template('all_students.html', listings=students, flashes=flashes)
    if request.method == 'POST':
        return render_template('all_students.html', flashes=flashes)

    return render_template('all_students.html', flashes=flashes)


@app.route('/login', methods=['GET', 'POST'])
def login():
    flashes = []
    if request.method == 'GET':
        return render_template('login.html', flashes=flashes)
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        salt = db.session.query(Users.user_salt).filter(Users.user_email == email).scalar()
        if salt is None:
            flashes.append('Incorrect Login Information!')
            return render_template('login.html', flashes=flashes)
        current_password = sha256((password + salt).encode('utf-8')).hexdigest()
        stored_password = db.session.query(Users.user_pw_hash).filter(Users.user_email == email).scalar()
        if stored_password is None:
            flashes.append('Incorrect Login Information!')
            return render_template('login.html', flashes=flashes)
        elif current_password == stored_password:
            user = User()
            user.id = email.lower()
            user_lookup = db.session.query(Users.user_role).filter(Users.user_email == email).scalar()
            role_lookup = db.session.query(Role.role_name).filter(Role.role_id == user_lookup).scalar()
            user.role = role_lookup
            login_user(user)
            return redirect(url_for('user_profile'))
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
            if db.session.query(Users.user_email).filter(Users.user_email == email).count() < 1:
                token = generate_confirmation_token(email, Constants.STUDENT_CONFIRM_SALT, app.secret_key)
                from_address = Constants.DEFAULT_EMAIL
                to_address = email
                subject = 'JSU Psychology Research Account Setup'
                body = 'Click the link below to setup your account:\n\n' \
                       'http://{}/signup/student/{}' \
                       '\n\nDo not reply to this email. It is not monitored and all replies will be deleted.' \
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


@app.route('/invite', methods=['GET', 'POST'])
@login_required
def invite_professor():
    flashes = []
    if request.method == 'GET':
        return render_template('invite.html')
    if request.method == 'POST':
        if current_user.role == 'admin':
            email = request.form.get('email')
            if db.session.query(Users.user_email).filter(Users.user_email == email).count() < 1:
                token = generate_confirmation_token(email, Constants.PROFESSOR_CONFIRM_SALT, app.secret_key)
                from_address = Constants.DEFAULT_EMAIL
                to_address = email
                subject = 'JSU Psychology Research Account Setup'
                body = 'You have been invited by a {} Admin.\n\n' \
                       'Click the link below to setup your account:\n\n' \
                       'http://{}/signup/professor/{}' \
                       '\n\nDo not reply to this email. It is not monitored and all replies will be deleted.' \
                    .format(Constants.APP_NAME, Constants.SERVER_IP, token)
                email_text = 'From: {}\n' \
                             'To: {}\n' \
                             'Subject: {}\n\n' \
                             '{}'.format(from_address, to_address, subject, body)
                send_email(from_address, to_address, email_text)
                return redirect(url_for('user_profile'))
            else:
                flashes.append('That email is already being used.')
                return render_template('invite.html', flashes=flashes)
        else:
            return redirect(url_for('user_profile'))

    return render_template('invite.html', flashes=flashes)


@app.route('/signup/student/<token>', methods=['GET', 'POST'])
def signup(token):
    flashes = []
    if request.method == 'GET':
        email = confirm_token(token, Constants.STUDENT_CONFIRM_SALT, app.secret_key)
        if not email:
            return redirect(url_for('confirm'))
        else:
            if db.session.query(Users.user_email).filter(Users.user_email == email).count() == 1:
                return redirect(url_for('login'))
            else:
                return render_template('signup.html', reg_email=email)
    if request.method == 'POST':
        email = confirm_token(token, Constants.STUDENT_CONFIRM_SALT, app.secret_key)
        if not email:
            return redirect(url_for('login'))
        else:
            if db.session.query(Users.user_email).filter(Users.user_email == email).count() == 1:
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


@app.route('/signup/professor/<token>', methods=['GET', 'POST'])
def professor_signup(token):
    flashes = []
    if request.method == 'GET':
        email = confirm_token(token, Constants.PROFESSOR_CONFIRM_SALT, app.secret_key)
        if not email:
            return redirect(url_for('login'))
        else:
            if db.session.query(Users.user_email).filter(Users.user_email == email).count() == 1:
                return redirect(url_for('login'))
            else:
                return render_template('professor_signup.html', reg_email=email)
    if request.method == 'POST':
        email = confirm_token(token, Constants.PROFESSOR_CONFIRM_SALT, app.secret_key)
        if not email:
            return redirect(url_for('login'))
        else:
            if db.session.query(Users.user_email).filter(Users.user_email == email).count() == 1:
                return redirect(url_for('login'))
            else:
                password = request.form.get('password')
                confirm_password = request.form.get('confirm-password')
                if password != confirm_password:
                    flashes.append('Your passwords did not match.')
                if len(flashes) > 0:
                    return render_template('professor_signup.html', flashes=flashes)
                else:
                    salt = sha256(email.encode('utf-8')).hexdigest()
                    password_hash = sha256((confirm_password + salt).encode('utf-8')).hexdigest()
                    user = Users(email, password_hash, salt, 2, False, False)
                    db.session.add(user)
                    db.session.commit()
                    return redirect(url_for('login'))
    return render_template('professor_signup.html', flashes=flashes)


@app.route('/reset/password', methods=['GET', 'POST'])
def send_reset():
    flashes = []
    if request.method == 'GET':
        return render_template('send_reset.html', flashes=flashes)
    if request.method == 'POST':
        email = request.form.get('email')
        if db.session.query(Users.user_email).filter(Users.user_email == email).count() == 1:
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
        if not email:
            return redirect(url_for('send_reset'))
        else:
            if db.session.query(Users.user_email).filter(Users.user_email == email).count() < 1:
                return redirect(url_for('login'))
            else:
                return render_template('reset_password.html', flashes=flashes)
    if request.method == 'POST':
        email = confirm_timed_token(token, app.secret_key)
        if not email:
            return redirect(url_for('send_reset'))
        else:
            if db.session.query(Users.user_email).filter(Users.user_email == email).count() == 1:
                password = request.form.get('password')
                confirm_password = request.form.get('confirm-password')
                if password != confirm_password:
                    flashes.append('Your passwords did not match.')
                if len(flashes) > 0:
                    return render_template('signup.html', flashes=flashes)
                else:
                    salt = sha256(email.encode('utf-8')).hexdigest()
                    password_hash = sha256((confirm_password + salt).encode('utf-8')).hexdigest()
                    db.session.query(Users.user_email).filter(Users.user_email == email).update(
                        {'user_pw_hash': password_hash})
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
    app.run(port=80, host='0.0.0.0')
