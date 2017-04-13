
from itsdangerous import URLSafeSerializer, URLSafeTimedSerializer
from smtplib import SMTP
import Constants


def generate_confirmation_token(email, salt, secret_key):
    serializer = URLSafeSerializer(secret_key)
    return serializer.dumps(email, salt)


def confirm_token(token, salt, secret_key):
    serializer = URLSafeSerializer(secret_key)
    try:
        email = serializer.loads(token, salt)
    except:
        return False
    return email


def generate_timed_confirmation_token(email, secret_key):
    serializer = URLSafeTimedSerializer(secret_key)
    return serializer.dumps(email)


def confirm_timed_token(token, secret_key):
    serializer = URLSafeTimedSerializer(secret_key)
    try:
        email = serializer.loads(token, max_age=600)
    except:
        return False
    return email


def send_email(from_address, to_address, email_text):
    server = SMTP('smtp.gmail.com')
    server.ehlo()
    server.starttls()
    server.login(Constants.EMAIL_USERNAME, Constants.EMAIL_PASSWORD)
    server.sendmail(from_address, to_address, email_text)
    server.quit()


def truncate_datetime_year(datetime):
    temp = datetime.split('T')
    date = temp[0]
    time = temp[1]
    year = date.split('-')[0]
    month = date.split('-')[1]
    day = date.split('-')[2]
    if len(year) > 4:
        return '{}-{}-{} {}'.format(year[:4], month, day, time)
    else:
        return datetime.replace('T', ' ')
