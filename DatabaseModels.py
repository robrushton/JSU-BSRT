
from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()


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
    created_on = db.Column('CreatedOn', db.DATETIME, server_default=db.func.current_timestamp(), nullable=False)

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
    is_visible = db.Column('IsVisible', db.BOOLEAN, default=True, nullable=False)
    is_deleted = db.Column('IsDeleted', db.BOOLEAN, default=False, nullable=False)
    created_on = db.Column('CreatedOn', db.DATETIME, server_default=db.func.current_timestamp(), nullable=False)

    def __init__(self, name, facilitator, description, research_credits):
        self.research_name = name
        self.research_facilitator = facilitator
        self.research_description = description
        self.research_credits = research_credits


class ResearchSlot(db.Model):
    __tablename__ = 'ResearchSlot'
    research_slot_id = db.Column('ResearchSlotID', db.BIGINT, nullable=False, autoincrement=True, primary_key=True)
    research_id = db.Column('ResearchID', db.BIGINT, db.ForeignKey(Research.research_id), nullable=False)
    research_slot_openings = db.Column('ResearchSlotOpenings', db.INTEGER, nullable=False)
    start_time = db.Column('StartTime', db.DATETIME, nullable=False)
    end_time = db.Column('EndTime', db.DATETIME, nullable=False)
    is_deleted = is_deleted = db.Column('IsDeleted', db.BOOLEAN, default=False, nullable=False)
    created_on = db.Column('CreatedOn', db.DATETIME, server_default=db.func.current_timestamp(), nullable=False)

    def __init__(self, rid, openings, start, end):
        self.research_id = rid
        self.research_slot_openings = openings
        self.start_time = start
        self.end_time = end


class StudentResearch(db.Model):
    __tablename__ = 'StudentResearch'
    student_research_id = db.Column('StudentResearchID', db.BIGINT, nullable=False, autoincrement=True, primary_key=True)
    user_id = db.Column('UserID', db.BIGINT, db.ForeignKey(Users.user_id), nullable=False)
    research_slot_id = db.Column('ResearchSlotID', db.BIGINT, db.ForeignKey(ResearchSlot.research_id), nullable=False)
    is_completed = db.Column('IsCompleted', db.BOOLEAN, default=False, nullable=False)
    is_dropped = db.Column('IsDropped', db.BOOLEAN, default=False, nullable=False)
    completed_on = db.Column('CompletedOn', db.DATETIME, default='1900-01-01 00:00:00')
    created_on = db.Column('CreatedOn', db.DATETIME, server_default=db.func.current_timestamp(), nullable=False)

    def __init__(self, uid, slot_id):
        self.user_id = uid
        self.research_slot_id = slot_id
