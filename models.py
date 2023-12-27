from datetime import datetime
from config import db


class UserLogin(db.Model):
    __tablename__ = 'user_login'
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(225))
    user_type = db.Column(db.String(50))
    email_id = db.Column(db.String(225), unique=True)
    mobile_no = db.Column(db.String(225))
    password = db.Column(db.String(225))
    status = db.Column(db.String(1))

    def __init__(self, user_name, user_type, email_id, mobile_no, password, status):
        self.user_name = user_name
        self.user_type = user_type
        self.email_id = email_id
        self.mobile_no = mobile_no
        self.password = password
        self.status = status


class UserDetails(db.Model):
    __tablename__ = 'user_details'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(255))
    first_name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))
    email_id = db.Column(db.String(255), unique=True)
    gender = db.Column(db.String(255))
    dob = db.Column(db.Date())
    martial_status = db.Column(db.String(255))
    pan_number = db.Column(db.String(255))
    aadhar_number = db.Column(db.String(255))
    passport = db.Column(db.String(255))
    passport_expire = db.Column(db.DateTime)
    user_type = db.Column(db.String(255))
    linked_in = db.Column(db.String(255))
    facebook = db.Column(db.String(255))
    twitter = db.Column(db.String(255))
    work_status = db.Column(db.String(255))
    resume = db.Column(db.String(255))
    photo = db.Column(db.String(255))
    alternate_mobile = db.Column(db.String(255))
    differently_abled = db.Column(db.String(255))
    abled_details = db.Column(db.String(255))
    status = db.Column(db.String(1))
    added_on = db.Column(db.DateTime(timezone=True), nullable=True)
    updated_on = db.Column(db.DateTime(timezone=True), nullable=True)

    def __init__(self, user_id,first_name, last_name, email_id, gender, dob, martial_status, pan_number, status,
                 aadhar_number, passport, passport_expire, user_type, linked_in, facebook, twitter, work_status,
                 resume, photo, alternate_mobile, differently_abled, abled_details, added_on, updated_on):
        self.user_id = user_id
        self.first_name = first_name
        self.last_name = last_name
        self.email_id = email_id
        self.gender = gender
        self.dob = dob
        self.status = status
        self.martial_status = martial_status
        self.pan_number = pan_number
        self.aadhar_number = aadhar_number
        self.passport = passport
        self.passport_expire = passport_expire
        self.user_type = user_type
        self.linked_in = linked_in
        self.facebook = facebook
        self.twitter = twitter
        self.work_status = work_status
        self.resume = resume
        self.photo = photo
        self.alternate_mobile = alternate_mobile
        self.differently_abled = differently_abled
        self.abled_details = abled_details
        self.added_on = added_on
        self.updated_on = updated_on


class Address(db.Model):
    __tablename__ = 'address'
    id = db.Column(db.Integer, primary_key=True)
    user_add_id = db.Column(db.Integer())
    address1 = db.Column(db.String(255))
    address2 = db.Column(db.String(255))
    city = db.Column(db.String(255))
    pincode = db.Column(db.String(225))
    landmark = db.Column(db.String(255))
    address_type = db.Column(db.String(255))
    status = db.Column(db.Integer)
    added_on = db.Column(db.DateTime(timezone=True), nullable=True)
    updated_on = db.Column(db.DateTime(timezone=True), nullable=True)

    def __init__(self, user_add_id, address1, address2, city, pincode, landmark, address_type, status, added_on,
                 updated_on):
        self.user_add_id = user_add_id
        self.address1 = address1
        self.address2 = address2
        self.city = city
        self.pincode = pincode
        self.landmark = landmark
        self.address_type = address_type
        self.status = status
        self.added_on = added_on
        self.updated_on = updated_on


class Skill(db.Model):
    __tablename__ = 'skills'
    skill_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer())
    skill = db.Column(db.String(255))
    experience = db.Column(db.String(255))
    status = db.Column(db.String(255))
    added_on = db.Column(db.DateTime(timezone=True), nullable=True)
    updated_on = db.Column(db.DateTime(timezone=True), nullable=True)
    skill_version = db.Column(db.String(255))

    def __init__(self, user_id, skill, experience, status, added_on, updated_on, skill_version):
        self.user_id = user_id
        self.skill = skill
        self.experience = experience
        self.status = status
        self.added_on = added_on
        self.updated_on = updated_on
        self.skill_version = skill_version


class Experience(db.Model):
    __tablename__ = 'experience'
    exp_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer())
    title = db.Column(db.String(255))
    company_name = db.Column(db.String(255))
    start_date = db.Column(db.DateTime(timezone=True), nullable=True)
    end_date = db.Column(db.DateTime(timezone=True), nullable=True)
    location = db.Column(db.String(225))
    status = db.Column(db.String(255))
    added_on = db.Column(db.DateTime(timezone=True), nullable=True)
    updated_on = db.Column(db.DateTime(timezone=True), nullable=True)

    def __init__(self, user_id, title, company_name, start_date, end_date, location, status, added_on, updated_on):
        self.user_id = user_id
        self.title = title
        self.company_name = company_name
        self.start_date = start_date
        self.end_date = end_date
        self.location = location
        self.status = status
        self.added_on = added_on
        self.updated_on = updated_on


class Education(db.Model):
    __tablename__ = 'education_details'
    edu_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer())
    course = db.Column(db.String(255))
    institute_name = db.Column(db.String(255))
    university = db.Column(db.String(255))
    year_of_pass = db.Column(db.DateTime(timezone=True), nullable=True)
    percentage = db.Column(db.String(20))
    status = db.Column(db.String(255))
    modify_on = db.Column(db.DateTime(timezone=True), nullable=True)
    modify_by = db.Column(db.String(20))

    def __init__(self, user_id, course, institute_name, university, year_of_pass, percentage, status, modify_on,
                 modify_by):
        self.user_id = user_id
        self.course = course
        self.institute_name = institute_name
        self.university = university
        self.year_of_pass = year_of_pass
        self.percentage = percentage
        self.status = status
        self.modify_on = modify_on
        self.modify_by = modify_by


class LoginStatus(db.Model):
    __tablename__ = 'login_status'
    id = db.Column(db.Integer, primary_key=True)
    login_status_id = db.Column(db.Integer())
    login_activate = db.Column(db.String(255))
    login_key = db.Column(db.String(255))
    login_device = db.Column(db.String(255))
    logout_date = db.Column(db.String(225))

    def __init__(self, login_status_id, login_activate, login_key, login_device, logout_date):
        self.login_status_id = login_status_id
        self.login_activate = login_activate
        self.login_key = login_key
        self.login_device = login_device
        self.logout_date = logout_date


class Certificate(db.Model):
    __tablename__ = 'certifications'
    cert_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer())
    cert_title = db.Column(db.String(255))
    cert_proof = db.Column(db.String(255))
    status = db.Column(db.String(255))
    added_on = db.Column(db.DateTime(timezone=True), nullable=True)
    updated_on = db.Column(db.DateTime(timezone=True), nullable=True)

    def __init__(self, user_id, cert_title, cert_proof, status, added_on, updated_on):
        self.user_id = user_id
        self.cert_title = cert_title
        self.cert_proof = cert_proof
        self.status = status
        self.added_on = added_on
        self.updated_on = updated_on


class Company(db.Model):
    __tablename__ = 'register_company'
    id = db.Column(db.Integer, primary_key=True)
    user_company_id = db.Column(db.Integer())
    company_name = db.Column(db.String(255))
    gst_no = db.Column(db.String(255))
    company_email = db.Column(db.String(255))
    details = db.Column(db.String(255))
    mobile_no = db.Column(db.String(255))
    address = db.Column(db.String(255))
    pin_code = db.Column(db.String(255))
    website_url = db.Column(db.String(255))
    linked_in = db.Column(db.String(255))
    twitter = db.Column(db.String(255))
    facebook = db.Column(db.String(255))
    instagram = db.Column(db.String(255))
    whatsapp = db.Column(db.String(255))
    contact_number = db.Column(db.String(255))
    status = db.Column(db.String(255))
    added_on = db.Column(db.DateTime(timezone=True), nullable=True)
    updated_on = db.Column(db.DateTime(timezone=True), nullable=True)

    def __init__(self, user_company_id, company_name, gst_no, company_email, details, mobile_no, address, pin_code,
                 website_url, linked_in, twitter, facebook, instagram, whatsapp, contact_number, status, added_on,
                 updated_on):
        self.user_company_id = user_company_id
        self.company_name = company_name
        self.gst_no = gst_no
        self.company_email = company_email
        self.details = details
        self.mobile_no = mobile_no
        self.address = address
        self.pin_code = pin_code
        self.website_url = website_url
        self.linked_in = linked_in
        self.twitter = twitter
        self.facebook = facebook
        self.instagram = instagram
        self.whatsapp = whatsapp
        self.contact_number = contact_number
        self.status = status
        self.added_on = added_on
        self.updated_on = updated_on


class JobPost(db.Model):
    __tablename__ = 'job_post'
    job_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer())
    company_id = db.Column(db.Integer())
    company_name_hidden = db.Column(db.String(255))
    created_on = db.Column(db.DateTime(timezone=True), nullable=True)
    job_location = db.Column(db.String(255))
    is_active = db.Column(db.String(255))
    apply_on = db.Column(db.DateTime(timezone=True), nullable=True)

    def __init__(self, user_id, company_id, company_name, created_on, job_location, is_activate, apply_on):
        self.user_id = user_id
        self.company_id = company_id
        self.company_name = company_name
        self.created_on = created_on
        self.job_location = job_location
        self.is_activate = is_activate
        self.apply_on = apply_on
