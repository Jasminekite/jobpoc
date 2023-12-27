from models import Certificate, Education, Experience, Skill
from config import db
from utils import date_now, object_as_dict

def cert():
    user_id = row['user_id']
    cert_title = row['cert_title']
    cert_proof = row['cert_proof']
    status = row['status']
    added_on = row['added_on']
    updated_on = row['updated_on']
    user_cert = Certificate(user_id=user_id, cert_title=cert_title, cert_proof=cert_proof,
                            status=status, added_on=added_on, updated_on=updated_on)
    db.session.add(user_cert)
    db.session.commit()

def edu():
    user_id = row['user_id']
    course = row['course']
    institute_name = row['institute_name']
    university = row['university']
    year_of_pass = row['year_of_pass']
    percentage = row['percentage']
    status = row['status']
    modify_on = row['modify_on']
    modify_by = row['modify_by']
    new_edu = Education(user_id=user_id, course=course, institute_name=institute_name,
                        university=university, year_of_pass=year_of_pass,
                        percentage=percentage, status=status, modify_on=modify_on, modify_by=modify_by)
    db.session.add(new_edu)
    db.session.commit()

def exp():
    user_id = row['user_id']
    title = row['title']
    company_name = row['company_name']
    start_date = row['start_date']
    end_date = row['end_date']
    location = row['location']
    status = row['status']
    added_on = row['added_on']
    updated_on = row['updated_on']
    user_exp = Experience(user_id=user_id, title=title, company_name=company_name,
                          start_date=start_date, end_date=end_date,
                          location=location, status=status,
                          added_on=added_on, updated_on=updated_on)
    db.session.add(user_exp)
    db.session.commit()

def skill():
    user_id = row['user_id']
    skill = row['skill']
    experience = row['experience']
    status = row['status']
    added_on = row['added_on']
    updated_on = row['updated_on']
    skill_version = row['skill_version']
    new_skill = Skill(user_id=user_id, skill=skill, experience=experience, status=status,
                      added_on=added_on, updated_on=updated_on, skill_version=skill_version, )
    db.session.add(new_skill)
    db.session.commit()
