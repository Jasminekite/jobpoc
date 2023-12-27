from flask import Flask, jsonify, request, make_response
import config
from models import UserLogin, UserDetails, Address, Certificate, Education, Experience, Skill, LoginStatus, \
    Company, JobPost
from config import db
from schema import userLogin, usersLogin, userRegister, usersRegister, usersAddress, userAddress, UserCertifications, \
    UsersCertifications, UserEdu, UsersEdu, UserExperience, UsersExperience, UserSkill, \
    UsersSkill, UserLoginStatus, UsersLoginStatus, userRegisterCompany, usersRegisterCompany, jobPostCompany, \
    jobsPostCompany
from utils import validate, date_now, response, object_as_dict, token_required
from validation import users_add, users_profile, address_s, certificate_s, education_s, experience_s
import uuid  # for public `id`
import jwt
import json

app = config.connex_app


# route for logging user in
@app.route('/login', methods=['POST'])
def login():
    # creates dictionary of form data
    auth = json.loads(request.data)
    print(auth)
    # auth = request.form
    if not auth or not auth.get('email_id') or not auth.get('password'):
        # returns 401 if any email or / and password is missing
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm ="Login required !!"'}
        )

    user = UserLogin.query \
        .filter_by(email_id=auth.get('email_id')) \
        .first()

    if not user:
        # returns 401 if user does not exist
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm ="User does not exist !!"'}
        )
    if user.password == auth.get('password'):
        # generates the JWT Token
        token = jwt.encode(payload={"user_name": user.user_name},
                           key='secret',
                           algorithm="HS256")

        return make_response(jsonify({'token': token}), 201)
    # returns 403 if password is wrong
    return make_response(
        'Could not verify',
        403,
        {'WWW-Authenticate': 'Basic realm ="Wrong Password !!"'}
    )


# signup route
@app.route('/signup', methods=['POST'])
def signup():
    # creates a dictionary of the form data
    data = json.loads(request.data)
    print(data)
    # gets name, email and password
    email_id = data.get('email_id')
    password = data.get('password')
    user_type = data.get('user_type')
    status = data.get('status')
    mobile_no = data.get('mobile_no')
    # checking for existing user
    user = UserLogin.query \
        .filter_by(email_id=email_id) \
        .first()
    if not user:
        # database ORM object
        user = UserLogin(
            user_name=str(uuid.uuid4()),
            email_id=email_id,
            password=password,
            user_type=user_type,
            status=status,
            mobile_no=mobile_no
        )
        # insert user
        db.session.add(user)
        db.session.commit()
        return make_response('Successfully registered.', 201)
    else:
        # returns 202 if user already exists
        return make_response('User already exists. Please Login.', 202)


# New user Entry
@app.route('/add_login', methods=['POST'])
def add_user():
    data = users_add(request.data)
    if data['status']:
        try:

            valid_data = data['message']
            if UserLogin.query.filter(UserLogin.user_name == valid_data['user_name']).first():
                return jsonify('Username is already in use')
            login = UserLogin(user_name=valid_data['user_name'], user_type=valid_data['user_type'],
                              email_id=valid_data['email_id'], mobile_no=valid_data['mobile_no'],
                              password=valid_data['password'], status=valid_data['status'])
            db.session.add(login)
            db.session.commit()
            return userLogin.jsonify(login)
        except Exception as e:
            return {"error_msg": str(e)}
    else:
        return jsonify({"test": data['message']})


@app.route('/add_login/<uid>', methods=['GET'])
@token_required
def login_single_data(current_user, uid):
    try:
        user = UserLogin.query.get(uid)
        if not user:
            return {"error_msg": "user data is not found"}
        data = {"user": object_as_dict(user)}
        return response(data, 200, "user_login Details", False)
    except Exception as e:
        return {"error_msg": str(e)}


@app.route('/add_login', methods=['GET'])
@token_required
def login_all_data(current_user):
    try:
        user = UserLogin.query.all()
        list = []
        for i in user:
            list.append(object_as_dict(i))
        data = {"users_list": list}
        return response(data, 200, "User Login Details", False)

    except Exception as e:
        return {"error_msg": str(e)}


@app.route('/add_login/<uid>', methods=['PUT'])
def update_user_entry(uid):
    user = UserLogin.query.get(uid)
    if not user:
        return {"error_msg": "user data is not found"}
    data = users_add(request.data)
    if data['status']:
        try:
            valid_data = data['message']
            user_name = valid_data['user_name']
            user_type = valid_data['user_type']
            email_id = valid_data['email_id']
            mobile_no = valid_data['mobile_no']
            password = valid_data['password']
            status = valid_data['status']
            user.user_name = user_name
            user.user_type = user_type
            user.email_id = email_id
            user.mobile_no = mobile_no
            user.password = password
            user.status = status
            db.session.commit()
            return userLogin.jsonify(user)
        except Exception as e:
            return {"error_msg": str(e)}
    else:
        return jsonify({"message": data['message']})


# userRegister-
@app.route('/user_register', methods=['POST'])
def user_register():
    data = users_profile(request.data)
    if data['status']:
        try:
            valid_data = data['message']
            new_reg = UserDetails(user_id=valid_data['user_id'], first_name=valid_data['first_name'],
                                  last_name=valid_data['last_name'],
                                  email_id=valid_data['email_id'],
                                  gender=valid_data['gender'], dob=valid_data['dob'],
                                  martial_status=valid_data['martial_status'], pan_number=valid_data['pan_number'],
                                  aadhar_number=valid_data['aadhar_number'], passport=valid_data['passport'],
                                  passport_expire=valid_data['passport_expire'],
                                  user_type=valid_data['user_type'], linked_in=valid_data['linked_in'],
                                  facebook=valid_data['facebook'], twitter=valid_data['twitter'],
                                  work_status=valid_data['work_status'], resume=valid_data['resume'],
                                  photo=valid_data['photo'],
                                  alternate_mobile=valid_data['alternate_mobile'],
                                  differently_abled=valid_data['differently_abled'],
                                  abled_details=valid_data['abled_details'], status=valid_data['status'],
                                  added_on=valid_data.get('added_on', date_now()),
                                  updated_on=valid_data.get('updated_on', date_now())
                                  )
            db.session.add(new_reg)
            db.session.commit()

            return userRegister.jsonify(new_reg)
        except Exception as e:
            return {"error_msg": str(e)}
    else:
        return jsonify({"test": data['message']})


@app.route('/update_user_register/<uid>', methods=['PUT'])
def update_user_register(uid):
    user = UserDetails.query.get(uid)
    if not user:
        return {"error_msg": "user_details data is not found"}
    data = users_profile(request.data)
    if data['status']:
        try:
            valid_data = data['message']
            user_id = valid_data['user_id']
            first_name = valid_data['first_name']
            last_name = valid_data['last_name']
            email_id = valid_data['email_id']
            gender = valid_data['gender']
            dob = valid_data['dob']
            martial_status = valid_data['martial_status']
            pan_number = valid_data['pan_number']
            aadhar_number = valid_data['aadhar_number']
            passport = valid_data['passport']
            passport_expire = valid_data['passport_expire']
            user_type = valid_data['user_type']
            linked_in = valid_data['linked_in']
            facebook = valid_data['facebook']
            twitter = valid_data['twitter']
            work_status = valid_data['work_status']
            resume = valid_data['resume']
            photo = valid_data['photo']
            alternate_mobile = valid_data['alternate_mobile']
            differently_abled = valid_data['differently_abled']
            abled_details = valid_data['abled_details']
            status = valid_data['status']
            added_on = valid_data.get('added_on', date_now())
            updated_on = valid_data.get('updated_on', date_now())
            user.user_id = user_id
            user.first_name = first_name
            user.last_name = last_name
            user.email_id = email_id
            user.gender = gender
            user.dob = dob
            user.martial_status = martial_status
            user.pan_number = pan_number
            user.aadhar_number = aadhar_number
            user.passport = passport
            user.passport_expire = passport_expire
            user.user_type = user_type
            user.linked_in = linked_in
            user.facebook = facebook
            user.twitter = twitter
            user.work_status = work_status
            user.resume = resume
            user.photo = photo
            user.alternate_mobile = alternate_mobile
            user.differently_abled = differently_abled
            user.abled_details = abled_details
            user.status = status
            user.added_on = added_on
            user.updated_on = updated_on
            db.session.commit()
            return userRegister.jsonify(user)
        except Exception as e:
            return {"error_msg": str(e)}
    else:
        return jsonify({"message": data['message']})


@app.route('/user_details/<uid>', methods=['GET'])
@token_required
def register_single_data(current_user, uid):
    try:
        user = UserDetails.query.get(uid)
        if not user:
            return {"error_msg": "user_details data is not found"}
        data = {"user": object_as_dict(user)}
        return response(data, 200, "user_Details", False)
    except Exception as e:
        return {"error_msg": str(e)}


@app.route('/users_all_details', methods=['GET'])
def register_all_data():
    try:
        user = UserDetails.query.all()
        list = []
        for a in user:
            list.append(object_as_dict(a))
        data = {"Register_list": list}
        return response(data, 200, "User RegisterDetails", False)
    except Exception as e:
        return {"error_msg": str(e)}


@app.route('/user_delete/<uid>', methods=['DELETE'])
def delete_user(uid):
    user = UserDetails.query.get(uid)
    db.session.delete(user)
    db.session.commit()
    return userRegister.jsonify(user)


# Address
@app.route('/address', methods=['POST'])
def address():
    data = address_s(request.data)
    if data['status']:
        try:
            valid_data = data['message']
            new_add = Address(user_add_id=valid_data['user_add_id'], address1=valid_data['address1'],
                              address2=valid_data['address2'], city=valid_data['city'],
                              pincode=valid_data['pincode'],
                              landmark=valid_data['landmark'], address_type=valid_data['address_type'],
                              status=valid_data['status'],
                              added_on=valid_data.get('added_on', date_now()),
                              updated_on=valid_data.get('updated_on', date_now())
                              )

            db.session.add(new_add)
            db.session.commit()
            return userRegister.jsonify(new_add)
        except Exception as e:
            return {"error_msg": str(e)}
    else:
        return jsonify({"test": data['message']})


@app.route('/address/<uid>', methods=['PUT'])
def update_user_address(uid):
    user = Address.query.get(uid)
    if not user:
        return {"error_msg": "address data is not found"}
    data = address_s(request.data)
    if data['status']:
        try:
            valid_data = data['message']
            user_add_id = valid_data['user_add_id']
            address1 = valid_data['address1']
            address2 = valid_data['address2']
            city = valid_data['city']
            pincode = valid_data['pincode']
            landmark = valid_data['landmark']
            address_type = valid_data['address_type']
            status = valid_data['status']
            added_on = valid_data['added_on']
            updated_on = valid_data['updated_on']
            user.user_add_id = user_add_id
            user.address1 = address1
            user.address2 = address2
            user.city = city
            user.pincode = pincode
            user.landmark = landmark
            user.address_type = address_type
            user.status = status
            user.added_on = added_on
            user.updated_on = updated_on
            db.session.commit()
            return userAddress.jsonify(user)
        except Exception as e:
            return {"error_msg": str(e)}
    else:
        return jsonify({"message": data['message']})


@app.route('/address/<uid>', methods=['GET'])
@token_required
def address_single_data(current_user, uid):
    try:
        user = Address.query.get(uid)
        if not user:
            return {"error_msg": "Address data is not found"}
        data = {"user": object_as_dict(user)}
        return response(data, 200, "user_Details", False)
    except Exception as e:
        return {"error_msg": str(e)}


@app.route('/address', methods=['GET'])
@token_required
def address_all_data(current_user):
    try:
        user = Address.query.all()
        list = []
        for a in user:
            list.append(object_as_dict(a))
        data = {"Address_list": list}
        return response(data, 200, "Address Details", False)
    except Exception as e:
        return {"error_msg": str(e)}


# Certificate
@app.route('/certificate', methods=['POST'])
def user_certificate():
    data = certificate_s(request.data)
    if data['status']:
        try:
            valid_data = data['message']
            new_cert = Certificate(user_id=valid_data['user_id'], cert_title=valid_data['cert_title'],
                                   cert_proof=valid_data['cert_proof'],
                                   status=valid_data['status'], added_on=valid_data['added_on'],
                                   updated_on=valid_data['updated_on'])
            return UserCertifications.jsonify(new_cert)
        except Exception as e:
            return {"error_msg": str(e)}
    else:
        return jsonify({"test": data['message']})


@app.route('/update_user_certificate/<uid>', methods=['PUT'])
def update_user_certificate(uid):
    user = Certificate.query.get(uid)
    if not user:
        return {"error_msg": "address data is not found"}
    data = certificate_s(request.data)
    if data['status']:
        try:
            valid_data = data['message']
            user_id = valid_data['user_id']
            cert_title = valid_data['cert_title']
            cert_proof = valid_data['cert_proof']
            status = valid_data['status']
            added_on = valid_data['added_on']
            updated_on = valid_data['updated_on']
            user.user_id = user_id
            user.cert_title = cert_title
            user.cert_proof = cert_proof
            user.status = status
            user.added_on = added_on
            user.updated_on = updated_on
            db.session.commit()
            return UserCertifications.jsonify(user)
        except Exception as e:
            return {"error_msg": str(e)}
    else:
        return jsonify({"message": data['message']})


@app.route('/user_certificate/<uid>', methods=['GET'])
@token_required
def certificate_single_dat(current_user, uid):
    try:
        user = Certificate.query.get(uid)
        if not user:
            return {"error_msg": "Certificate data is not found"}
        data = {"user": object_as_dict(user)}
        return response(data, 200, "Certificate Details", False)
    except Exception as e:
        return {"error_msg": str(e)}


@app.route('/cert_userid/<user_id>', methods=['GET'])
@token_required
def use_id(current_user, user_id):
    try:
        user = Certificate.query.filter_by(user_id=user_id)
        return UsersCertifications.jsonify(user)
    except Exception as e:
        return {"error_msg": str(e)}


@app.route('/cert_id/<cert_id>', methods=['GET'])
@token_required
def cer_id(current_user, cert_id):
    try:
        user = Certificate.query.filter_by(cert_id=cert_id)
        return UsersCertifications.jsonify(user)
    except Exception as e:
        return {"error_msg": str(e)}


@app.route('/all_user_certificate', methods=['GET'])
@token_required
def certificate_all_data(current_user):
    try:
        user = Certificate.query.all()
        list = []
        for c in user:
            list.append(object_as_dict(c))
        data = {"Register_list": list}
        return response(data, 200, "Address Details", False)
    except Exception as e:
        return {"error_msg": str(e)}


# Education
@app.route('/education', methods=['POST'])
def education():
    data = education_s(request.data)
    if data['status']:
        try:
            valid_data = data['message']
            new_edu = Education(user_id=valid_data['user_id'], course=valid_data['course'],
                                institute_name=valid_data['institute_name'],
                                university=valid_data['university'], year_of_pass=valid_data['year_of_pass'],
                                percentage=valid_data['percentage'], status=valid_data['status'],
                                modify_on=valid_data['modify_on'], modify_by=valid_data['modify_by'])
            return Education.jsonify(new_edu)
        except Exception as e:
            return {"error_msg": str(e)}
    else:
        return jsonify({"test": data['message']})


@app.route('/edu/<uid>', methods=['GET'])
@token_required
def education_data(current_user, uid):
    try:
        user = Education.query.get(uid)
        if not user:
            return {"error_msg": "Education data is not found"}
        data = {"user": object_as_dict(user)}
        return response(data, 200, "Education Details", False)
    except Exception as e:
        return {"error_msg": str(e)}


@app.route('/edu_userid/<user_id>', methods=['GET'])
@token_required
def edu_data(current_user, user_id):
    try:
        user = Education.query.filter_by(user_id=user_id)
        return UsersEdu.jsonify(user)
    except Exception as e:
        return {"error_msg": str(e)}


@app.route('/edu_id/<edu_id>', methods=['GET'])
@token_required
def education_id(current_user, edu_id):
    try:
        user = Education.query.filter_by(edu_id=edu_id)
        return UsersEdu.jsonify(user)
    except Exception as e:
        return {"error_msg": str(e)}


@app.route('/edu_all', methods=['GET'])
@token_required
def edu_datas(current_user):
    try:
        user = Education.query.all()
        list = []
        for e in user:
            list.append(object_as_dict(e))
        data = {"Education_list": list}
        return response(data, 200, "Education Details", False)
    except Exception as e:
        return {"error_msg": str(e)}


@app.route('/update_education/<edu_id>', methods=['PUT'])
def update_edu(edu_id):
    user = Education.query.get(edu_id)
    if not user:
        return {"error_msg": "Education data is not found"}
    data = education_s(request.data)
    if data['status']:
        try:
            valid_data = data['message']
            user = Education.query.get(edu_id)
            user_id = valid_data['user_id']
            course = valid_data['course']
            institute_name = valid_data['institute_name']
            university = valid_data['university']
            year_of_pass = valid_data['year_of_pass']
            percentage = valid_data['percentage']
            status = valid_data['status']
            modify_on = valid_data['modify_on']
            modify_by = valid_data['modify_by']
            user.user_id = user_id
            user.course = course
            user.institute_name = institute_name
            user.university = university
            user.year_of_pass = year_of_pass
            user.percentage = percentage
            user.status = status
            user.modify_on = modify_on
            user.modify_by = modify_by
            db.session.commit()
            return UserEdu.jsonify(user)
        except Exception as e:
            return {"error_msg": str(e)}
    else:
        return jsonify({"message": data['message']})


# Experience
@app.route('/experience', methods=['POST'])
def user_experience():
    data = experience_s(request.data)
    if data['status']:
        try:
            valid_data = data['message']
            new_exp = Experience(user_id=valid_data['user_id'], title=valid_data['title'],
                                 company_name=valid_data['company_name'],
                                 start_date=valid_data['start_date'], end_date=valid_data['end_date'],
                                 location=valid_data['location'], status=valid_data['status'],
                                 added_on=valid_data['added_on'], updated_on=valid_data['updated_on'])
            return Education.jsonify(new_exp)
        except Exception as e:
            return {"error_msg": str(e)}
    else:
        return jsonify({"test": data['message']})


@app.route('/update_user_experience/<uid>', methods=['PUT'])
def update_exp(uid):
    user = Experience.query.get(uid)
    if not user:
        return {"error_msg": "Experience data is not found"}
    data = experience_s(request.data)
    if data['status']:
        try:
            valid_data = data['message']
            user_id = valid_data['user_id']
            title = valid_data['title']
            company_name = valid_data['company_name']
            start_date = valid_data['start_date']
            end_date = valid_data['end_date']
            location = valid_data['location']
            status = valid_data['status']
            added_on = valid_data['added_on']
            updated_on = valid_data['updated_on']
            user.user_id = user_id
            user.title = title
            user.company_name = company_name
            user.start_date = start_date
            user.end_date = end_date
            user.location = location
            user.status = status
            user.added_on = added_on
            user.updated_on = updated_on
            db.session.commit()
            return UserExperience.jsonify(user)
        except Exception as e:
            return {"error_msg": str(e)}
    else:
        return jsonify({"message": data['message']})


@app.route('/exp/<uid>', methods=['GET'])
@token_required
def experience_single_data(current_user, uid):
    try:
        user = Experience.query.get(uid)
        if not user:
            return {"error_msg": "Experience data is not found"}
        data = {"user": object_as_dict(user)}
        return response(data, 200, "Experience Details", False)
    except Exception as e:
        return {"error_msg": str(e)}


@app.route('/exp_userid/<user_id>', methods=['GET'])
@token_required
def experience_by_users(current_user, user_id):
    try:
        user = Experience.query.filter_by(user_id=user_id)
        return UsersExperience.jsonify(user)
    except Exception as e:
        return {"error_msg": str(e)}


@app.route('/exp_id/<exp_id>', methods=['GET'])
@token_required
def experience_id(current_user, exp_id):
    try:
        user = Experience.query.filter_by(exp_id=exp_id)
        return UsersExperience.jsonify(user)
    except Exception as e:
        return {"error_msg": str(e)}


@app.route('/all_experience_data', methods=['GET'])
@token_required
def experience_all_data(current_user):
    user = Experience.query.all()
    list = []
    for x in user:
        list.append(object_as_dict(x))
    data = {"Experience_list": list}
    return response(data, 200, "Experience Details", False)


# skill
@app.route('/skill', methods=['POST'])
def skill():
    data = Skill(request.data)
    if data['status']:
        try:
            valid_data = data['message']
            skills = Skill(user_id=valid_data['user_id'], skill=valid_data['skill'],
                           experience=valid_data['experience'],
                           status=valid_data[' status'], skill_version=valid_data['skill_version'],
                           added_on=valid_data['added_on'], updated_on=valid_data['updated_on'])
            return Skill.jsonify(skills)
        except Exception as e:
            return {"error_msg": str(e)}
    else:
        return jsonify({"test": data['message']})


@app.route('/user_skill/<uid>', methods=['GET'])
@token_required
def skill_single_data(current_user, uid):
    try:
        user = Skill.query.get(uid)
        if not user:
            return {"error_msg": "Skill data is not found"}
        data = {"user": object_as_dict(user)}
        return response(data, 200, "Skill Details", False)
    except Exception as e:
        return {"error_msg": str(e)}


@app.route('/all_skill', methods=['GET'])
@token_required
def skill_all_data(current_user):
    try:
        user = Skill.query.all()
        list = []
        for s in user:
            list.append(object_as_dict(s))
        data = {"Skill_list": list}
        return response(data, 200, "`Skill Details", False)
    except Exception as e:
        return {"error_msg": str(e)}


@app.route('/skill_userid/<user_id>', methods=['GET'])
@token_required
def skill_data(current_user, user_id):
    try:
        user = Skill.query.filter_by(user_id=user_id)
        return UsersSkill.jsonify(user)
    except Exception as e:
        return {"error_msg": str(e)}


@app.route('/skill_id/<skill_id>', methods=['GET'])
@token_required
def skill_id(current_user, skill_id):
    try:
        user = Skill.query.filter_by(skill_id=skill_id)
        return UsersSkill.jsonify(user)
    except Exception as e:
        return {"error_msg": str(e)}


# skill
@app.route('/update_skill/<skill_id>', methods=['PUT'])
def update_skill(skill_id):
    user = Skill.query.get(skill_id)
    if not user:
        return {"error_msg": "Skill data is not found"}
    data = experience_s(request.data)
    if data['status']:
        try:
            valid_data = data['message']
            user_id = valid_data['user_id']
            skill = valid_data['skill']
            experience = valid_data['experience']
            status = valid_data['status']
            added_on = valid_data['added_on']
            updated_on = valid_data['updated_on']
            skill_version = valid_data['skill_version']
            user.user_id = user_id
            user.skill = skill
            user.experience = experience
            user.status = status
            user.added_on = added_on
            user.updated_on = updated_on
            user.skill_version = skill_version
            db.session.commit()
            return UserSkill.jsonify(user)
        except Exception as e:
            return {"error_msg": str(e)}
    else:
        return jsonify({"message": data['message']})


# LoginStatus
@app.route('/loginStatus', methods=['POST'])
def user_login_status():
    data = validate(request.data)
    if validate(request.data)['status']:
        valid_data = data['message']
        try:
            login_status_id = request.json['login_status_id']
            login_activate = request.json['login_activate']
            login_key = request.json['login_key']
            login_device = request.json['login_device']
            logout_date = request.json['logout_date']
            new_user = LoginStatus(login_status_id=login_status_id, login_activate=login_activate, login_key=login_key,
                                   login_device=login_device, logout_date=logout_date)
            db.session.add(new_user)
            db.session.commit()
            return UserLoginStatus.jsonify(new_user)
        except Exception as e:
            return {"error_msg": str(e)}
    else:
        return jsonify({"test": data['message']})


@app.route('/user_Login/<uid>', methods=['GET'])
@token_required
def login_status_single_data(current_user, uid):
    try:
        user = LoginStatus.query.get(uid)
        return UserLoginStatus.jsonify(user)
    except Exception as e:
        return {"error_msg": str(e)}


@app.route('/all_user_Login', methods=['GET'])
@token_required
def login_status_all_data(current_user):
    try:
        user = LoginStatus.query.all()
        return UsersLoginStatus.jsonify(user)
    except Exception as e:
        return {"error_msg": str(e)}


# RegisterCompany
@app.route('/add_company', methods=['POST'])
def add_company():
    data = validate(request.data)
    if validate(request.data)['status']:
        valid_data = data['message']
        try:
            user_company_id = request.json['user_company_id']
            company_name = request.json['company_name']
            gst_no = request.json['gst_no']
            company_email = request.json['company_email']
            details = request.json['details']
            mobile_no = request.json['mo bile_no']
            address = request.json['address']
            pin_code = request.json['pin_code']
            website_url = request.json['website_url']
            linked_in = request.json['linked_in']
            twitter = request.json['twitter']
            facebook = request.json['facebook']
            instagram = request.json['instagram']
            whatsapp = request.json['whatsapp']
            contact_number = request.json['contact_number']
            status = request.json['status']
            added_on = request.json['added_on']
            updated_on = request.json['updated_on']
            new_user = Company(user_company_id=user_company_id, company_name=company_name, gst_no=gst_no,
                               company_email=company_email,
                               details=details, mobile_no=mobile_no, address=address, pin_code=pin_code,
                               website_url=website_url, linked_in=linked_in, facebook=facebook, twitter=twitter,
                               instagram=instagram, whatsapp=whatsapp, contact_number=contact_number, status=status,
                               added_on=added_on, updated_on=updated_on)
            db.session.add(new_user)
            db.session.commit()
            return userRegisterCompany.jsonify(new_user)
        except Exception as e:
            return {"error_msg": str(e)}
    else:
        return jsonify({"test": data['message']})


@app.route('/update_company/<user_company_id>', methods=['PUT'])
def update_company(user_company_id):
    user = Company.query.get(user_company_id)
    user_company_id = request.json['user_company_id']
    company_name = request.json['company_name']
    gst_no = request.json['gst_no']
    company_email = request.json['company_email']
    details = request.json['details']
    mobile_no = request.json['mobile_no']
    address = request.json['address']
    pin_code = request.json['pin_code']
    website_url = request.json['website_url']
    linked_in = request.json['linked_in']
    twitter = request.json['twitter']
    facebook = request.json['facebook']
    instagram = request.json['instagram']
    whatsapp = request.json['whatsapp']
    contact_number = request.json['contact_number']
    status = request.json['status']
    added_on = request.json['added_on']
    updated_on = request.json['updated_on']
    user.user_company_id = user_company_id
    user.company_name = company_name
    user.gst_no = gst_no
    user.company_email = company_email
    user.details = details
    user.mobile_no = mobile_no
    user.address = address
    user.pin_code = pin_code
    user.website_url = website_url
    user.linked_in = linked_in
    user.twitter = twitter
    user.facebook = facebook
    user.instagram = instagram
    user.whatsapp = whatsapp
    user.contact_number = contact_number
    user.status = status
    user.added_on = added_on
    user.updated_on = updated_on
    db.session.commit()
    return userRegisterCompany.jsonify(user)


@app.route('/company/<uid>', methods=['GET'])
@token_required
def company_single_data(current_user, uid):
    try:
        user = Company.query.get(uid)
        if not user:
            return {"error_msg": "Register company data is not found"}
        data = {"user": object_as_dict(user)}
        return response(data, 200, "Register company Details", False)
    except Exception as e:
        return {"error_msg": str(e)}


@app.route('/all_company', methods=['GET'])
@token_required
def company_all_data(current_user):
    try:
        user = Company.query.all()
        list = []
        for c in user:
            list.append(object_as_dict(c))
        data = {"Register Company_list": list}
        return response(data, 200, "Register company Details", False)
    except Exception as e:
        return {"error_msg": str(e)}


# jobpost

@app.route('/job_post', methods=['POST'])
def job_post():
    data = validate(request.data)
    if validate(request.data)['status']:
        valid_data = data['message']
        try:
            job_id = request.json['job_id']
            user_id = request.json['user_id']
            company_id = request.json['company_id']
            company_name_hidden = request.json['company_name_hidden']
            created_on = request.json['created_on']
            job_location = request.json['job_location']
            is_active = request.json['is_active']
            apply_on = request.json['apply_on']
            new_user = JobPost(job_id=job_id, user_id=user_id, company_id=company_id,
                               company_name_hidden=company_name_hidden,
                               created_on=created_on, job_location=job_location, is_active=is_active, apply_on=apply_on)
            db.session.add(new_user)
            db.session.commit()
            return jobPostCompany.jsonify(new_user)
        except Exception as e:
            return {"error_msg": str(e)}
    else:
        return jsonify({"test": data['message']})


@app.route('/update_job/<uid>', methods=['PUT'])
def update_job(uid):
    try:
        user = JobPost.query.get(uid)
        job_id = request.json['job_id']
        user_id = request.json['user_id']
        company_id = request.json['company_id']
        company_name_hidden = request.json['company_name_hidden']
        is_active = request.json['is_active']
        job_location = request.json['job_location']
        created_on = request.json['created_on']
        apply_on = request.json['apply_on']
        user.job_id = job_id
        user.user_id = user_id
        user.company_id = company_id
        user.company_name_hidden = company_name_hidden
        user.created_on = created_on
        user.job_location = job_location
        user.is_active = is_active
        user.apply_on = apply_on
        db.session.commit()
        return jobPostCompany.jsonify(user)
    except Exception as e:
        return {"error_msg": str(e)}


@app.route('/job_post/<user_id>', methods=['GET'])
@token_required
def jobpost(current_user, user_id):
    try:
        user = JobPost.query.get(user_id)
        if not user:
            return {"error_msg": "job post data is not found"}
        data = {"user": object_as_dict(user)}
        return response(data, 200, "job post Details", False)
    except Exception as e:
        return {"error_msg": str(e)}


@app.route('/all_job_post', methods=['GET'])
@token_required
def all_job_post(current_user):
    try:
        user = JobPost.query.all()
        list = []
        for e in user:
            list.append(object_as_dict(e))
        data = {"Job Post_list": list}
        return response(data, 200, "Job Post Details", False)
    except Exception as e:
        return {"error_msg": str(e)}


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
