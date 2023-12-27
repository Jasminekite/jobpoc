from config import db, ma

class UserSchema(ma.Schema):
    class Meta:
        fields = ('id', 'user_name', 'user_type', 'email_id', 'mobile_no', 'password', 'status')


userLogin = UserSchema()
usersLogin = UserSchema(many=True)

class UserRegister(ma.Schema):
    class Meta:
        fields = ('id', 'reg_user_id', 'first_name', 'last_name', 'email_id', 'gender', 'dob',
                  'martial_status', 'pan_number', 'aadhar_number', 'passport', 'passport_expire', 'user_type',
                  'linked_in', 'facebook ', 'twitter', 'work_status', 'resume', 'photo', 'alternate_mobile',
                  'differently_abled', 'abled_details', 'status', 'added_on', 'updated_on')


userRegister = UserRegister()
usersRegister = UserRegister(many=True)

class UserAddress(ma.Schema):
    class Meta:
        fields = (
            'id', 'user_add_id', 'address1', 'address2', 'city', 'pincode', 'landmark', 'address_type', 'status',
            'added_on', 'updated_on')


userAddress = UserAddress()
usersAddress = UserAddress(many=True)

class UserCertificate(ma.Schema):
    class Meta:
        fields = (
            'cert_id', 'user_id', 'cert_title', 'cert_proof', 'status', 'added_on', 'updated_on'
        )


UserCertifications = UserCertificate()
UsersCertifications = UserCertificate(many=True)

class Skill(ma.Schema):
    class Meta:
        fields = (
            'skill_id', 'user_id', 'skill', 'experience', 'status', 'added_on', 'updated_on', 'skill_version'
        )


UserSkill = Skill()
UsersSkill = Skill(many=True)

class UserEducation(ma.Schema):
    class Meta:
        fields = (
            'edu_id', 'user_id', 'course', 'institute_name', 'university', 'year_of_pass', 'percentage', 'status',
            'modify_on', 'modify_by'

        )


UserEdu = UserEducation()
UsersEdu = UserEducation(many=True)


class Experience(ma.Schema):
    class Meta:
        fields = (
            'exp_id', 'user_id', 'title', 'company_name', 'start_date', 'end_date', 'location', 'status',
            'added_on', 'updated_on'

        )

UserExperience = Experience()
UsersExperience = Experience(many=True)


class LoginStatus(ma.Schema):
    class Meta:
        fields = (
            'id', 'login_status_id', 'login_activate', 'login_key', 'login_device', 'logout_date'
        )


UserLoginStatus = LoginStatus()
UsersLoginStatus = LoginStatus(many=True)


class RegisterCompany(ma.Schema):
    class Meta:
        fields = ('id', 'user_company_id', 'company_name', 'gst_no', 'company_email', 'details', 'mobile_no',
                  'address', 'pin_code', 'website_url', 'linkedin', 'twitter', 'facebook',
                  'instagram', 'whatsapp', 'contact_number', 'status', 'added_on', 'updated_on')


userRegisterCompany = RegisterCompany()
usersRegisterCompany = RegisterCompany(many=True)

class JobPost(ma.Schema):
    class Meta:
        fields = (
            'job_id', 'user_id', 'company_id', 'company_name_hidden', 'created_on', 'job_location', 'is_active',
            'apply_on'
        )


jobPostCompany = JobPost()
jobsPostCompany = JobPost(many=True)
