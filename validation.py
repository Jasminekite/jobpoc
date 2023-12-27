from utils import validate, validate_req_data


def users_add(request_data):
    data = validate(request_data)
    if data['status']:
        try:
            valid_data = data['message']
            req_keys = ['user_name', 'email_id', 'password']
            data = validate_req_data(valid_data, req_keys)
            if not data['status']:
                return {"status": False, "message": data['message']}
            user_name = valid_data['user_name']
            if len(user_name) < 5 or len(user_name) > 20:
                return {"status": False, "message": "Username must be between 5 and 20 characters"}
            else:
                return {"status": True, "message": valid_data}
        except Exception as e:
            return {"status": False, "message": str(e)}
    else:
        return {"status": False, "message": data['message']}


def users_profile(request_data):
    data = validate(request_data)
    if data['status']:
        try:
            valid_data = data['message']
            req_keys = ['first_name', 'last_name', 'email_id', 'gender']
            data = validate_req_data(valid_data, req_keys)
            if not data['status']:
                return {"status": False, "message": data['message']}
            else:
                return {"status": True, "message": valid_data}
        except Exception as e:
            return {"status": False, "message": str(e)}
    else:
        return {"status": False, "message": data['message']}


def address_s(request_data):
    data = validate(request_data)
    if data['status']:
        try:
            valid_data = data['message']
            req_keys = ['address1', 'address2', 'pin_code', 'city']
            data = validate_req_data(valid_data, req_keys)
            if not data['status']:
                return {"status": False, "message": data['message']}
            else:
                return {"status": True, "message": valid_data}
        except Exception as e:
            return {"status": False, "message": str(e)}
    else:
        return {"status": False, "message": data['message']}


def certificate_s(request_data):
    data = validate(request_data)
    if data['status']:
        try:
            valid_data = data['message']
            req_keys = ['cert_proof', 'cert_title']
            data = validate_req_data(valid_data, req_keys)
            if not data['status']:
                return {"status": False, "message": data['message']}
            else:
                return {"status": True, "message": valid_data}
        except Exception as e:
            return {"status": False, "message": str(e)}
    else:
        return {"status": False, "message": data['message']}


def education_s(request_data):
    data = validate(request_data)
    if data['status']:
        try:
            valid_data = data['message']
            req_keys = ['course', ' year_of_pass', 'institute_name', 'university', 'percentage']
            data = validate_req_data(valid_data, req_keys)
            if not data['status']:
                return {"status": False, "message": data['message']}
            else:
                return {"status": True, "message": valid_data}
        except Exception as e:
            return {"status": False, "message": str(e)}
    else:
        return {"status": False, "message": data['message']}


def experience_s(request_data):
    data = validate(request_data)
    if data['status']:
        try:
            valid_data = data['message']
            req_keys = [' title', 'company_name']
            data = validate_req_data(valid_data, req_keys)
            if not data['status']:
                return {"status": False, "message": data['message']}
            else:
                return {"status": True, "message": valid_data}
        except Exception as e:
            return {"status": False, "message": str(e)}
    else:
        return {"status": False, "message": data['message']}
