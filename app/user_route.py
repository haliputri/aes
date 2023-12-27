from flask import Flask, request, jsonify, Blueprint, redirect, url_for, render_template, flash
from config import mongo, db_user, db_essay
from bson import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash

user_blueprint = Blueprint('users', __name__)

# crud db users
def user_inc_index():
    user = db_user.find_one_and_update(
        {"_id": "user_id"},
        {"$inc": {"dump_index": 1}},
        upsert=True,
        return_document=True,
    )
    return str(user["dump_index"])

@user_blueprint.route('/create_user', methods=['GET', 'POST'])
def create_user():
    _json = request.json
    # _name = _json['name']
    _email = _json['email']
    _password = _json['password']
    # _npm = _json['npm']
    # _role = _json['role']
    
    if _email and _password and request.method == 'POST':
        _hashed_password = generate_password_hash(_password)
        _index = str(user_inc_index())
            
        # id = db_user.insert_one({'index':_index, 'name' : _name, 'email':_email, 'password' : _hashed_password, 'npm' : _npm, 'role':_role})
        id = db_user.insert_one({'index':_index, 'email':_email, 'password' : _hashed_password})
        
        resp = jsonify("User added succesfully")
        resp.status_code = 200
        
        return resp
    else:
        return not_found()
    
@user_blueprint.errorhandler(404)
def not_found(error = None):
    message = {
        'status' : 404,
        'message' : 'Not Found' + request.url
    }
    resp = jsonify(message)
    resp.status_code = 404
    return resp

# Route to create user collection and insert new data
@user_blueprint.route('/users', methods=['GET'])
def api_users():
    user_collection = mongo.db.users

    # Fetch all users from the collection
    users_cursor = user_collection.find()

    # Convert the cursor to a list of dictionaries
    users = list(users_cursor)

    # Convert ObjectId to string for JSON serialization
    for user in users:
        user['_id'] = str(user['_id'])

    # Count the documents in the "users" collection
    user_count = user_collection.count_documents({})

    response_data = {'user_count': user_count, 'users': users}
    # Return a JSON response containing the inserted users
    return jsonify(response_data)

@user_blueprint.route('/delete/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    db_user.delete_one({'_id': ObjectId(user_id)})
    resp = jsonify("User deleted successfully")
    resp.status_code = 200
    return resp

@user_blueprint.route('/update/<user_id>', methods=['PUT'])
def update_user(user_id):
    try:
        _id = user_id
        _json = request.json

        # Pastikan _json bukan None dan _json adalah dictionary
        if _json and isinstance(_json, dict):
            update_fields = {}  # Inisialisasi dictionary untuk bidang yang akan diupdate

            # Cek apakah bidang-bidang yang akan diupdate ada dalam _json
            if 'name' in _json:
                update_fields['name'] = _json['name']

            if 'email' in _json:
                update_fields['email'] = _json['email']

            if 'password' in _json:
                update_fields['password'] = generate_password_hash(_json['password'])

            if 'npm' in _json:
                update_fields['npm'] = _json['npm']

            # Perbarui dokumen menggunakan operator $set
            db_user.update_one({'_id': ObjectId(_id)}, {'$set': update_fields})

            resp = jsonify("User updated successfully")
            resp.status_code = 200

            return resp
        else:
            return jsonify({'error': 'Invalid JSON data'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# @user_blueprint.route('/users/<user_id>')
# def get_user_by_id(user_id):
#     try:
#         user_object_id = ObjectId(user_id)
#         user = db_user.find_one({'_id': user_object_id})

#         if user:
#             user['_id'] = str(user['_id'])
#             return jsonify(user)
#         else:
#             return jsonify({'error' : 'User not found'}), 404
#     except Exception as e:
#         # Handle any exceptions that may occur during the process
#         return jsonify({'error': str(e)}), 500
    
@user_blueprint.route('/users/<index>')
def get_user_by_index(index):
    try:
        user = db_user.find_one({'index': index})

        if user:
            # Convert the index back to a string in the response
            user['_id'] = str(user['_id'])
            user['index'] = str(user['index'])
            return jsonify(user)
        else:
            return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        # Handle any exceptions that may occur during the process
        print(f"Error: {str(e)}")
        return jsonify({'error': str(e)}), 500

    
@user_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    # Get user input from the form
    email = request.form.get('email')
    password = request.form.get('password')
    role = 'user'
    
    if email and password and request.method == 'POST':
        _hashed_password = generate_password_hash(password)
        _index = str(user_inc_index())
        
        db_user.insert_one({'index':_index,'email':email, 'password' : _hashed_password, 'role':role})
       
        # Flash a success message
        flash('Registration successful!', 'success')
        
        # Redirect to a success page (you can customize this)
        return render_template('register.html')
    # Render the registration form for GET requests
    return render_template('register.html')

@user_blueprint.route('/', methods=['GET', 'POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')
    
    if email and password and request.method == 'POST':
        user = db_user.find_one({'email': email})
        
        if user and check_password_hash(user['password'], password):
            # Authentication successful, set a session variable or perform other tasks
            flash('Login successful!', 'success')
            if 'role' in user:
                if user['role'] == 'admin':
                    # return redirect(url_for('users.profile_admin_by_id', user_id=str(user['_id'])))
                    return redirect(url_for('users.profile_admin_by_index', index=user['index']))
                elif user['role'] == 'user':
                    return redirect(url_for('users.profile_user_by_index', index=user['index']))
            return redirect(url_for('profile_user_by_id', user_id=str(user['_id'])))  # Redirect to the dashboard or another page
        else:
            flash('Invalid email or password', 'error')
            
    return render_template('login.html')

# @user_blueprint.route('/user/<user_id>')
# def profile_user_by_id(user_id):
#     try:
#         user_object_id = ObjectId(user_id)
#         user = db_user.find_one({'_id': user_object_id})

#         if user:
#             user_name = user['name'] if 'name' in user else user['email'].split('@')[0]
#             return render_template('user.html', user_id=str(user['_id']), user_email=user['email'], user_name=user_name)
#         else:
#             return jsonify({'error' : 'User not found'}), 404
#     except Exception as e:
#         # Handle any exceptions that may occur during the process
#         return jsonify({'error': str(e)}), 500
    
@user_blueprint.route('/user/<index>')
def profile_user_by_index(index):
    try:
        user = db_user.find_one({'index': index})
        if user:
            user_name = user['name'] if 'name' in user else user['email'].split('@')[0]
            return render_template('user.html', user=user, user_name=user_name)
        else:
            return jsonify({'error' : 'User not found'}), 404
    except Exception as e:
        # Handle any exceptions that may occur during the process
        return jsonify({'error': str(e)}), 500
    
# @user_blueprint.route('/admin/<user_id>')
# def profile_admin_by_id(user_id):
#     try:
#         user_object_id = ObjectId(user_id)
#         user = db_user.find_one({'_id': user_object_id})

#         if user:
#             user_name = user['name'] if 'name' in user else user['email'].split('@')[0]
#             return render_template('/admin/admin.html', user_id=str(user['_id']), user_email=user['email'], user_name=user_name)
#         else:
#             return jsonify({'error' : 'Admin not found'}), 404
#     except Exception as e:
#         # Handle any exceptions that may occur during the process
#         return jsonify({'error': str(e)}), 500

@user_blueprint.route('/admin/<index>')
def profile_admin_by_index(index):
    try:
        user = db_user.find_one({'index': index})

        if user:
            user_name = user['name'] if 'name' in user else user['email'].split('@')[0]
            return render_template('/admin/admin.html', user=user, user_name=user_name)
        else:
            return jsonify({'error' : 'Admin not found'}), 404
    except Exception as e:
        # Handle any exceptions that may occur during the process
        return jsonify({'error': str(e)}), 500
    
# @user_blueprint.route('/user/intro/<user_id>')
# def introSoal(user_id):
#     try:
#         user_object_id = ObjectId(user_id)
#         user = db_user.find_one({'_id': user_object_id})

#         if user:
#             user_name = user['name'] if 'name' in user else user['email'].split('@')[0]
#             return render_template('introSoal.html', user_id=str(user['_id']), user_email=user['email'], user_name=user_name)
#         else:
#             return jsonify({'error' : 'Page not found'}), 404
#     except Exception as e:
#         # Handle any exceptions that may occur during the process
#         return jsonify({'error': str(e)}), 500
    

@user_blueprint.route('/user/intro/<index>')
def introSoal(index):
    try:
        user = db_user.find_one({'index': index})

        if user:
            user_name = user['name'] if 'name' in user else user['email'].split('@')[0]
            return render_template('introSoal.html', user=user, user_name=user_name)
        else:
            return jsonify({'error' : 'Page not found'}), 404
    except Exception as e:
        # Handle any exceptions that may occur during the process
        return jsonify({'error': str(e)}), 500
    
@user_blueprint.route('/admin/adminEsai/<index>')
def adminEsai(index):
    try:
        essays_data = db_essay.find_one({})
        user = db_user.find_one({'index': index})

        if essays_data and user:
            user_name = user['name'] if 'name' in user else user['email'].split('@')[0]
            essays = essays_data.get('essays', [])
            return render_template('admin/adminEsai.html', essays=essays_data, user=user, user_name=user_name)
        else:
            return jsonify({'error': 'Essay data not found'}), 404
    except Exception as e:
        # Handle any exceptions that may occur during the process
        return jsonify({'error': str(e)}), 500