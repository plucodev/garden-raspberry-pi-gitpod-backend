"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
import os
from flask import Flask, request, jsonify, url_for
from flask_migrate import Migrate
from flask_swagger import swagger
from flask_cors import CORS
from utils import APIException, generate_sitemap, sha256
from models import db, User

app = Flask(__name__)
app.url_map.strict_slashes = False
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_CONNECTION_STRING')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
MIGRATE = Migrate(app, db)
db.init_app(app)
CORS(app)

# Handle/serialize errors like a JSON object
@app.errorhandler(APIException)
def handle_invalid_usage(error):
    return jsonify(error.to_dict()), error.status_code

# generate sitemap with all your endpoints
@app.route('/')
def sitemap():
    return generate_sitemap(app)

@app.route('/user', methods=['POST', 'GET'])
def handle_user():
    """
    Create user and retrieve all users
    """

    # POST request
    if request.method == 'POST':
        body = request.get_json()

        if body is None:
            raise APIException("You need to specify the request body as a json object", status_code=400)
        if 'username' not in body:
            raise APIException('You need to specify the username', status_code=400)
        if 'email' not in body:
            raise APIException('You need to specify the email', status_code=400)
        if 'password' not in body:
            raise APIException('You need to specify the password', status_code=400)    

        user1 = User(username=body['username'], email=body['email'], password=sha256(body['password']))
        db.session.add(user1)
        db.session.commit()
        return "ok", 200

    # GET request
    if request.method == 'GET':
        all_users = User.query.all()
        all_users = list(map(lambda x: x.serialize(), all_users))
        return jsonify(all_users), 200

    return "Invalid Method", 404


@app.route('/user/<int:user_id>', methods=['PUT', 'GET', 'DELETE'])
def get_single_user(user_id):
    """
    Single user
    """
    current_user = User.query.get(user_id)
    # PUT request
    if request.method == 'PUT':
        body = request.get_json()
        if body is None:
            raise APIException("You need to specify the request body as a json object", status_code=400)
        if current_user is None:
            raise APIException('User not found', status_code=404)
        if "username" in body:
            current_user.username = body["username"]
        if "email" in body:
            current_user.email = body["email"]
        if "password" in body:
            current_user.password = sha256(body["password"])
        db.session.commit()

        return jsonify(current_user.serialize()), 200

    # GET request
    if request.method == 'GET':
        if current_user is None:
            raise APIException('User not found', status_code=404)
        return jsonify(current_user.serialize()), 200

    # DELETE request
    if request.method == 'DELETE':
        if current_user is None:
            raise APIException('User not found', status_code=404)
        db.session.delete(current_user)
        return "ok", 200

    return "Invalid Method", 404

# this only runs if `$ python src/main.py` is executed
if __name__ == '__main__':
    PORT = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=PORT, debug=False)
