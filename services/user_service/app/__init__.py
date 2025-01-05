from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from redis import Redis
from flask_jwt_extended import jwt_required, get_jwt_identity, JWTManager, get_jwt
from flask_injector import FlaskInjector
from datetime import timedelta
from injector import inject, singleton
import json

app = Flask(__name__)
app.config['MONGO_URI'] = 'mongodb://mongo:27017/auth_service_db'
app.config['JWT_SECRET_KEY'] = '6f3a3b5e4e94a62b8b86d705db7f36d5a4c898ed246f6cc871eaf5d42a502d9f'
app.config["JWT_HEADER_NAME"] = 'Authorization'
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config["JWT_HEADER_TYPE"] = "Bearer"
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
mongo = PyMongo(app)
redis = Redis(host='redis', port=6379)
jwt = JWTManager(app)

@app.route('/user', methods=['POST'])
@jwt_required()
def add_user():
    data = request.json
    claims = get_jwt()
    user_role = claims.get("role")
    if user_role != 'admin':
        return jsonify({"message": "Unauthorized"}), 403
    mongo.db.users.insert_one(data)
    return jsonify({"message": "User added successfully"}), 201

@app.route('/user/<user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    user_data = redis.get(f"user:{user_id}")
    if user_data:
        return jsonify(json.loads(user_data)), 200
    user = mongo.db.users.find_one({"username": user_id})
    user["_id"] = str(user["_id"])
    if not user:
        return jsonify({"message": "User not found"}), 404
    redis.set(f"user:{user_id}", json.dumps(user), ex=3600)  # Cache for 1 hour
    return jsonify(user), 200

@app.route('/user/<user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    data = request.json
    current_user = get_jwt_identity()
    user = mongo.db.users.find_one({"_id": user_id})
    if not user:
        return jsonify({"message": "User not found"}), 404
    if current_user['role'] != 'admin' and current_user['email'] != user['email']:
        return jsonify({"message": "Unauthorized"}), 403
    mongo.db.users.update_one({"_id": user_id}, {"$set": data})
    return jsonify({"message": "User updated successfully"}), 200

@app.route('/user/<user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({"message": "Unauthorized"}), 403
    mongo.db.users.delete_one({"_id": user_id})
    return jsonify({"message": "User deleted successfully"}), 200
