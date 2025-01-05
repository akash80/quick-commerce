from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token
from flask_pymongo import PyMongo
from datetime import timedelta
from functools import wraps

app = Flask(__name__)
app.config['MONGO_URI'] = 'mongodb://mongo:27017/auth_service_db'
app.config['JWT_SECRET_KEY'] = '6f3a3b5e4e94a62b8b86d705db7f36d5a4c898ed246f6cc871eaf5d42a502d9f'
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
mongo = PyMongo(app)
jwt = JWTManager(app)

# Mocked user role check decorator
def role_required(role):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            token = request.headers.get('Authorization').split(" ")[1]
            user = jwt.decode_token(token)
            if user.get('role') != role:
                return jsonify({"message": "Unauthorized"}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator

@app.route('/register', methods=['POST'])
def register_user():
    data = request.json
    if mongo.db.users.find_one({"email": data["email"]}):
        return jsonify({"message": "User already exists"}), 400
    mongo.db.users.insert_one(data)
    return jsonify({"message": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login_user():
    data = request.json
    user = mongo.db.users.find_one({"email": data["email"]})
    if not user or user["password"] != data["password"]:
        return jsonify({"message": "Invalid credentials"}), 401
    access_token = create_access_token(
        identity=str(user["email"]),  # Use a string or simple value for identity
        additional_claims={"role": user["role"]}
    )
    return jsonify({"access_token": access_token}), 200
