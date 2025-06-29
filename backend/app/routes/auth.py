from flask import Blueprint, request, jsonify
from app import db
from app.models.user import User
from flask_jwt_extended import create_access_token

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    name = data.get('name')
    password = data.get('password')

    if not all([email, name, password]):
        return jsonify({'error': 'Missing fields'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 409

    user = User(email=email, name=name)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({'message': 'Invalid credentials'}), 401

    token = jwt.encode({
        'id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, Config.JWT_SECRET_KEY, algorithm="HS256")

    return jsonify({'token': token, 'user': user.to_dict()}), 200
