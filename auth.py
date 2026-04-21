import jwt
import datetime
from functools import wraps
from flask import Blueprint, request, jsonify, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, AuditLog
from crypto_utils import generate_rsa_keypair

auth_bp = Blueprint('auth', __name__)

def token_required(role=None):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = None
            if 'Authorization' in request.headers:
                parts = request.headers['Authorization'].split()
                if len(parts) == 2 and parts[0] == 'Bearer':
                    token = parts[1]
            if not token:
                return jsonify({'message': 'Token is missing'}), 401
            try:
                data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
                current_user = User.query.get(data['user_id'])
                if not current_user:
                    return jsonify({'message': 'User not found'}), 401
                if role and current_user.role != role:
                    return jsonify({'message': f'Requires {role} role'}), 403
            except Exception as e:
                return jsonify({'message': 'Token is invalid', 'error': str(e)}), 401
            return f(current_user, *args, **kwargs)
        return decorated
    return decorator


@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password') or not data.get('email') or not data.get('role'):
        return jsonify({'message': 'Missing data'}), 400

    role = data.get('role')
    if role not in ['admin', 'center']:
        return jsonify({'message': 'Invalid role'}), 400

    if User.query.filter_by(username=data['username']).first() or User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'User already exists'}), 400

    hashed_password = generate_password_hash(data['password'])
    
    # Generate RSA keys
    private_pem, public_pem = generate_rsa_keypair()
    
    new_user = User(
        username=data['username'],
        email=data['email'],
        password_hash=hashed_password,
        role=role,
        public_key=public_pem.decode('utf-8')
    )
    
    # Simulating secure key storage for Admin server-side:
    # If it's an admin, we store the private key so the server can sign papers on their behalf during upload.
    # If it's a center, we DO NOT store the private key, we only return it once.
    if role == 'admin':
        new_user.private_key = private_pem.decode('utf-8')
    
    db.session.add(new_user)
    db.session.flush()
    db.session.add(AuditLog(
        user_id=new_user.id,
        action='register',
        details=f"role={role}; username={new_user.username}"
    ))
    db.session.commit()

    response = {'message': 'User created successfully', 'id': new_user.id}
    if role == 'center':
        # CRITICAL: Return the center's private key only once, never store it on server
        response['private_key'] = private_pem.decode('utf-8')
        
    return jsonify(response), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Missing credentials'}), 400
        
    user = User.query.filter_by(username=data['username']).first()
    if not user or not check_password_hash(user.password_hash, data['password']):
        return jsonify({'message': 'Invalid credentials'}), 401
        
    token = jwt.encode({
        'user_id': user.id,
        'role': user.role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    }, current_app.config['SECRET_KEY'], algorithm="HS256")
    db.session.add(AuditLog(
        user_id=user.id,
        action='login',
        details=f"role={user.role}; username={user.username}"
    ))
    db.session.commit()
    
    return jsonify({'token': token, 'role': user.role})

@auth_bp.route('/me', methods=['GET'])
@token_required()
def me(current_user):
    return jsonify({
        'id': current_user.id,
        'username': current_user.username,
        'email': current_user.email,
        'role': current_user.role,
        'public_key': current_user.public_key
    })


@auth_bp.route('/admin-public-key', methods=['GET'])
def admin_public_key():
    admin = User.query.filter_by(role='admin').order_by(User.id.asc()).first()
    if not admin or not admin.public_key:
        return jsonify({'error': 'Admin public key not available'}), 404
    return jsonify({
        'admin_id': admin.id,
        'public_key': admin.public_key
    })


@auth_bp.route('/centers', methods=['GET'])
@token_required(role='admin')
def list_centers(current_user):
    centers = User.query.filter_by(role='center').order_by(User.id.asc()).all()
    return jsonify({
        'centers': [
            {
                'id': center.id,
                'username': center.username,
                'email': center.email,
            }
            for center in centers
        ]
    })
