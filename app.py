import qrcode
import io
import base64
from flask import Flask, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root@localhost/di_task1'
app.config['SECRET_KEY'] = 'your_jwt_secret_key'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    twofa_secret = db.Column(db.String(256), nullable=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255))
    price = db.Column(db.Numeric(10, 2))
    quantity = db.Column(db.Integer)

token_blacklist = set()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'message': 'Token is missing or invalid format!'}), 401
        token = token.split(" ")[1]
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            if token in token_blacklist:
                return jsonify({'message': 'Token is revoked!'}), 401
            current_user = User.query.filter_by(id=data['user_id']).first()
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return jsonify({'message': 'Invalid or expired token!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'User already exists!'}), 400

    hashed_password = generate_password_hash(data['password'] ) #method='sha256'
    twofa_secret = pyotp.random_base32()

    new_user = User(username=data['username'], password=hashed_password, twofa_secret=twofa_secret)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully!', 'username': data['username']})

@app.route('/generate_qr', methods=['POST'])
def generate_qr():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if not user:
        return jsonify({'message': 'User not found!'}), 404

    otp_uri = pyotp.totp.TOTP(user.twofa_secret).provisioning_uri(data['username'], issuer_name='FlaskApp')
    qr = qrcode.make(otp_uri)
    buffer = io.BytesIO()
    qr.save(buffer, format='PNG')
    qr_b64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

    return jsonify({'qr_code': qr_b64})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()

    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Invalid username or password!'}), 401

    totp = pyotp.TOTP(user.twofa_secret)
    if not totp.verify(data['token']):
        return jsonify({'message': 'Invalid 2FA code!'}), 401

    token = jwt.encode({'user_id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)}, app.config['SECRET_KEY'], algorithm='HS256')
    return jsonify({'token': token})

@app.route('/logout', methods=['POST'])
@token_required
def logout(current_user):
    token = request.headers.get('Authorization').split(" ")[1]
    token_blacklist.add(token)
    return jsonify({'message': 'Logout successful!'})

@app.route('/products', methods=['POST'])
@token_required
def create_product(current_user):
    data = request.get_json()
    new_product = Product(name=data['name'], description=data['description'], price=data['price'], quantity=data['quantity'])
    db.session.add(new_product)
    db.session.commit()
    return jsonify({'message': 'Product created successfully!'})

@app.route('/products', methods=['GET'])
@token_required
def get_products(current_user):
    products = Product.query.all()
    output = [{'id': p.id, 'name': p.name, 'description': p.description, 'price': float(p.price), 'quantity': p.quantity} for p in products]
    return jsonify({'products': output})

@app.route('/products/<int:id>', methods=['PUT'])
@token_required
def update_product(current_user, id):
    product = Product.query.get_or_404(id)
    data = request.get_json()

    product.name = data.get('name', product.name)
    product.description = data.get('description', product.description)
    product.price = data.get('price', product.price)
    product.quantity = data.get('quantity', product.quantity)

    db.session.commit()
    return jsonify({'message': 'Product updated successfully!'})

@app.route('/products/<int:id>', methods=['DELETE'])
@token_required
def delete_product(current_user, id):
    product = Product.query.get_or_404(id)
    db.session.delete(product)
    db.session.commit()
    return jsonify({'message': 'Product deleted successfully!'})

if __name__ == '_main_':
    with app.app_context():
        db.create_all()
    app.run(debug=True)