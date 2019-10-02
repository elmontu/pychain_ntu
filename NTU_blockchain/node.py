from flask import Flask, jsonify, request, send_from_directory, make_response
from flask_cors import CORS
from wallet import Wallet
from blockchain import Blockchain
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps


app = Flask(__name__)
CORS(app)

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Make.db'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_key = db.Column(db.String(), unique=True)
    private_key = db.Column(db.String(), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)
    """ Creates a database table with the following arguments:
    id = numerical index
    public key = address of user
    private key = for signing of transaction and block
    name = name of the user
    password = password in a hashed format
    admin = extra rights.
    """

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_key=data['public_key']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/user', methods=['POST'])
@token_required
def create_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    wallet.create_keys()
    new_user = User(public_key = wallet.public_key, private_key = wallet.private_key, name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    #added persistence for the wallet. Tied to the user's acc
    return jsonify({'message' : 'New user created!'})

@app.route('/user', methods=['GET'])
@token_required
def get_all_users():
    users = User.query.all()
    output = []
    for user in users:
        user_data = {}
        user_data['public_key'] = user.public_key
        user_data['private_key'] = user.private_key
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)
    return jsonify({'users' : output})

@app.route('/user/<public_key>', methods=['PUT'])
@token_required
def promote_user(current_user, public_key):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_key = public_key).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message' : 'The user has been promoted!'})

@app.route('/user/<public_key>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_key):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_key=public_key).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message' : 'The user has been deleted!'})

@app.route('/login') #using get in postman
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_key' : user.public_key, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        #pass the public key and private keys to the session
        if wallet.load_keys(user.public_key, user.private_key):
            global blockchain
            blockchain = Blockchain(wallet.public_key, port)
            response = {
                'message':'User wallet loaded',
                'public_key': wallet.public_key,
                'token': token.decode('UTF-8')

            }
            return jsonify(response), 201

        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

@app.route('/', methods=['GET'])
def get_node_ui():
    return send_from_directory('ui', 'node.html')


@app.route('/network', methods=['GET'])
def get_network_ui():
    return send_from_directory('ui', 'network.html')


@app.route('/balance', methods=['GET'])
def get_balance():
    balance = blockchain.get_balance()
    if balance != None:
        response = {
            'message': 'Fetched balance successfully.',
            'funds': balance
        }
        return jsonify(response), 200
    else:
        response = {
            'messsage': 'Loading balance failed.',
            'wallet_set_up': wallet.public_key != None
        }
        return jsonify(response), 500


@app.route('/broadcast-transaction', methods=['POST'])
def broadcast_transaction():
    values = request.get_json()
    if not values:
        response = {'message': 'No data found.'}
        return jsonify(response), 400
    required = ['sender', 'recipient', 'amount', 'signature']
    if not all(key in values for key in required):
        response = {'message': 'Some data is missing.'}
        return jsonify(response), 400
    success = blockchain.add_transaction(
        values['recipient'], values['sender'], values['signature'], values['amount'], is_receiving=True)
    if success:
        response = {
            'message': 'Successfully added transaction.',
            'transaction': {
                'sender': values['sender'],
                'recipient': values['recipient'],
                'amount': values['amount'],
                'signature': values['signature']
            }
        }
        return jsonify(response), 201
    else:
        response = {
            'message': 'Creating a transaction failed.'
        }
        return jsonify(response), 500


@app.route('/broadcast-block', methods=['POST'])
def broadcast_block():
    values = request.get_json()
    if not values:
        response = {'message': 'No data found.'}
        return jsonify(response), 400
    if 'block' not in values:
        response = {'message': 'Some data is missing.'}
        return jsonify(response), 400
    block = values['block']
    if block['index'] == blockchain.chain[-1].index + 1:
        if blockchain.add_block(block):
            response = {'message': 'Block added'}
            return jsonify(response), 201
        else:
            response = {'message': 'Block seems invalid.'}
            return jsonify(response), 409
    elif block['index'] > blockchain.chain[-1].index:
        response = {'message': 'Blockchain seems to differ from local blockchain.'}
        blockchain.resolve_conflicts = True
        return jsonify(response), 200
    else: 
        response = {'message': 'Blockchain seems to be shorter, block not added'}
        return jsonify(response), 409

@app.route('/transaction', methods=['POST'])
@token_required
def add_transaction(current_user):
    if wallet.public_key == None:
        response = {
            'message': 'No wallet set up.'
        }
        return jsonify(response), 400
    values = request.get_json()
    if not values:
        response = {
            'message': 'No data found.'
        }
        return jsonify(response), 400
    required_fields = ['recipient','productID', 'amount']
    if not all(field in values for field in required_fields):
        response = {
            'message': 'Required data is missing.'
        }
        return jsonify(response), 400
    recipient = values['recipient']
    productID = values['productID']
    amount = values['amount']
    signature = wallet.sign_transaction(wallet.public_key, recipient, productID, amount)
    success = blockchain.add_transaction(
        recipient, wallet.public_key, signature, productID, amount)
    if success:
        response = {
            'message': 'Successfully added transaction.',
            'transaction': {
                'sender': wallet.public_key,
                'recipient': recipient,
                'productID' : productID,
                'amount': amount,
                'signature': signature
            },
            'funds': blockchain.get_balance()
        }
        return jsonify(response), 201
    else:
        response = {
            'message': 'Creating a transaction failed.'
        }
        return jsonify(response), 500

@app.route('/createitem', methods=['POST'])
@token_required
def create_item(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'Administrator permission required!'})

    values = request.get_json()
    if not values:
        response = {
            'message': 'No data found.'
        }
        return jsonify(response), 400
    required_fields = ['recipient','productID', 'amount']
    if not all(field in values for field in required_fields):
        response = {
            'message': 'Required data is missing.'
        }
        return jsonify(response), 400
    recipient = values['recipient']
    productID = values['productID']
    amount = values['amount']
    signature = wallet.sign_transaction(wallet.public_key, recipient, productID, amount)
    success = blockchain.add_transaction2(
        recipient, wallet.public_key, signature, productID, amount)
    if success:
        response = {
            'message': 'Successfully added transaction.',
            'transaction': {
                'sender': wallet.public_key,
                'recipient': recipient,
                'productID' : productID,
                'amount': amount,
                'signature': signature
            },
            'funds': blockchain.get_balance()
        }
        return jsonify(response), 201
    else:
        response = {
            'message': 'Creating a transaction failed.'
        }
        return jsonify(response), 500



@app.route('/mine', methods=['POST'])
@token_required
def mine(current_user):
    if not current_user.admin:
        return jsonify({'message' : 'Administrator permission required!'})

    if blockchain.resolve_conflicts:
        response = {'message': 'Resolve conflicts first, block not added!'}
        return jsonify(response), 409
    block = blockchain.mine_block()
    if block != None:
        dict_block = block.__dict__.copy()
        dict_block['transactions'] = [
            tx.__dict__ for tx in dict_block['transactions']]
        response = {
            'message': 'Block added successfully.',
            'block': dict_block,
        }
        return jsonify(response), 201
    else:
        response = {
            'message': 'Adding a block failed.',
            'wallet_set_up': wallet.public_key != None
        }
        return jsonify(response), 500


@app.route('/resolve-conflicts', methods=['POST'])
def resolve_conflicts():
    replaced = blockchain.resolve()
    if replaced:
        response = {'message': 'Chain was replaced!'}
    else:
        response = {'message': 'Local chain kept!'}
    return jsonify(response), 200


@app.route('/transactions', methods=['GET'])
def get_open_transaction():
    transactions = blockchain.get_open_transactions()
    dict_transactions = [tx.__dict__ for tx in transactions]
    return jsonify(dict_transactions), 200

@app.route('/products', methods=['GET'])
def get_product_txns():
    values = request.get_json()
    if not values:
        response = {
            'message': 'No data attached.'
        }
        return jsonify(response), 400
    if 'productID' not in values:
        response = {
            'message': 'No product data found.'
        }
        return jsonify(response), 400
    productID =values['productID']
    transactions = blockchain.get_product_txn(productID)
    dict_transactions = [tx.__dict__ for tx in transactions]
    return jsonify(dict_transactions), 200


@app.route('/chain', methods=['GET'])
def get_chain():
    chain_snapshot = blockchain.chain
    dict_chain = [block.__dict__.copy() for block in chain_snapshot]
    for dict_block in dict_chain:
        dict_block['transactions'] = [
            tx.__dict__ for tx in dict_block['transactions']]
    return jsonify(dict_chain), 200


@app.route('/node', methods=['POST'])
def add_node():
    values = request.get_json()
    if not values:
        response = {
            'message': 'No data attached.'
        }
        return jsonify(response), 400
    if 'node' not in values:
        response = {
            'message': 'No node data found.'
        }
        return jsonify(response), 400
    node = values['node']
    blockchain.add_peer_node(node)
    response = {
        'message': 'Node added successfully.',
        'all_nodes': blockchain.get_peer_nodes()
    }
    return jsonify(response), 201


@app.route('/node/<node_url>', methods=['DELETE'])
def remove_node(node_url):
    if node_url == '' or node_url == None:
        response = {
            'message': 'No node found.'
        }
        return jsonify(response), 400
    blockchain.remove_peer_node(node_url)
    response = {
        'message': 'Node removed',
        'all_nodes': blockchain.get_peer_nodes()
    }
    return jsonify(response), 200


@app.route('/nodes', methods=['GET'])
def get_nodes():
    nodes = blockchain.get_peer_nodes()
    response = {
        'all_nodes': nodes
    }
    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', type=int, default=5000)
    args = parser.parse_args()
    port = args.port
    wallet = Wallet(port)
    blockchain = Blockchain(wallet.public_key, port)
    app.run(host='0.0.0.0', port=port)
