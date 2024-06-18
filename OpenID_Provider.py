
# server side :

from flask import Flask, request, jsonify
import uuid

app = Flask(__name__)

@app.route('/openid/authenticate', methods=['GET'])
def authenticate():
    username = request.args.get('username')
    password = request.args.get('password')
    # Mock authentication logic
    if username == 'user@example.com' and password == 'password123':
        # Generate a session ID
        session_id = str(uuid.uuid4())
        print("Session initiated for user:", username)
        print("Session ID:", session_id)
        return jsonify({"identity_token": "mock_identity_token", "session_id": session_id})
    else:
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/openid/token', methods=['POST'])
def token():
    identity_token = request.form.get('identity_token')
    # Mock token issuance logic
    if identity_token == 'mock_identity_token':
        return jsonify({"access_token": "mock_access_token"})
    else:
        return jsonify({"error": "Invalid token"}), 401

@app.route('/rp/resource', methods=['GET'])
def resource():
    access_token = request.headers.get('Authorization').split('Bearer ')[1]
    # Mock resource access logic
    if access_token == 'mock_access_token':
        return jsonify({"user_id": 123, "username": "user@example.com"})
    else:
        return jsonify({"error": "Unauthorized"}), 403

if __name__ == '__main__':
    app.run(debug=True)
