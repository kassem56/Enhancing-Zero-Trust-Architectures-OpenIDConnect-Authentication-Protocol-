import datetime
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
import uuid

app = Flask(__name__)

# Maintain a dictionary to store session IDs and corresponding nonces
session_nonces = {}

@app.route('/openid/authenticate', methods=['GET'])
def authenticate():
    username = request.args.get('username')
    password = request.args.get('password')
    # Mock authentication logic
    if username == 'kassem' and password == 'k56':
        # Generate a session ID
        session_id = str(uuid.uuid4())
        print("Enhancement Step: The end user's credentials are validated.")
        print("Session initiated for user:", username)
        print("Session ID:", session_id)

        # Generate and store a nonce for the session
        nonce = str(uuid.uuid4())
        session_nonces[session_id] = nonce

        # Encrypt nonce
        cipher = AES.new(b'password for AES is Kassem', AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(nonce.encode())

        # Generate expiration time for the identity token
        expiration_time = datetime.utcnow() + datetime.timedelta(seconds=15)

        # Return identity token with expiration time
        identity_token = {
            "sub": username,
            "exp": expiration_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "session_id": session_id,
            "nonce": nonce
        }

        return jsonify({"identity_token": identity_token})
    else:
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/rp/resource', methods=['GET'])
def access_resource():
    nonce = request.args.get('nonce')
    tag = request.args.get('tag')
    ciphertext = bytes.fromhex(nonce)
    tag = bytes.fromhex(tag)
    
    # Decrypt nonce using shared secret key
    cipher = AES.new(b'password for AES is Kassem', AES.MODE_EAX, nonce=b'nonce')
    try:
        decrypted_nonce = cipher.decrypt_and_verify(ciphertext, tag)
        decrypted_nonce = decrypted_nonce.decode()
        # Compare decrypted nonce with stored nonce
        if nonce == decrypted_nonce:
            print("Enhancement Step: Nonce verification successful.")
            print("Great! Nonce is the same! We will provide you the resources.")
            # Mock resource access logic
            return jsonify({"user_id": 123, "kkd5384": "kassem@rit.com"})
        else:
            print("Sorry, wrong nonce!")
            return jsonify({"error": "Wrong nonce"}), 401
    except ValueError:
        print("Decryption failed!")
        return jsonify({"error": "Decryption failed"}), 401

if __name__ == '__main__':
    app.run(debug=True)
