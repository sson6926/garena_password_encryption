from flask import Flask, request, jsonify
import hashlib
from Crypto.Cipher import AES

app = Flask(__name__)

def generate_decryption_key(password_md5, v1, v2):
    intermediate_hash = hashlib.sha256((password_md5 + v1).encode()).hexdigest()
    decryption_key = hashlib.sha256((intermediate_hash + v2).encode()).hexdigest()
    return decryption_key

def encrypt_aes_256_ecb(plaintext, key):
    cipher = AES.new(bytes.fromhex(key), AES.MODE_ECB)
    plaintext_bytes = bytes.fromhex(plaintext)
    padding_length = 16 - len(plaintext_bytes) % 16
    plaintext_bytes += bytes([padding_length]) * padding_length
    chiper_raw = cipher.encrypt(plaintext_bytes)
    return chiper_raw.hex()[:32]

@app.route('/encrypt', methods=['GET'])
def encrypt():
    password = request.args.get('password')
    v1 = request.args.get('v1')
    v2 = request.args.get('v2')

    if not all([password, v1, v2]):
        return jsonify({"error": "Missing required parameters"}), 400

    password_md5 = hashlib.md5(password.encode()).hexdigest()
    decryption_key = generate_decryption_key(password_md5, v1, v2)
    encrypted_password = encrypt_aes_256_ecb(password_md5, decryption_key)
    
    return jsonify({"encrypted_password": encrypted_password})

if __name__ == '__main__':
    app.run(debug=True)
