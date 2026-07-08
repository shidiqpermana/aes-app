from flask import Flask, request, jsonify, render_template_string, send_from_directory
from aes_core import aes_encrypt, aes_decrypt
import os, json

app = Flask(__name__)

HTML_PATH = os.path.join(os.path.dirname(__file__), 'index.html')

@app.route('/')
def index():
    with open(HTML_PATH, 'r', encoding='utf-8') as f:
        return f.read()

@app.route('/api/process', methods=['POST'])
def process():
    data = request.json
    mode = data.get('mode', 'encrypt')
    plaintext_input = data.get('plaintext', '').strip()
    key_hex = data.get('key', '').strip().lower()
    
    # Validate key
    if len(key_hex) != 32 or not all(c in '0123456789abcdef' for c in key_hex):
        return jsonify({"error": "Kunci harus tepat 32 karakter hex (128-bit)"}), 400
    
    key_bytes = bytes.fromhex(key_hex)
    
    if mode == 'encrypt':
        # Input: text (max 16 chars) or 32 char hex
        if len(plaintext_input) == 32 and all(c in '0123456789abcdefABCDEF' for c in plaintext_input):
            pt_bytes = bytes.fromhex(plaintext_input)
        else:
            if len(plaintext_input) > 16:
                return jsonify({"error": "Plaintext teks maks. 16 karakter (atau 32 karakter hex)"}), 400
            pt_bytes = plaintext_input.encode('utf-8').ljust(16, b'\x00')
        
        pt_hex = pt_bytes.hex()
        ciphertext_hex, steps = aes_encrypt(pt_bytes, key_bytes)
        return jsonify({
            "mode": "encrypt",
            "input_hex": pt_hex,
            "output_hex": ciphertext_hex,
            "steps": steps
        })
    
    else:  # decrypt
        ct_input = plaintext_input
        if len(ct_input) != 32 or not all(c in '0123456789abcdefABCDEF' for c in ct_input):
            return jsonify({"error": "Ciphertext untuk dekripsi harus 32 karakter hex"}), 400
        
        ct_bytes = bytes.fromhex(ct_input)
        plaintext_hex, plaintext_str, steps = aes_decrypt(ct_bytes, key_bytes)
        return jsonify({
            "mode": "decrypt",
            "input_hex": ct_input.lower(),
            "output_hex": plaintext_hex,
            "output_text": plaintext_str,
            "steps": steps
        })

if __name__ == '__main__':
    app.run(debug=True, port=5000)
