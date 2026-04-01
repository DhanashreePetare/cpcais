import os
import io
import base64
from datetime import datetime
from flask import Blueprint, request, jsonify, current_app, send_file
from models import db, User, Paper, AuditLog
from auth import token_required
from crypto_utils import unwrap_aes_key, decrypt_file_data, verify_signature
from watermark_utils import generate_boneh_shaw_fingerprint, embed_watermark_text

center_bp = Blueprint('center', __name__)

@center_bp.route('/download/<int:paper_id>', methods=['GET'])
@token_required(role='center')
def download_paper(current_user, paper_id):
    paper = Paper.query.get(paper_id)
    if not paper:
        return jsonify({'error': 'Paper not found'}), 404
        
    if paper.center_id != current_user.id:
        return jsonify({'error': 'Forbidden: Not your paper'}), 403
        
    if datetime.utcnow() < paper.release_time:
        return jsonify({'error': 'Not yet released'}), 403
        
    if not os.path.exists(paper.file_path):
        return jsonify({'error': 'Encrypted file missing from disk'}), 500
        
    with open(paper.file_path, 'rb') as f:
        encrypted_data = f.read()
        
    return jsonify({
        'paper_id': paper.id,
        'filename': paper.filename,
        'wrapped_aes_key': base64.b64encode(paper.wrapped_aes_key).decode('utf-8'),
        'signature': base64.b64encode(paper.signature).decode('utf-8'),
        'encrypted_blob': base64.b64encode(encrypted_data).decode('utf-8')
    })

@center_bp.route('/decrypt', methods=['POST'])
def decrypt_paper():
    """
    Stateless utility endpoint to decrypt paper given the necessary keys.
    In a real system, the center decrypts offline locally.
    We simulate this here by passing payload to server.
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Missing JSON payload'}), 400
        
    encrypted_blob_b64 = data.get('encrypted_blob')
    wrapped_aes_key_b64 = data.get('wrapped_aes_key')
    signature_b64 = data.get('signature')
    center_private_key_pem = data.get('center_private_key')
    admin_public_key_pem = data.get('admin_public_key')
    
    if not all([encrypted_blob_b64, wrapped_aes_key_b64, signature_b64, center_private_key_pem, admin_public_key_pem]):
        return jsonify({'error': 'Missing arguments'}), 400
        
    try:
        encrypted_blob = base64.b64decode(encrypted_blob_b64)
        wrapped_aes_key = base64.b64decode(wrapped_aes_key_b64)
        signature = base64.b64decode(signature_b64)
        center_priv_pem = center_private_key_pem.encode('utf-8')
        admin_pub_pem = admin_public_key_pem.encode('utf-8')
    except Exception as e:
        return jsonify({'error': 'Decoding error: ' + str(e)}), 400
        
    # 1. Verify Signature
    is_valid = verify_signature(encrypted_blob, signature, admin_pub_pem)
    if not is_valid:
        return jsonify({'error': 'Signature verification failed'}), 400
        
    # 2. Unwrap AES key
    try:
        aes_key = unwrap_aes_key(wrapped_aes_key, center_priv_pem)
    except Exception as e:
        return jsonify({'error': 'Failed to unwrap AES key. Wrong center private key?'}), 400
        
    # 3. Decrypt PDF data
    try:
        decrypted_data = decrypt_file_data(encrypted_blob, aes_key)
    except Exception as e:
        return jsonify({'error': 'Failed to decrypt file data'}), 400

    # Embed visible Boneh-Shaw watermark (center_id, paper_id)
    # Always use paper_id from request or fallback to DB
    paper_id = data.get('paper_id')
    if not paper_id:
        return jsonify({'error': 'Missing paper_id for auditing'}), 400

    try:
        paper_id = int(paper_id)
    except (TypeError, ValueError):
        return jsonify({'error': 'paper_id must be an integer'}), 400

    paper = Paper.query.get(paper_id)
    if not paper:
        return jsonify({'error': 'Paper not found'}), 404

    center_id = paper.center_id
    watermark = generate_boneh_shaw_fingerprint(center_id, str(paper_id))
    try:
        decrypted_data = embed_watermark_text(decrypted_data, f"WATERMARK:{watermark}")
    except Exception as e:
        print("[Watermarking Error]", e)

    # Return as a file download 
    db.session.add(AuditLog(
        user_id=center_id,
        action='decrypt',
        details=f"paper_id={paper_id}; filename={paper.filename}"
    ))
    db.session.commit()

    return send_file(
        io.BytesIO(decrypted_data),
        mimetype='application/pdf',
        as_attachment=True,
        download_name='decrypted_paper.pdf'
    )
