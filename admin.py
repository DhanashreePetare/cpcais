import os
import uuid
import base64
from datetime import datetime
from flask import Blueprint, request, jsonify, current_app
from werkzeug.utils import secure_filename
from models import db, User, Paper, AuditLog
from auth import token_required
from crypto_utils import generate_aes_key, encrypt_file_data, wrap_aes_key, sign_data
from cryptography.hazmat.primitives import hashes

# --- IMPORT THE WATERMARK UTILS ---
from watermark_utils import generate_boneh_shaw_fingerprint, embed_watermark_text

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/upload', methods=['POST'])
@token_required(role='admin')
def upload_paper(current_user):
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
        
    file = request.files['file']
    center_id = request.form.get('center_id')
    release_time_str = request.form.get('release_time')
    
    if not file or not file.filename:
        return jsonify({'error': 'No file selected'}), 400
    if not center_id or not release_time_str:
        return jsonify({'error': 'Missing center_id or release_time'}), 400
        
    try:
        release_time = datetime.fromisoformat(release_time_str)
    except ValueError:
        return jsonify({'error': 'Invalid datetime format. Use ISO format.'}), 400
        
    center = User.query.filter_by(id=center_id, role='center').first()
    if not center:
        return jsonify({'error': 'Center not found or invalid target'}), 400
        
    if not current_user.private_key:
        return jsonify({'error': 'Admin private key missing, cannot sign.'}), 500

    # Read PDF data
    file_data = file.read()
    
    # --- STEP: APPLY WATERMARK BEFORE ENCRYPTION ---
    try:
        # 1. Generate the unique fingerprint for this center/paper
        fingerprint = generate_boneh_shaw_fingerprint(center_id, file.filename)
        watermark_text = f"CENTER: {center_id} | CODE: {fingerprint}"
        
        # 2. Embed the watermark into the PDF bytes
        file_data = embed_watermark_text(file_data, watermark_text)
        print(f"Watermark applied: {watermark_text}")
    except Exception as e:
        print(f"Watermarking error: {e}")
        return jsonify({'error': 'Failed to apply watermark to PDF'}), 500
    # ----------------------------------------------
    
    # 3. Generate AES-256 key
    aes_key = generate_aes_key()
    
    # 4. Encrypt the NOW-WATERMARKED PDF data with AES
    encrypted_data = encrypt_file_data(file_data, aes_key)
    
    # 5. Wrap AES key with Center's Public Key
    center_public_key = center.public_key.encode('utf-8')
    wrapped_key = wrap_aes_key(aes_key, center_public_key)
    
    # 6. Sign encrypted file with Admin's Private Key
    admin_private_key = current_user.private_key.encode('utf-8')
    signature = sign_data(encrypted_data, admin_private_key)

    digest = hashes.Hash(hashes.SHA256())
    digest.update(encrypted_data)
    encrypted_hash_hex = digest.finalize().hex()
    
    # Save to disk
    filename = secure_filename(file.filename)
    unique_id = str(uuid.uuid4())
    save_filename = f"{unique_id}_{filename}.enc"
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], save_filename)
    
    with open(file_path, 'wb') as f:
        f.write(encrypted_data)
        
    # Save to DB
    new_paper = Paper(
        center_id=center.id,
        release_time=release_time,
        filename=filename,
        file_path=file_path,
        wrapped_aes_key=wrapped_key,
        signature=signature
    )
    
    db.session.add(new_paper)
    db.session.flush()

    db.session.add(AuditLog(
        user_id=current_user.id,
        action='encrypt',
        details=f"paper_id={new_paper.id}; center_id={center.id}; filename={filename}"
    ))
    db.session.add(AuditLog(
        user_id=current_user.id,
        action='hash',
        details=f"paper_id={new_paper.id}; sha256={encrypted_hash_hex}"
    ))

    db.session.commit()

    return jsonify({
        'message': 'Paper watermarked and encrypted successfully.',
        'paper_id': new_paper.id,
        'aes_key_b64': base64.b64encode(aes_key).decode(),
        'encrypted_aes_key_b64': base64.b64encode(wrapped_key).decode(),
        'encrypted_paper_b64': base64.b64encode(encrypted_data).decode(),
        'encrypted_paper_sha256': encrypted_hash_hex,
    }), 201