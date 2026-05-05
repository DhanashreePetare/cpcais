import os
import base64
from datetime import datetime
from flask import Blueprint, request, jsonify, current_app
from models import db, User, Paper, AuditLog
from auth import token_required
from crypto_utils import unwrap_aes_key, decrypt_file_data, verify_signature
from watermark_utils import generate_boneh_shaw_fingerprint, embed_watermark_text

center_bp = Blueprint('center', __name__)


def _get_admin_public_key_for_paper(paper_id):
    encrypt_log = AuditLog.query.filter(
        AuditLog.action == 'encrypt',
        AuditLog.details.like(f"%paper_id={paper_id}%")
    ).order_by(AuditLog.timestamp.asc()).first()
    if not encrypt_log or not encrypt_log.user_id:
        return None

    admin = User.query.get(encrypt_log.user_id)
    if not admin or not admin.public_key:
        return None
    return admin.public_key


@center_bp.route('/assigned-paper', methods=['GET'])
@token_required(role='center')
def assigned_paper(current_user):
    paper = Paper.query.filter_by(center_id=current_user.id).order_by(Paper.created_at.desc()).first()
    if not paper:
        return jsonify({'paper_id': None, 'filename': None, 'release_time': None}), 200

    admin_public_key = _get_admin_public_key_for_paper(paper.id)

    return jsonify({
        'paper_id': paper.id,
        'filename': paper.filename,
        'release_time': paper.release_time.isoformat() if paper.release_time else None,
        'status': 'released' if paper.release_time and datetime.utcnow() >= paper.release_time else 'pending',
        'center_id': paper.center_id,
        'admin_public_key': admin_public_key,
    })

@center_bp.route('/download/<int:paper_id>', methods=['GET'])
@token_required(role='center')
def download_paper(current_user, paper_id):
    paper = Paper.query.get(paper_id)
    if not paper:
        db.session.add(AuditLog(
            user_id=current_user.id,
            action='missing_paper',
            details=f"paper_id={paper_id}; requester_center_id={current_user.id}"
        ))
        db.session.commit()
        return jsonify({'error': 'Paper not found'}), 404
        
    if paper.center_id != current_user.id:
        db.session.add(AuditLog(
            user_id=current_user.id,
            action='unauthorized_download',
            details=f"paper_id={paper_id}; requester_center_id={current_user.id}; assigned_center_id={paper.center_id}"
        ))
        db.session.commit()
        return jsonify({'error': 'Forbidden: Not your paper'}), 403
        
    if datetime.utcnow() < paper.release_time:
        db.session.add(AuditLog(
            user_id=current_user.id,
            action='early_download_blocked',
            details=f"paper_id={paper_id}; requester_center_id={current_user.id}; release_time={paper.release_time.isoformat()}"
        ))
        db.session.commit()
        return jsonify({'error': 'Not yet released'}), 403
        
    if not os.path.exists(paper.file_path):
        db.session.add(AuditLog(
            user_id=current_user.id,
            action='missing_encrypted_file',
            details=f"paper_id={paper_id}; file_path={paper.file_path}"
        ))
        db.session.commit()
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
        print('[Decrypt] Missing JSON payload')
        return jsonify({'error': 'Missing JSON payload'}), 400
        
    encrypted_blob_b64 = data.get('encrypted_blob')
    wrapped_aes_key_b64 = data.get('wrapped_aes_key')
    signature_b64 = data.get('signature')
    center_private_key_pem = data.get('center_private_key')
    admin_public_key_pem = data.get('admin_public_key')
    
    if not all([encrypted_blob_b64, wrapped_aes_key_b64, signature_b64, center_private_key_pem, admin_public_key_pem]):
        print('[Decrypt] Missing arguments')
        return jsonify({'error': 'Missing arguments'}), 400

    paper_id = data.get('paper_id')
    if not paper_id:
        print('[Decrypt] Missing paper_id for auditing')
        return jsonify({'error': 'Missing paper_id for auditing'}), 400

    try:
        paper_id = int(paper_id)
    except (TypeError, ValueError):
        print(f"[Decrypt] Invalid paper_id: {paper_id}")
        return jsonify({'error': 'paper_id must be an integer'}), 400

    paper = Paper.query.get(paper_id)
    if not paper:
        print(f"[Decrypt] Paper not found: paper_id={paper_id}")
        db.session.add(AuditLog(
            user_id=None,
            action='missing_paper',
            details=f"paper_id={paper_id}; decrypt_request=true"
        ))
        db.session.commit()
        return jsonify({'error': 'Paper not found'}), 404
        
    try:
        encrypted_blob = base64.b64decode(encrypted_blob_b64)
        wrapped_aes_key = base64.b64decode(wrapped_aes_key_b64)
        signature = base64.b64decode(signature_b64)
        center_priv_pem = center_private_key_pem.encode('utf-8')
    except Exception as e:
        print(f"[Decrypt] Decoding error: {e}")
        return jsonify({'error': 'Decoding error: ' + str(e)}), 400

    admin_pub_override = _get_admin_public_key_for_paper(paper_id)
    if admin_pub_override:
        admin_pub_pem = admin_pub_override.encode('utf-8')
    elif admin_public_key_pem:
        admin_pub_pem = admin_public_key_pem.encode('utf-8')
    else:
        print(f"[Decrypt] Admin public key missing for paper_id={paper_id}")
        return jsonify({'error': 'Admin public key not available for verification'}), 400
        
    # 1. Verify Signature
    is_valid = verify_signature(encrypted_blob, signature, admin_pub_pem)
    if not is_valid:
        print(f"[Decrypt] Signature verification failed for paper_id={paper_id}")
        db.session.add(AuditLog(
            user_id=paper.center_id,
            action='signature_failed',
            details=f"paper_id={paper_id}; center_id={paper.center_id}"
        ))
        db.session.commit()
        return jsonify({'error': 'Signature verification failed'}), 400
        
    # 2. Unwrap AES key
    try:
        aes_key = unwrap_aes_key(wrapped_aes_key, center_priv_pem)
    except Exception as e:
        print(f"[Decrypt] Failed to unwrap AES key for paper_id={paper_id}: {e}")
        return jsonify({'error': 'Failed to unwrap AES key. Wrong center private key?'}), 400
        
    # 3. Decrypt PDF data
    try:
        decrypted_data = decrypt_file_data(encrypted_blob, aes_key)
    except Exception as e:
        print(f"[Decrypt] Failed to decrypt file data for paper_id={paper_id}: {e}")
        return jsonify({'error': 'Failed to decrypt file data'}), 400

    # Embed visible Boneh-Shaw watermark for the decoded copy.
    center_id = paper.center_id
    watermark = generate_boneh_shaw_fingerprint(center_id, paper.filename)
    try:
        decrypted_data = embed_watermark_text(
            decrypted_data,
            f"CENTER: {center_id} | CODE: {watermark}"
        )
    except Exception as e:
        print("[Watermarking Error]", e)

    # Return as JSON with base64-encoded PDF so frontend can control the download
    db.session.add(AuditLog(
        user_id=center_id,
        action='decrypt',
        details=f"paper_id={paper_id}; filename={paper.filename}"
    ))
    db.session.commit()

    return jsonify({
        'decrypted_pdf_b64': base64.b64encode(decrypted_data).decode('utf-8'),
        'filename': paper.filename or 'decrypted_paper.pdf'
    })
