import os
import uuid
import base64
import re
from datetime import datetime
from flask import Blueprint, request, jsonify, current_app
from werkzeug.utils import secure_filename
from models import db, User, Paper, AuditLog
from auth import token_required
from crypto_utils import generate_aes_key, encrypt_file_data, wrap_aes_key, sign_data
from cryptography.hazmat.primitives import hashes

# --- IMPORT THE WATERMARK UTILS ---
from watermark_utils import (
    generate_boneh_shaw_fingerprint,
    embed_watermark_text,
    extract_watermark_text,
    extract_boneh_shaw_code,
    extract_center_id_from_watermark,
    identify_boneh_shaw_center,
)

admin_bp = Blueprint('admin', __name__)


def _extract_paper_id_from_details(details):
    if not details:
        return None
    match = re.search(r"paper_id=(\d+)", str(details))
    return int(match.group(1)) if match else None

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


@admin_bp.route('/dashboard', methods=['GET'])
@token_required(role='admin')
def dashboard(current_user):
    admin_logs = AuditLog.query.filter_by(user_id=current_user.id).order_by(AuditLog.timestamp.desc()).all()
    recent_logs = admin_logs[:15]

    upload_logs = [log for log in admin_logs if log.action == 'encrypt']
    upload_entries = []
    seen_paper_ids = set()
    for log in upload_logs:
        paper_id = _extract_paper_id_from_details(log.details)
        if paper_id is None or paper_id in seen_paper_ids:
            continue
        paper = Paper.query.get(paper_id)
        if not paper:
            continue
        seen_paper_ids.add(paper_id)
        upload_entries.append({
            'paper_id': paper.id,
            'center_id': paper.center_id,
            'filename': paper.filename,
            'release_time': paper.release_time.isoformat() if paper.release_time else None,
            'created_at': paper.created_at.isoformat() if paper.created_at else None,
            'status': 'released' if paper.release_time and paper.release_time <= datetime.utcnow() else 'pending',
        })
        if len(upload_entries) >= 10:
            break

    suspicious_actions = [
        'forensic_mismatch',
        'signature_failed',
        'unauthorized_download',
        'early_download_blocked',
        'missing_encrypted_file',
    ]
    suspicious_count = AuditLog.query.filter(
        AuditLog.user_id == current_user.id,
        AuditLog.action.in_(suspicious_actions)
    ).count()

    return jsonify({
        'summary': {
            'admin_id': current_user.id,
            'total_actions': len(admin_logs),
            'total_uploads': len(upload_entries),
            'total_encrypt_actions': len(upload_logs),
            'suspicious_events': suspicious_count,
        },
        'recent_logs': [
            {
                'id': log.id,
                'user_id': log.user_id,
                'action': log.action,
                'timestamp': log.timestamp.isoformat() if log.timestamp else None,
                'details': log.details,
            }
            for log in recent_logs
        ],
        'recent_uploads': upload_entries,
        'recent_papers': upload_entries,
    })


@admin_bp.route('/forensics/inspect', methods=['POST'])
@token_required(role='admin')
def inspect_watermark(current_user):
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    if not file or not file.filename:
        return jsonify({'error': 'No file selected'}), 400

    paper_id_raw = request.form.get('paper_id')
    paper_context = None
    paper = None
    if paper_id_raw:
        try:
            paper = Paper.query.get(int(paper_id_raw))
        except (TypeError, ValueError):
            return jsonify({'error': 'paper_id must be an integer'}), 400
        if not paper:
            return jsonify({'error': 'Paper not found'}), 404
        paper_context = paper.filename

    pdf_bytes = file.read()
    watermark_text = extract_watermark_text(pdf_bytes)
    extracted_code = extract_boneh_shaw_code(watermark_text)
    cleartext_center_id = extract_center_id_from_watermark(watermark_text)
    inferred_center_id = identify_boneh_shaw_center(watermark_text, paper_context) if paper_context else None
    notes = []
    if paper_context is None:
        notes.append('No paper_id was supplied, so the code could not be matched against the database.')
    if cleartext_center_id is None:
        notes.append('The uploaded PDF does not contain a cleartext CENTER field. This usually means you inspected the decrypted output copy, which preserves only the Boneh-Shaw forensic code.')
    if extracted_code:
        notes.append('A Boneh-Shaw code was found in the watermark metadata.')

    if inferred_center_id is not None and paper and inferred_center_id != paper.center_id:
        db.session.add(AuditLog(
            user_id=current_user.id,
            action='forensic_mismatch',
            details=f"paper_id={paper.id}; extracted_center_id={inferred_center_id}; expected_center_id={paper.center_id}"
        ))
        db.session.commit()

    return jsonify({
        'paper_id': paper.id if paper else None,
        'paper_context': paper_context,
        'watermark_text': watermark_text,
        'fingerprint_code': extracted_code,
        'cleartext_center_id': cleartext_center_id,
        'inferred_center_id': inferred_center_id,
        'matched': (
            inferred_center_id == paper.center_id if paper and inferred_center_id is not None else None
        ),
        'notes': notes,
    })


@admin_bp.route('/papers/<int:paper_id>/timeline', methods=['GET'])
@token_required(role='admin')
def paper_timeline(current_user, paper_id):
    paper = Paper.query.get(paper_id)
    if not paper:
        return jsonify({'error': 'Paper not found'}), 404

    events = AuditLog.query.filter(
        AuditLog.details.like(f"%paper_id={paper_id}%")
    ).order_by(AuditLog.timestamp.asc()).all()

    now = datetime.utcnow()
    timeline = []
    timeline.append({
        'action': 'created',
        'timestamp': paper.created_at.isoformat() if paper.created_at else None,
        'details': f'center_id={paper.center_id}; filename={paper.filename}',
    })
    timeline.append({
        'action': 'release_scheduled',
        'timestamp': paper.release_time.isoformat() if paper.release_time else None,
        'details': 'Release time configured',
    })
    timeline.extend([
        {
            'action': event.action,
            'timestamp': event.timestamp.isoformat() if event.timestamp else None,
            'details': event.details,
        }
        for event in events
    ])

    return jsonify({
        'paper': {
            'id': paper.id,
            'filename': paper.filename,
            'center_id': paper.center_id,
            'release_time': paper.release_time.isoformat() if paper.release_time else None,
            'created_at': paper.created_at.isoformat() if paper.created_at else None,
            'status': 'released' if paper.release_time <= now else 'pending',
            'encrypted_file_present': os.path.exists(paper.file_path),
        },
        'timeline': timeline,
    })