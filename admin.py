import os
import uuid
import base64
import re
from datetime import datetime
from flask import Blueprint, request, jsonify, current_app
from werkzeug.utils import secure_filename
from models import db, User, Paper, AuditLog, WatermarkRecord
from auth import token_required
from crypto_utils import generate_aes_key, encrypt_file_data, wrap_aes_key, sign_data
from cryptography.hazmat.primitives import hashes

# --- IMPORT THE WATERMARK UTILS ---
from watermark_utils import (
    generate_boneh_shaw_fingerprint,
    build_hidden_payload,
    decode_hidden_payload,
    extract_hidden_marker,
    build_visible_watermark_label,
    add_visible_watermark,
    embed_watermark_text,
    extract_watermark_text,
    extract_watermark_from_text_blob,
    extract_visible_watermark_from_text,
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
    watermark_payload = None
    visible_label = None
    try:
        if file_data.lstrip().startswith(b'%PDF'):
            fingerprint = generate_boneh_shaw_fingerprint(center_id, file.filename)
            watermark_text = f"CENTER: {center_id} | CODE: {fingerprint}"
            watermark_payload = build_hidden_payload(watermark_text)

            visible_label = build_visible_watermark_label(center.username, datetime.utcnow().strftime('%Y-%m-%d %I:%M %p'))
            file_data = add_visible_watermark(file_data, visible_label)
            file_data = embed_watermark_text(file_data, watermark_text)
            print(f"Watermark applied: {watermark_text}")
        else:
            print("Watermark skipped: uploaded file is not a PDF payload")
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

    if watermark_payload:
        db.session.add(WatermarkRecord(
            paper_id=new_paper.id,
            center_id=center.id,
            wm_payload=watermark_payload,
            visible_label=visible_label,
        ))

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
    payload = request.get_json(silent=True) or {}
    inspection_mode = payload.get('mode')
    if not inspection_mode and request.form:
        inspection_mode = request.form.get('mode')
    if not inspection_mode:
        inspection_mode = 'text'
    pasted_text = payload.get('text')
    if not pasted_text and request.form:
        pasted_text = request.form.get('text') or request.form.get('forensic_text')
    if not pasted_text:
        raw_body = request.get_data(as_text=True)
        if raw_body and raw_body.strip() and request.content_type and 'text/plain' in request.content_type:
            pasted_text = raw_body.strip()
    if inspection_mode not in ['pdf', 'text', 'photo']:
        inspection_mode = 'text' if pasted_text else 'pdf'

    file = request.files.get('file')
    if inspection_mode == 'pdf' and not file:
        return jsonify({'error': 'No PDF uploaded'}), 400
    if inspection_mode in ['text', 'photo'] and not pasted_text:
        return jsonify({'error': 'No text pasted'}), 400
    if not file and not pasted_text:
        return jsonify({'error': 'No file uploaded or text pasted'}), 400

    paper_id_raw = request.form.get('paper_id') if request.form else None
    if not paper_id_raw:
        paper_id_raw = payload.get('paper_id')

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

    watermark_text = None
    visible_trace = None
    if inspection_mode == 'photo':
        visible_trace = extract_visible_watermark_from_text(pasted_text)
        watermark_text = visible_trace or str(pasted_text).strip() or None
    elif pasted_text:
        watermark_text = extract_watermark_from_text_blob(pasted_text)
        if not watermark_text:
            watermark_text = str(pasted_text).strip() or None
    else:
        pdf_bytes = file.read()
        watermark_text = extract_watermark_text(pdf_bytes)

    hidden_payload = decode_hidden_payload(pasted_text) if pasted_text else None
    if not hidden_payload and watermark_text:
        hidden_payload = decode_hidden_payload(watermark_text)
    if not hidden_payload and pasted_text:
        hidden_payload = extract_hidden_marker(pasted_text)

    hidden_center_id = None
    hidden_tag = None
    if hidden_payload:
        center_match = re.search(r"CID=(\d+)", hidden_payload)
        tag_match = re.search(r"TAG=([A-Z0-9]+)", hidden_payload)
        hidden_center_id = int(center_match.group(1)) if center_match else None
        hidden_tag = tag_match.group(1) if tag_match else None

    extracted_code = extract_boneh_shaw_code(watermark_text)
    cleartext_center_id = extract_center_id_from_watermark(watermark_text)
    inferred_center_id = identify_boneh_shaw_center(watermark_text, paper_context) if paper_context else None
    watermark_present = bool(watermark_text and (extracted_code or cleartext_center_id is not None or hidden_center_id is not None or visible_trace))
    notes = []
    if paper_context is None:
        notes.append('No paper_id was supplied, so the code could not be matched against the database.')
    if cleartext_center_id is None:
        notes.append('The uploaded PDF does not contain a cleartext CENTER field. This usually means you inspected the decrypted output copy, which preserves only the Boneh-Shaw forensic code.')
    if extracted_code:
        notes.append('A Boneh-Shaw code was found in the watermark metadata.')
    if inspection_mode == 'photo' and visible_trace:
        notes.append('Visible watermark text detected from photo/OCR input.')
    if pasted_text and watermark_present:
        notes.append('The pasted text contains a detectable watermark trace.')
    if pasted_text and not watermark_present:
        notes.append('No watermark pattern was detected in the pasted text.')

    display_watermark_text = None
    if inspection_mode == 'pdf' and watermark_text:
        display_watermark_text = watermark_text
    elif watermark_present:
        display_watermark_text = 'Hidden trace detected'

    if inferred_center_id is not None and paper and inferred_center_id != paper.center_id:
        db.session.add(AuditLog(
            user_id=current_user.id,
            action='forensic_mismatch',
            details=f"paper_id={paper.id}; extracted_center_id={inferred_center_id}; expected_center_id={paper.center_id}"
        ))
        db.session.commit()

    record_match = None
    if hidden_payload and not paper:
        record_match = WatermarkRecord.query.filter_by(wm_payload=hidden_payload).order_by(WatermarkRecord.generated_at.desc()).first()
    if cleartext_center_id is not None and not paper and not record_match:
        record_match = WatermarkRecord.query.filter_by(center_id=cleartext_center_id).order_by(WatermarkRecord.generated_at.desc()).first()
    if inferred_center_id is not None and not paper and not record_match:
        record_match = WatermarkRecord.query.filter_by(center_id=inferred_center_id).order_by(WatermarkRecord.generated_at.desc()).first()

    return jsonify({
        'paper_id': paper.id if paper else None,
        'paper_context': paper_context,
        'watermark_text': display_watermark_text,
        'visible_trace': visible_trace,
        'fingerprint_code': extracted_code,
        'hidden_payload': hidden_payload,
        'hidden_center_id': hidden_center_id,
        'hidden_tag': hidden_tag,
        'cleartext_center_id': cleartext_center_id,
        'inferred_center_id': inferred_center_id,
        'record_paper_id': record_match.paper_id if record_match else None,
        'record_center_id': record_match.center_id if record_match else None,
        'record_visible_label': record_match.visible_label if record_match else None,
        'watermark_present': watermark_present,
        'inspection_mode': inspection_mode,
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


@admin_bp.route('/forensics/generate-test-data', methods=['POST'])
@token_required(role='admin')
def generate_test_data(current_user):
    """Generate sample test data for all three forensic leak detection cases."""
    from watermark_utils import (
        _encode_hidden_payload,
        _build_hidden_payload,
        build_visible_watermark_label,
        add_visible_watermark,
        embed_watermark_text,
    )
    from reportlab.pdfgen import canvas as rl_canvas
    import io as _io

    payload = request.get_json(silent=True) or {}
    center_id = payload.get('center_id', 42)
    timestamp_str = datetime.utcnow().strftime('%Y-%m-%d %I:%M %p')

    # --- Build a small real PDF ---
    pdf_buf = _io.BytesIO()
    c = rl_canvas.Canvas(pdf_buf)
    c.setFont("Helvetica", 14)
    c.drawString(72, 750, "Sample Exam Paper — Leak Detection Demo")
    c.drawString(72, 720, "This PDF was generated to test the forensic watermark system.")
    c.drawString(72, 690, f"Target center: {center_id}")
    c.save()
    raw_pdf = pdf_buf.getvalue()

    # Apply watermarks exactly like the upload flow
    fingerprint = generate_boneh_shaw_fingerprint(center_id, 'test_demo.pdf')
    watermark_text = f"CENTER: {center_id} | CODE: {fingerprint}"
    visible_label = build_visible_watermark_label(f"CENTER-{center_id}", timestamp_str)

    watermarked_pdf = add_visible_watermark(raw_pdf, visible_label)
    watermarked_pdf = embed_watermark_text(watermarked_pdf, watermark_text)

    # --- Case 2: build text with zero-width chars embedded ---
    hidden_payload = _build_hidden_payload(watermark_text)
    encoded_zw = _encode_hidden_payload(hidden_payload)
    sample_text = f"Question 1: What is the capital of France?{encoded_zw} Answer: Paris."

    # --- Case 3: simulate OCR visible watermark text ---
    ocr_text = f"CENTER CENTER-{center_id} - {timestamp_str}"

    return jsonify({
        'case1_pdf_b64': base64.b64encode(watermarked_pdf).decode('ascii'),
        'case2_text': sample_text,
        'case2_hidden_payload': hidden_payload,
        'case3_ocr_text': ocr_text,
        'visible_label': visible_label,
        'watermark_text': watermark_text,
        'center_id': center_id,
    })