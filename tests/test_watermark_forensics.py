"""
Tests for watermark-based leak detection — all three forensic cases.

Case 1: Forwarded PDF — zero-width chars in PDF text layer
Case 2: Copied text — zero-width chars survive copy/paste
Case 3: Photo / print — visible watermark text readable from OCR
"""

import io
import json
import base64
from datetime import datetime, timedelta

import pytest
from reportlab.pdfgen import canvas as rl_canvas

# --- Helper: register admin + center, login both, return credentials ---

def setup_users(client):
    """Register admin and center, login, return tokens and keys."""
    # Register admin
    resp = client.post('/auth/register', json={
        'username': 'fadmin',
        'email': 'fadmin@test.com',
        'password': 'pass123',
        'role': 'admin'
    })
    assert resp.status_code == 201
    admin_id = resp.get_json()['id']

    # Register center
    resp = client.post('/auth/register', json={
        'username': 'fcenter',
        'email': 'fcenter@test.com',
        'password': 'pass123',
        'role': 'center'
    })
    assert resp.status_code == 201
    center_data = resp.get_json()
    center_id = center_data['id']
    center_priv_key = center_data['private_key']

    # Login admin
    resp = client.post('/auth/login', json={'username': 'fadmin', 'password': 'pass123'})
    assert resp.status_code == 200
    admin_token = resp.get_json()['token']

    # Login center
    resp = client.post('/auth/login', json={'username': 'fcenter', 'password': 'pass123'})
    assert resp.status_code == 200
    center_token = resp.get_json()['token']

    # Get admin public key
    resp = client.get('/auth/me', headers={'Authorization': f'Bearer {admin_token}'})
    assert resp.status_code == 200
    admin_pub_key = resp.get_json()['public_key']

    return {
        'admin_token': admin_token,
        'admin_id': admin_id,
        'admin_pub_key': admin_pub_key,
        'center_token': center_token,
        'center_id': center_id,
        'center_priv_key': center_priv_key,
    }


def make_real_pdf(text="Sample exam paper content for testing."):
    """Build a small real PDF using reportlab."""
    buf = io.BytesIO()
    c = rl_canvas.Canvas(buf)
    c.setFont("Helvetica", 12)
    c.drawString(72, 750, text)
    c.save()
    return buf.getvalue()


def upload_pdf(client, admin_token, center_id, pdf_bytes, filename='test_paper.pdf'):
    """Upload a PDF through the admin upload endpoint."""
    release_time = (datetime.utcnow() - timedelta(minutes=5)).isoformat()
    data = {
        'center_id': str(center_id),
        'release_time': release_time,
        'file': (io.BytesIO(pdf_bytes), filename)
    }
    resp = client.post(
        '/admin/upload',
        data=data,
        content_type='multipart/form-data',
        headers={'Authorization': f'Bearer {admin_token}'}
    )
    assert resp.status_code == 201, f"Upload failed: {resp.get_json()}"
    return resp.get_json()


def download_and_decrypt(client, center_token, center_priv_key, admin_pub_key, paper_id):
    """Download and decrypt a paper through the center endpoints."""
    # Download
    resp = client.get(
        f'/center/download/{paper_id}',
        headers={'Authorization': f'Bearer {center_token}'}
    )
    assert resp.status_code == 200, f"Download failed: {resp.get_json()}"
    dl = resp.get_json()

    # Decrypt
    resp = client.post('/center/decrypt', json={
        'encrypted_blob': dl['encrypted_blob'],
        'wrapped_aes_key': dl['wrapped_aes_key'],
        'signature': dl['signature'],
        'center_private_key': center_priv_key,
        'admin_public_key': admin_pub_key,
        'paper_id': paper_id,
    })
    assert resp.status_code == 200, f"Decrypt failed: {resp.get_json()}"
    dec = resp.get_json()
    return base64.b64decode(dec['decrypted_pdf_b64'])


# ============================================================================
# UNIT TESTS — watermark_utils functions
# ============================================================================

class TestWatermarkUtils:
    """Direct unit tests for watermark encoding/decoding functions."""

    def test_hidden_payload_roundtrip(self):
        """Encode then decode a hidden payload — must return the original."""
        from watermark_utils import _encode_hidden_payload, _decode_hidden_payload

        original = "CID=42;TAG=ABCDEF1234"
        encoded = _encode_hidden_payload(original)

        # Encoded string should contain zero-width chars and start/end markers
        assert '\u2063' in encoded  # start marker
        assert '\u2064' in encoded  # end marker
        assert '\u200b' in encoded or '\u200c' in encoded  # bit chars

        # Decode must recover original
        decoded = _decode_hidden_payload(encoded)
        assert decoded == original

    def test_hidden_payload_survives_surrounding_text(self):
        """Zero-width chars embedded in regular text are still extractable."""
        from watermark_utils import _encode_hidden_payload, _decode_hidden_payload

        payload = "CID=7;TAG=FF00112233"
        encoded = _encode_hidden_payload(payload)

        # Simulate copy-paste: payload is surrounded by normal text
        text_blob = f"Question 1: What is 2+2?{encoded} The answer is 4."
        decoded = _decode_hidden_payload(text_blob)
        assert decoded == payload

    def test_build_hidden_payload(self):
        """_build_hidden_payload extracts center ID and produces CID=...;TAG=..."""
        from watermark_utils import _build_hidden_payload

        wm = "CENTER: 42 | CODE: BS1:762:abc123"
        result = _build_hidden_payload(wm)
        assert result.startswith("CID=42;TAG=")
        assert len(result) > 10

    def test_extract_watermark_from_text_blob_with_zw(self):
        """Full pipeline: build hidden payload → encode → embed in text → extract."""
        from watermark_utils import (
            _build_hidden_payload,
            _encode_hidden_payload,
            extract_watermark_from_text_blob,
        )

        wm_text = "CENTER: 99 | CODE: BS1:8:testcode"
        hidden = _build_hidden_payload(wm_text)
        encoded = _encode_hidden_payload(hidden)
        blob = f"Some leaked text content{encoded} more text here"

        result = extract_watermark_from_text_blob(blob)
        assert result is not None
        assert '99' in result

    def test_extract_visible_watermark_from_text(self):
        """extract_visible_watermark_from_text recovers center + timestamp."""
        from watermark_utils import extract_visible_watermark_from_text

        ocr = "CENTER CENTER-5 - 2026-05-05 09:30 PM"
        result = extract_visible_watermark_from_text(ocr)
        assert result is not None
        assert 'CENTER-5' in result

    def test_empty_inputs(self):
        """Edge case: empty/None inputs don't crash."""
        from watermark_utils import (
            _encode_hidden_payload,
            _decode_hidden_payload,
            extract_watermark_from_text_blob,
            extract_visible_watermark_from_text,
        )
        assert _encode_hidden_payload('') == ''
        assert _encode_hidden_payload(None) == ''
        assert _decode_hidden_payload('') is None
        assert _decode_hidden_payload(None) is None
        assert extract_watermark_from_text_blob('') is None
        assert extract_watermark_from_text_blob(None) is None
        assert extract_visible_watermark_from_text('') is None
        assert extract_visible_watermark_from_text(None) is None


# ============================================================================
# CASE 1 — Forwarded PDF: inspect the watermarked PDF file
# ============================================================================

class TestCase1ForwardedPdf:
    """Case 1: A watermarked PDF is forwarded digitally.
    Zero-width chars in the text layer encode the center ID."""

    def test_pdf_forensics_detects_watermark(self, client):
        """Upload a real PDF, then inspect it via the forensics endpoint."""
        creds = setup_users(client)

        # Build and upload a real PDF
        pdf_bytes = make_real_pdf("Confidential exam: Mathematics Paper 1")
        upload_result = upload_pdf(client, creds['admin_token'], creds['center_id'], pdf_bytes)
        paper_id = upload_result['paper_id']

        # Download and decrypt (this re-applies watermarks)
        decrypted_pdf = download_and_decrypt(
            client, creds['center_token'], creds['center_priv_key'],
            creds['admin_pub_key'], paper_id
        )

        # Now inspect the decrypted (watermarked) PDF via forensics
        from io import BytesIO
        data = {
            'file': (BytesIO(decrypted_pdf), 'leaked.pdf'),
            'mode': 'pdf',
            'paper_id': str(paper_id),
        }
        resp = client.post(
            '/admin/forensics/inspect',
            data=data,
            content_type='multipart/form-data',
            headers={'Authorization': f'Bearer {creds["admin_token"]}'}
        )

        assert resp.status_code == 200
        result = resp.get_json()
        assert result['watermark_present'] is True
        assert result['inspection_mode'] == 'pdf'
        assert result['watermark_text'] is not None

    def test_generate_test_data_case1(self, client):
        """The generate-test-data endpoint produces a valid watermarked PDF."""
        creds = setup_users(client)

        resp = client.post(
            '/admin/forensics/generate-test-data',
            json={'center_id': 42},
            headers={
                'Authorization': f'Bearer {creds["admin_token"]}',
                'Content-Type': 'application/json'
            }
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'case1_pdf_b64' in data

        # The PDF should be inspectable
        pdf_bytes = base64.b64decode(data['case1_pdf_b64'])
        from io import BytesIO
        inspect_data = {
            'file': (BytesIO(pdf_bytes), 'test_generated.pdf'),
            'mode': 'pdf',
        }
        resp2 = client.post(
            '/admin/forensics/inspect',
            data=inspect_data,
            content_type='multipart/form-data',
            headers={'Authorization': f'Bearer {creds["admin_token"]}'}
        )
        assert resp2.status_code == 200
        result = resp2.get_json()
        assert result['watermark_present'] is True


# ============================================================================
# CASE 2 — Copied text: zero-width chars survive copy/paste
# ============================================================================

class TestCase2CopiedText:
    """Case 2: Text is copied from a leaked PDF.
    Zero-width characters travel with the copied text automatically."""

    def test_pasted_zw_text_detected(self, client):
        """Text with embedded zero-width watermark is detected by forensics."""
        from watermark_utils import _build_hidden_payload, _encode_hidden_payload

        creds = setup_users(client)
        center_id = creds['center_id']

        # Simulate: build watermark text as the upload flow would
        from watermark_utils import generate_boneh_shaw_fingerprint
        fingerprint = generate_boneh_shaw_fingerprint(center_id, 'exam.pdf')
        wm_text = f"CENTER: {center_id} | CODE: {fingerprint}"

        # Encode hidden payload with zero-width chars
        hidden_payload = _build_hidden_payload(wm_text)
        encoded_zw = _encode_hidden_payload(hidden_payload)

        # Simulate pasted text with the hidden watermark embedded
        pasted = f"Question 1: Explain photosynthesis.{encoded_zw} Marks: 10"

        resp = client.post(
            '/admin/forensics/inspect',
            json={'text': pasted, 'mode': 'text'},
            headers={
                'Authorization': f'Bearer {creds["admin_token"]}',
                'Content-Type': 'application/json'
            }
        )

        assert resp.status_code == 200
        result = resp.get_json()
        assert result['watermark_present'] is True
        assert result['inspection_mode'] == 'text'
        assert result['hidden_payload'] is not None
        assert result['hidden_center_id'] == center_id

    def test_pasted_plaintext_watermark_detected(self, client):
        """Plaintext CENTER: X | CODE: BS1:... pattern is also detected."""
        creds = setup_users(client)
        center_id = creds['center_id']

        pasted = f"Some content CENTER: {center_id} | CODE: BS1:8:YWJjaWQ more content"
        resp = client.post(
            '/admin/forensics/inspect',
            json={'text': pasted, 'mode': 'text'},
            headers={
                'Authorization': f'Bearer {creds["admin_token"]}',
                'Content-Type': 'application/json'
            }
        )

        assert resp.status_code == 200
        result = resp.get_json()
        assert result['watermark_present'] is True
        assert result['cleartext_center_id'] == center_id

    def test_generate_test_data_case2(self, client):
        """The generate-test-data endpoint produces valid zero-width text."""
        creds = setup_users(client)

        resp = client.post(
            '/admin/forensics/generate-test-data',
            json={'center_id': 42},
            headers={
                'Authorization': f'Bearer {creds["admin_token"]}',
                'Content-Type': 'application/json'
            }
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'case2_text' in data

        # The text should be detectable by forensics
        resp2 = client.post(
            '/admin/forensics/inspect',
            json={'text': data['case2_text'], 'mode': 'text'},
            headers={
                'Authorization': f'Bearer {creds["admin_token"]}',
                'Content-Type': 'application/json'
            }
        )
        assert resp2.status_code == 200
        result = resp2.get_json()
        assert result['watermark_present'] is True
        assert result['hidden_payload'] is not None


# ============================================================================
# CASE 3 — Photo / printed paper: visible watermark readable from OCR
# ============================================================================

class TestCase3PhotoOcr:
    """Case 3: Paper is printed and photographed.
    Invisible watermark is destroyed. Visible faint diagonal text
    (center name + timestamp) is readable directly from the photo."""

    def test_visible_watermark_detected_from_ocr(self, client):
        """Simulated OCR text containing visible watermark is detected."""
        creds = setup_users(client)

        ocr_text = "CENTER CENTER-5 - 2026-05-05 09:30 PM"
        resp = client.post(
            '/admin/forensics/inspect',
            json={'text': ocr_text, 'mode': 'photo'},
            headers={
                'Authorization': f'Bearer {creds["admin_token"]}',
                'Content-Type': 'application/json'
            }
        )

        assert resp.status_code == 200
        result = resp.get_json()
        assert result['inspection_mode'] == 'photo'
        assert result['visible_trace'] is not None
        assert 'CENTER-5' in result['visible_trace']

    def test_visible_watermark_with_realistic_ocr(self, client):
        """OCR text mixed with exam content still detects the watermark."""
        creds = setup_users(client)

        ocr_text = (
            "Question 1 What is the speed of light\n"
            "CENTER CENTER-12 - 2026-05-01 10:00 AM\n"
            "Answer 3 x 10^8 m/s"
        )
        resp = client.post(
            '/admin/forensics/inspect',
            json={'text': ocr_text, 'mode': 'photo'},
            headers={
                'Authorization': f'Bearer {creds["admin_token"]}',
                'Content-Type': 'application/json'
            }
        )

        assert resp.status_code == 200
        result = resp.get_json()
        assert result['visible_trace'] is not None
        assert 'CENTER-12' in result['visible_trace']

    def test_no_visible_watermark_returns_none(self, client):
        """OCR text without a watermark returns no visible trace."""
        creds = setup_users(client)

        ocr_text = "Just some random exam text without any watermark"
        resp = client.post(
            '/admin/forensics/inspect',
            json={'text': ocr_text, 'mode': 'photo'},
            headers={
                'Authorization': f'Bearer {creds["admin_token"]}',
                'Content-Type': 'application/json'
            }
        )

        assert resp.status_code == 200
        result = resp.get_json()
        assert result['visible_trace'] is None

    def test_generate_test_data_case3(self, client):
        """The generate-test-data endpoint produces valid OCR text."""
        creds = setup_users(client)

        resp = client.post(
            '/admin/forensics/generate-test-data',
            json={'center_id': 42},
            headers={
                'Authorization': f'Bearer {creds["admin_token"]}',
                'Content-Type': 'application/json'
            }
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'case3_ocr_text' in data

        # The OCR text should be detectable by forensics in photo mode
        resp2 = client.post(
            '/admin/forensics/inspect',
            json={'text': data['case3_ocr_text'], 'mode': 'photo'},
            headers={
                'Authorization': f'Bearer {creds["admin_token"]}',
                'Content-Type': 'application/json'
            }
        )
        assert resp2.status_code == 200
        result = resp2.get_json()
        assert result['visible_trace'] is not None
        assert '42' in result['visible_trace'] or 'CENTER-42' in result['visible_trace']
