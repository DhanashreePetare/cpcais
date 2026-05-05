"""End-to-end diagnostic: trace exactly where the visible watermark gets lost."""
import sys, os, io, base64
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reportlab.pdfgen import canvas as rl_canvas
from reportlab.lib.pagesizes import A4
from PyPDF2 import PdfReader

from watermark_utils import (
    generate_boneh_shaw_fingerprint,
    build_visible_watermark_label,
    add_visible_watermark,
    embed_watermark_text,
    build_hidden_payload,
)
from crypto_utils import (
    generate_aes_key, encrypt_file_data, decrypt_file_data,
    generate_rsa_keypair, wrap_aes_key, unwrap_aes_key,
    sign_data, verify_signature,
)
from datetime import datetime

OUT_DIR = os.path.dirname(os.path.abspath(__file__))

def save_pdf(data, name):
    path = os.path.join(OUT_DIR, name)
    with open(path, 'wb') as f:
        f.write(data)
    print(f"  -> Saved: {name} ({len(data)} bytes)")
    return path

def check_pdf_text(data, label):
    try:
        reader = PdfReader(io.BytesIO(data))
        text = reader.pages[0].extract_text() or ''
        has_center = 'CENTER' in text.upper()
        print(f"  -> {label}: starts_with_PDF={data[:5]}, text_has_CENTER={has_center}, text_len={len(text)}")
        if has_center:
            # Find the watermark line
            for line in text.split('\n'):
                if 'CENTER' in line.upper():
                    print(f"     Found: {line[:80]}")
    except Exception as e:
        print(f"  -> {label}: ERROR reading PDF: {e}")

# ===============================================
# Step 1: Create a sample PDF
# ===============================================
print("\n=== STEP 1: Create sample PDF ===")
buf = io.BytesIO()
c = rl_canvas.Canvas(buf, pagesize=A4)
c.setFont("Helvetica", 14)
c.drawString(72, 750, "CONFIDENTIAL EXAM - Mathematics Paper 1")
c.drawString(72, 720, "Question 1: What is 2 + 2?")
c.save()
raw_pdf = buf.getvalue()
save_pdf(raw_pdf, "e2e_1_raw.pdf")
print(f"  Starts with %PDF: {raw_pdf.lstrip()[:5]}")

# ===============================================
# Step 2: Apply watermark (admin.py upload flow)
# ===============================================
print("\n=== STEP 2: Admin upload watermark flow ===")
center_id = 5
filename = "exam_paper.pdf"

is_pdf = raw_pdf.lstrip().startswith(b'%PDF')
print(f"  Is PDF: {is_pdf}")

fingerprint = generate_boneh_shaw_fingerprint(center_id, filename)
watermark_text = f"CENTER: {center_id} | CODE: {fingerprint}"
print(f"  Watermark text: {watermark_text}")

visible_label = build_visible_watermark_label(f"CENTER-{center_id}", datetime.utcnow().strftime('%Y-%m-%d %I:%M %p'))
print(f"  Visible label: {visible_label}")

# Apply visible watermark FIRST (like admin.py)
step2a = add_visible_watermark(raw_pdf, visible_label)
save_pdf(step2a, "e2e_2a_after_visible_wm.pdf")
check_pdf_text(step2a, "After visible WM")

# Apply invisible watermark (like admin.py)
step2b = embed_watermark_text(step2a, watermark_text)
save_pdf(step2b, "e2e_2b_after_both_wm.pdf")
check_pdf_text(step2b, "After both WMs")

# ===============================================
# Step 3: Encrypt (admin.py)
# ===============================================
print("\n=== STEP 3: Encrypt ===")
priv_pem, pub_pem = generate_rsa_keypair()
aes_key = generate_aes_key()
encrypted_data = encrypt_file_data(step2b, aes_key)
wrapped_key = wrap_aes_key(aes_key, pub_pem)
signature = sign_data(encrypted_data, priv_pem)
print(f"  Encrypted size: {len(encrypted_data)}")

# ===============================================
# Step 4: Decrypt (center.py)
# ===============================================
print("\n=== STEP 4: Decrypt ===")
# Verify signature
is_valid = verify_signature(encrypted_data, signature, pub_pem)
print(f"  Signature valid: {is_valid}")

# Unwrap AES key
recovered_key = unwrap_aes_key(wrapped_key, priv_pem)
print(f"  AES key matches: {recovered_key == aes_key}")

# Decrypt
decrypted_data = decrypt_file_data(encrypted_data, recovered_key)
save_pdf(decrypted_data, "e2e_4_decrypted.pdf")
check_pdf_text(decrypted_data, "After decrypt")
print(f"  Decrypted == step2b: {decrypted_data == step2b}")

# ===============================================
# Step 5: Re-watermark (center.py decrypt flow)
# ===============================================
print("\n=== STEP 5: Re-watermark in center.py decrypt ===")
watermark2 = generate_boneh_shaw_fingerprint(center_id, filename)
visible_label2 = build_visible_watermark_label(f"CENTER-{center_id}", datetime.utcnow().strftime('%Y-%m-%d %I:%M %p'))
print(f"  Visible label 2: {visible_label2}")

try:
    step5a = add_visible_watermark(decrypted_data, visible_label2)
    save_pdf(step5a, "e2e_5a_re_visible_wm.pdf")
    check_pdf_text(step5a, "After re-visible WM")
except Exception as e:
    print(f"  ERROR in add_visible_watermark: {e}")
    step5a = decrypted_data

try:
    step5b = embed_watermark_text(step5a, f"CENTER: {center_id} | CODE: {watermark2}")
    save_pdf(step5b, "e2e_5b_final.pdf")
    check_pdf_text(step5b, "Final output")
except Exception as e:
    print(f"  ERROR in embed_watermark_text: {e}")
    step5b = step5a

# ===============================================
# Step 6: Simulate what center.html does (base64 decode)
# ===============================================
print("\n=== STEP 6: Simulate browser download ===")
b64_payload = base64.b64encode(step5b).decode('utf-8')
decoded = base64.b64decode(b64_payload)
save_pdf(decoded, "e2e_6_browser_download.pdf")
print(f"  b64 roundtrip matches: {decoded == step5b}")
check_pdf_text(decoded, "Browser download")

print("\n=== DONE ===")
print("Open the e2e_*.pdf files in your PDF viewer to check which step loses the watermark.")
