import base64
import hashlib
import re
import io
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.colors import Color

def _deterministic_column_permutation(length, context):
    """Create a deterministic permutation for column scrambling (paper-specific)."""
    decorated = []
    for idx in range(length):
        digest = hashlib.sha256(f"{context}:{idx}".encode("utf-8")).digest()
        decorated.append((digest, idx))
    decorated.sort()
    return [idx for _, idx in decorated]


def _boneh_shaw_codeword(center_index, total_centers=128, repeat=6, context="default"):
    """
    Generate a Boneh-Shaw style binary codeword for one center.

    Construction:
    - Start from the monotone base matrix with (n-1) columns.
    - Repeat each column `repeat` times.
    - Apply a deterministic context-based column permutation.
    """
    n = max(int(total_centers), 2)
    i = int(center_index) % n

    base_bits = []
    for j in range(1, n):
        # In the base matrix, center i gets a 1 when i >= j, else 0.
        base_bits.append(1 if i >= j else 0)

    expanded = []
    for bit in base_bits:
        expanded.extend([bit] * max(int(repeat), 1))

    perm = _deterministic_column_permutation(len(expanded), context)
    return [expanded[p] for p in perm]


def _bits_to_compact_code(bits, prefix="BS1"):
    """Pack bits and encode as URL-safe Base64 for compact watermark text."""
    bit_count = len(bits)
    packed = bytearray((bit_count + 7) // 8)
    for idx, bit in enumerate(bits):
        if bit:
            packed[idx // 8] |= 1 << (7 - (idx % 8))
    payload = base64.urlsafe_b64encode(bytes(packed)).decode("ascii").rstrip("=")
    return f"{prefix}:{bit_count}:{payload}"


def generate_boneh_shaw_fingerprint(center_id, paper_id, length=16):
    """
    Generate a deterministic Boneh-Shaw style fingerprint code.

    The `length` argument is accepted for backward compatibility but the final
    size is derived from `total_centers * repeat` in the code construction.
    """
    _ = length  # Backward-compatible unused argument
    context = f"paper={paper_id}"
    bits = _boneh_shaw_codeword(center_index=int(center_id), total_centers=128, repeat=6, context=context)
    return _bits_to_compact_code(bits)


def extract_boneh_shaw_code(watermark_text):
    """Extract the compact Boneh-Shaw code from watermark text."""
    if not watermark_text:
        return None
    match = re.search(r"(BS1:\d+:[A-Za-z0-9_-]+)", str(watermark_text))
    return match.group(1) if match else None


def extract_center_id_from_watermark(watermark_text):
    """Extract a cleartext center id if present in the watermark text."""
    if not watermark_text:
        return None
    match = re.search(r"CENTER:\s*(\d+)", str(watermark_text), re.IGNORECASE)
    return int(match.group(1)) if match else None


def identify_boneh_shaw_center(watermark_text, paper_context, max_centers=128, repeat=6):
    """Brute-force the Boneh-Shaw fingerprint to identify the most likely center."""
    code = extract_boneh_shaw_code(watermark_text)
    if not code:
        return None

    for center_id in range(1, int(max_centers) + 1):
        candidate = generate_boneh_shaw_fingerprint(center_id, paper_context)
        if candidate == code:
            return center_id
    return None

def embed_watermark_text(pdf_bytes, watermark_text):
    """
    Embed INVISIBLE watermark text into each page and PDF metadata.
    """
    input_pdf = PdfReader(io.BytesIO(pdf_bytes))
    output_pdf = PdfWriter()
    existing_metadata = getattr(input_pdf, "metadata", None) or {}
    
    for page in input_pdf.pages:
        # Get original page size
        mediabox = page.mediabox
        width = float(mediabox.width)
        height = float(mediabox.height)
        
        # Create invisible watermark PDF layer
        packet = io.BytesIO()
        can = canvas.Canvas(packet, pagesize=(width, height))
        
        # --- THE INVISIBLE PART ---
        # Set alpha to 0.0 makes the text completely transparent
        can.setFillColor(Color(0, 0, 0, alpha=0.0)) 
        can.setFont("Helvetica", 1) # Tiny font size
        
        # Draw the string at a specific coordinate
        can.drawString(10, 10, watermark_text)
        can.save()
        
        packet.seek(0)
        watermark_layer = PdfReader(packet)
        
        # Merge the invisible layer onto the original page
        page.merge_page(watermark_layer.pages[0])
        output_pdf.add_page(page)

    # --- METADATA STEGANOGRAPHY ---
    # Add the fingerprint to the internal PDF dictionary
    merged_fingerprint = watermark_text
    previous_fingerprint = existing_metadata.get('/Fingerprint') if isinstance(existing_metadata, dict) else None
    if previous_fingerprint and previous_fingerprint != watermark_text:
        merged_fingerprint = f"{previous_fingerprint} || {watermark_text}"

    output_pdf.add_metadata({
        '/Fingerprint': merged_fingerprint,
        '/Producer': 'Secure Distribution System v1.0',
        '/Author': 'Exam Administration'
    })

    output_stream = io.BytesIO()
    output_pdf.write(output_stream)
    return output_stream.getvalue()

def extract_watermark_text(pdf_bytes):
    """
    Extract the invisible watermark from PDF metadata.
    """
    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
        # Access the metadata dictionary
        metadata = reader.metadata
        if metadata and '/Fingerprint' in metadata:
            return metadata['/Fingerprint']
        return "No fingerprint found in metadata."
    except Exception as e:
        return f"Extraction failed: {str(e)}"