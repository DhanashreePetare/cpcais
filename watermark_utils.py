import base64
import hashlib
import re
import io
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.colors import Color

_ZERO_WIDTH_CHARS = ["\u200b", "\u200c"]
_ZW_BIT_0 = "\u200b"
_ZW_BIT_1 = "\u200c"
_ZW_START = "\u200b\u200b\u200b\u200b"
_ZW_END = "\u200c\u200c\u200c\u200c"
_VISIBLE_WM_PREFIX = "CENTER"


def _normalize_text_watermark(watermark_text):
    return str(watermark_text or '').strip()


def _normalize_text_for_matching(text_blob):
    text = str(text_blob or '')
    text = text.replace(_ZW_START, '').replace(_ZW_END, '')
    for char in _ZERO_WIDTH_CHARS:
        text = text.replace(char, '')
    return re.sub(r"\s+", " ", text).strip()


def _encode_hidden_payload(payload):
    payload_text = str(payload or '').strip()
    if not payload_text:
        return ''
    payload_bytes = payload_text.encode('utf-8')
    bit_string = ''.join(f"{byte:08b}" for byte in payload_bytes)
    encoded_bits = ''.join(_ZW_BIT_1 if bit == '1' else _ZW_BIT_0 for bit in bit_string)
    return f"{_ZW_START}{encoded_bits}{_ZW_END}"


def _decode_hidden_payload(text_blob):
    text = str(text_blob or '')
    pattern = re.compile(
        re.escape(_ZW_START) + r"([\u200b\u200c]+)" + re.escape(_ZW_END)
    )
    for match in pattern.finditer(text):
        bits = ''.join('1' if char == _ZW_BIT_1 else '0' for char in match.group(1))
        if len(bits) % 8 != 0:
            continue
        payload = bytearray()
        for index in range(0, len(bits), 8):
            payload.append(int(bits[index:index + 8], 2))
        try:
            decoded = payload.decode('utf-8').strip()
            if decoded:
                return decoded
        except UnicodeDecodeError:
            continue
    return None


def build_hidden_payload(watermark_text):
    return _build_hidden_payload(watermark_text)


def decode_hidden_payload(text_blob):
    return _decode_hidden_payload(text_blob)


def extract_hidden_marker(text_blob):
    if not text_blob:
        return None
    match = re.search(r"ZW:([A-Za-z0-9=;:_-]+)", str(text_blob))
    return match.group(1) if match else None


def build_hidden_payload(watermark_text):
    return _build_hidden_payload(watermark_text)


def decode_hidden_payload(text_blob):
    return _decode_hidden_payload(text_blob)


def _build_hidden_payload(watermark_text):
    normalized = _normalize_text_for_matching(watermark_text)
    if not normalized:
        return ''

    center_match = re.search(r"CENTER:\s*(\d+)", normalized, re.IGNORECASE)
    code_match = re.search(r"(BS1:\d+:[A-Za-z0-9_-]+)", normalized)
    center_value = center_match.group(1) if center_match else "NA"
    tag_source = code_match.group(1) if code_match else normalized
    short_tag = hashlib.sha256(tag_source.encode('utf-8')).hexdigest()[:10].upper()
    return f"CID={center_value};TAG={short_tag}"


def _obfuscate_text_watermark(watermark_text):
    """Hide watermark text using zero-width separators so it looks like ordinary text."""
    normalized = _normalize_text_watermark(watermark_text)
    if not normalized:
        return normalized

    obfuscated = []
    separator_index = 0
    for char in normalized:
        obfuscated.append(char)
        if char.isalnum():
            obfuscated.append(_ZERO_WIDTH_CHARS[separator_index % len(_ZERO_WIDTH_CHARS)])
            separator_index += 1
    return ''.join(obfuscated)


def _build_scattered_watermark_snippets(watermark_text, count=4):
    hidden_payload = _build_hidden_payload(watermark_text)
    encoded_hidden_payload = _encode_hidden_payload(hidden_payload)
    if not encoded_hidden_payload:
        return []
    total = max(int(count), 1)
    return [encoded_hidden_payload for _ in range(total)]


def extract_watermark_from_text_blob(text_blob):
    """Extract watermark data from copied text or a PDF text layer."""
    if not text_blob:
        return None

    hidden_payload = _decode_hidden_payload(text_blob)
    if hidden_payload:
        center_match = re.search(r"CID=(\d+)", hidden_payload)
        tag_match = re.search(r"TAG=([A-Z0-9]+)", hidden_payload)
        if center_match and tag_match:
            return f"CENTER: {center_match.group(1)} | CODE: TAG:{tag_match.group(1)}"
        if center_match:
            return f"CENTER: {center_match.group(1)}"

    text = _normalize_text_for_matching(text_blob)
    full_match = re.search(
        r"(CENTER:\s*\d+\s*\|\s*CODE:\s*BS1:\d+:[A-Za-z0-9_-]+)",
        text,
        re.IGNORECASE,
    )
    if full_match:
        return full_match.group(1)

    code = extract_boneh_shaw_code(text)
    center_id = extract_center_id_from_watermark(text)
    if center_id is not None and code:
        return f"CENTER: {center_id} | CODE: {code}"
    if center_id is not None:
        return f"CENTER: {center_id}"
    if code:
        return code
    return None

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
    match = re.search(r"(BS1:\d+:[A-Za-z0-9_-]+)", _normalize_text_for_matching(watermark_text))
    return match.group(1) if match else None


def extract_center_id_from_watermark(watermark_text):
    """Extract a cleartext center id if present in the watermark text."""
    if not watermark_text:
        return None
    match = re.search(r"CENTER:\s*(\d+)", _normalize_text_for_matching(watermark_text), re.IGNORECASE)
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
    Embed INVISIBLE watermark text into multiple spots on each page and PDF metadata.
    """
    input_pdf = PdfReader(io.BytesIO(pdf_bytes))
    output_pdf = PdfWriter()
    existing_metadata = getattr(input_pdf, "metadata", None) or {}
    snippets = _build_scattered_watermark_snippets(watermark_text, count=4)
    
    for page in input_pdf.pages:
        # Get original page size
        mediabox = page.mediabox
        width = float(mediabox.width)
        height = float(mediabox.height)
        
        # Create invisible watermark PDF layer
        packet = io.BytesIO()
        can = canvas.Canvas(packet, pagesize=(width, height))
        
        # --- THE INVISIBLE PART ---
        # Use invisible text render mode so zero-width glyphs do not display as boxes.
        can.setFillColor(Color(0, 0, 0, alpha=0.0))
        can.setFont("Helvetica", 1)
        
        # Scatter the same watermark across the page so copied text preserves the trace.
        scatter_positions = [
            (10, 10),
            (width * 0.25, 10),
            (10, height * 0.35),
            (width * 0.55, height * 0.70),
        ]
        for snippet, (x, y) in zip(snippets, scatter_positions):
            text_obj = can.beginText(float(x), float(y))
            text_obj.setFont("Helvetica", 1)
            text_obj.setTextRenderMode(3)
            text_obj.textOut(snippet)
            can.drawText(text_obj)

        # Add a tiny white marker so copy/paste keeps a readable payload.
        hidden_payload = _build_hidden_payload(watermark_text)
        if hidden_payload:
            can.setFillColor(Color(1, 1, 1))
            marker_obj = can.beginText(2, 2)
            marker_obj.setFont("Helvetica", 1)
            marker_obj.textOut(f"ZW:{hidden_payload}")
            can.drawText(marker_obj)
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
        '/WatermarkText': watermark_text,
        '/Producer': 'Secure Distribution System v1.0',
        '/Author': 'Exam Administration'
    })

    output_stream = io.BytesIO()
    output_pdf.write(output_stream)
    return output_stream.getvalue()


def build_visible_watermark_label(center_name, issued_at):
    safe_center = str(center_name or 'CENTER').strip().upper()
    safe_ts = str(issued_at or '').strip()
    return f"{_VISIBLE_WM_PREFIX} {safe_center} - {safe_ts}" if safe_ts else f"{_VISIBLE_WM_PREFIX} {safe_center}"


def add_visible_watermark(pdf_bytes, watermark_label, opacity=0.6):
    """
    Bake a very visible watermark onto every page using direct PDF text.
    """
    input_pdf = PdfReader(io.BytesIO(pdf_bytes))
    output_pdf = PdfWriter()

    label_text = str(watermark_label or '').strip()
    alpha = int(max(0.0, min(float(opacity), 1.0)) * 255)
    if ' - ' in label_text:
        center_name, timestamp = label_text.split(' - ', 1)
        watermark_line = f"{center_name.strip()}   {timestamp.strip()}"
    else:
        watermark_line = label_text or 'CENTER'

    for page in input_pdf.pages:
        mediabox = page.mediabox
        width = float(mediabox.width)
        height = float(mediabox.height)

        # --- Build overlay PDF page with the watermark text ---
        packet = io.BytesIO()
        can = canvas.Canvas(packet, pagesize=(width, height))

        # Strong, visible banner at the top.
        can.setFillColor(Color(0.1, 0.1, 0.1))
        can.rect(0, height - 55, width, 55, fill=1, stroke=0)
        can.setFillColor(Color(1, 1, 1))
        can.setFont("Helvetica-Bold", 24)
        can.drawString(20, height - 38, watermark_line)

        # Large centered watermark.
        can.setFillColor(Color(0.65, 0.0, 0.0))
        can.setFont("Helvetica-Bold", 60)
        can.drawCentredString(width / 2, height / 2, watermark_line)

        # Diagonal repeat for extra visibility.
        can.setFillColor(Color(0.45, 0.0, 0.0))
        can.setFont("Helvetica", 32)
        can.saveState()
        can.translate(width / 2, height / 2)
        can.rotate(35)
        for y_pos in range(-600, 600, 120):
            can.drawCentredString(0, y_pos, watermark_line)
        can.restoreState()

        can.save()

        # --- Merge watermark overlay on top of original page ---
        packet.seek(0)
        wm_page = PdfReader(packet).pages[0]

        # Flatten original page first
        flat_writer = PdfWriter()
        flat_writer.add_page(page)
        flat_buf = io.BytesIO()
        flat_writer.write(flat_buf)
        flat_buf.seek(0)
        clean_page = PdfReader(flat_buf).pages[0]

        # Merge: watermark image goes on top of the clean page
        clean_page.merge_page(wm_page)
        output_pdf.add_page(clean_page)

    output_stream = io.BytesIO()
    output_pdf.write(output_stream)
    return output_stream.getvalue()


def extract_visible_watermark_from_text(text_blob):
    """Extract a visible watermark label from OCR or copied text."""
    if not text_blob:
        return None
    text = _normalize_text_for_matching(text_blob)
    match = re.search(rf"{_VISIBLE_WM_PREFIX}\s+([A-Z0-9_-]+)\s*-\s*(.+)?", text)
    if match:
        center_name = match.group(1).strip()
        ts = (match.group(2) or '').strip()
        return build_visible_watermark_label(center_name, ts)
    return None

def extract_watermark_text(pdf_bytes):
    """
    Extract the invisible watermark from PDF metadata or text layer.
    """
    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
        # Access the metadata dictionary
        metadata = reader.metadata
        if metadata and '/Fingerprint' in metadata:
            return metadata['/Fingerprint']
        if metadata and '/WatermarkText' in metadata:
            return metadata['/WatermarkText']

        extracted_text = []
        for page in reader.pages:
            try:
                page_text = page.extract_text() or ''
            except Exception:
                page_text = ''
            if page_text:
                extracted_text.append(page_text)
                found = extract_watermark_from_text_blob(page_text)
                if found:
                    return found

        combined_text = '\n'.join(extracted_text)
        found = extract_watermark_from_text_blob(combined_text)
        if found:
            return found

        return "No fingerprint found in metadata or extracted text."
    except Exception as e:
        return f"Extraction failed: {str(e)}"