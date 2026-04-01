import random
import string
import io
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.colors import Color

def generate_boneh_shaw_fingerprint(center_id, paper_id, length=16):
    """
    Generate a simple Boneh-Shaw style fingerprint string for demo purposes.
    """
    random.seed(f"{center_id}-{paper_id}")
    code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
    return code

def embed_watermark_text(pdf_bytes, watermark_text):
    """
    Embed INVISIBLE watermark text into each page and PDF metadata.
    """
    input_pdf = PdfReader(io.BytesIO(pdf_bytes))
    output_pdf = PdfWriter()
    
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
    output_pdf.add_metadata({
        '/Fingerprint': watermark_text,
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