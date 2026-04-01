import requests
import json
import base64
import os
import time

BASE_URL = "http://127.0.0.1:5000"

def run_demo():
    print("=== Secure Question Paper Distribution API Demo ===\n")
    
    # 1. Check if server is up
    try:
        req = requests.get(f"{BASE_URL}/")
        print(f"Server Status: {req.json()['status']}")
    except requests.exceptions.ConnectionError:
        print("Error: Please make sure the Flask server is running on http://127.0.0.1:5000")
        return

    # --- SETUP: REGISTRATION & LOGIN ---
    
    print("\n1. Registering an Admin User...")
    response = requests.post(f"{BASE_URL}/auth/register", json={
        "username": "superadmin",
        "email": "superadmin@univ.edu",
        "password": "strongpassword",
        "role": "admin"
    })
    
    # If already exists from a previous run, just login
    if response.status_code == 400 and 'already exists' in response.text:
       print("   Admin already exists, skipping registration.")
    else:
       print(f"   Success! status: {response.status_code}")

    print("2. Logging in as Admin to get JWT token...")
    response = requests.post(f"{BASE_URL}/auth/login", json={
        "username": "superadmin",
        "password": "strongpassword"
    })
    
    admin_token = response.json().get('token')
    print(f"   Success! Admin Token acquired (Bearer ...{admin_token[-10:]})")

    # To get Admin's public key (to verify signatures later)
    headers_admin = {"Authorization": f"Bearer {admin_token}"}
    admin_info = requests.get(f"{BASE_URL}/auth/me", headers=headers_admin).json()
    admin_pub_key = admin_info['public_key']


    print("\n3. Registering an Exam Center...")
    response = requests.post(f"{BASE_URL}/auth/register", json={
        "username": "center_alpha",
        "email": "alpha@centers.edu",
        "password": "centerpassword",
        "role": "center"
    })
    
    if response.status_code == 400 and 'already exists' in response.text:
        print("   Center already exists! Let's use a unique name.")
        timestamp = int(time.time())
        response = requests.post(f"{BASE_URL}/auth/register", json={
            "username": f"center_alpha_{timestamp}",
            "email": f"alpha_{timestamp}@centers.edu",
            "password": "centerpassword",
            "role": "center"
        })
        
    res_json = response.json()
    center_id = res_json['id']
    center_priv_key = res_json['private_key']
    
    print(f"   Success! Center ID: {center_id}")
    print("   ** CRITICAL: This is the ONLY time the server will send the Center Private Key. We must save it. **")
    print(f"   (Saving {len(center_priv_key)} bytes of RSA Private Key...)\n")
    
    print("4. Logging in as Exam Center to get JWT token...")
    response = requests.post(f"{BASE_URL}/auth/login", json={
        "username": res_json.get('username', "center_alpha"),  # Handle edge cases
        "password": "centerpassword"
    })
    
    if 'token' not in response.json():
        # Edge case retry
        response = requests.post(f"{BASE_URL}/auth/login", json={
            "username": response.request.body.decode().split('"center_alpha')[1].split('"')[0] if 'center_alpha' in response.request.body.decode() else "center_alpha",
            "password": "centerpassword"
        })
    center_token = response.json().get('token')
    # Because of our unique naming logic above, we can just grab it dynamically
    headers_center = {"Authorization": f"Bearer {center_token}"}
    print(f"   Success! Center Token acquired.")

    # --- UPLOAD PHASE (ADMIN) ---

    print("\n--- Phase 1: Upload (Admin) ---")
    
    # Create a dummy question paper
    with open('dummy_paper.pdf', 'wb') as f:
        f.write(b'This is a top secret 2026 Question Paper payload. Do not read before the exam.')
    
    # Release time in the past to allow immediate download for the demo
    # In reality this would be: "2026-06-01T09:00:00"
    from datetime import datetime
    release_time = datetime.utcnow().isoformat()
    
    print(f"5. Admin uploading 'dummy_paper.pdf' assigned to Center {center_id}...")
    with open('dummy_paper.pdf', 'rb') as f:
        files = {'file': f}
        data = {
            'center_id': center_id,
            'release_time': release_time
        }
        res = requests.post(f"{BASE_URL}/admin/upload", headers=headers_admin, files=files, data=data)
        
    print(f"   Success! Response: {res.json()}")
    paper_id = res.json()['paper_id']


    # --- DOWNLOAD PHASE (CENTER) ---
    print("\n--- Phase 2: Download & Decrypt (Center) ---")
    
    print(f"6. Center requesting Download for Paper ID {paper_id}...")
    res = requests.get(f"{BASE_URL}/center/download/{paper_id}", headers=headers_center)
    
    print(f"   Download Success! Received Encrypted Bundle.")
    payload = res.json()
    
    print("   Summary of downloaded payload:")
    print(f"   - Encrypted Blob Size: {len(payload['encrypted_blob'])} base64 chars")
    print(f"   - Wrapped AES Key Size: {len(payload['wrapped_aes_key'])} base64 chars")
    print(f"   - Signature Size: {len(payload['signature'])} base64 chars")
    
    print("\n7. Center decrypting the paper locally (Simulated via /center/decrypt utility endpoint)...")
    
    decrypt_payload = {
        "encrypted_blob": payload['encrypted_blob'],
        "wrapped_aes_key": payload['wrapped_aes_key'],
        "signature": payload['signature'],
        "center_private_key": center_priv_key,
        "admin_public_key": admin_pub_key
    }
    
    res = requests.post(f"{BASE_URL}/center/decrypt", json=decrypt_payload)
    
    if res.status_code == 200:
        print("\n🎉 SUCCESS: Decrypted Paper Output: 🎉")
        print("-" * 50)
        print(res.content.decode('utf-8'))
        print("-" * 50)
    else:
        print(f"Decryption failed: {res.json()}")
        
    # Cleanup
    if os.path.exists('dummy_paper.pdf'):
        os.remove('dummy_paper.pdf')

if __name__ == '__main__':
    run_demo()
