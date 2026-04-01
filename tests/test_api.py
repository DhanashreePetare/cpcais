import os
import io
import json
from datetime import datetime, timedelta

def test_auth_flow(client):
    # Register Admin
    resp = client.post('/auth/register', json={
        'username': 'admin1',
        'email': 'admin1@test.com',
        'password': 'password123',
        'role': 'admin'
    })
    assert resp.status_code == 201
    assert 'private_key' not in resp.json # Should not return for admin

    # Register Center
    resp = client.post('/auth/register', json={
        'username': 'center1',
        'email': 'center1@test.com',
        'password': 'password123',
        'role': 'center'
    })
    assert resp.status_code == 201
    center_id = resp.json['id']
    center_priv_key = resp.json['private_key']
    assert center_priv_key is not None

    # Login Admin
    resp = client.post('/auth/login', json={'username': 'admin1', 'password': 'password123'})
    assert resp.status_code == 200
    admin_token = resp.json['token']

    # Login Center
    resp = client.post('/auth/login', json={'username': 'center1', 'password': 'password123'})
    assert resp.status_code == 200
    center_token = resp.json['token']

    # Check Me
    resp = client.get('/auth/me', headers={'Authorization': f'Bearer {admin_token}'})
    assert resp.status_code == 200
    assert resp.json['username'] == 'admin1'
    admin_pub_key = resp.json['public_key']
    
    return admin_token, center_token, center_id, center_priv_key, admin_pub_key

def test_upload_download_decrypt_flow(client):
    # 1. Setup Auth
    admin_token, center_token, center_id, center_priv_key, admin_pub_key = test_auth_flow(client)
    
    # 2. Upload Paper (Admin)
    future_time = (datetime.utcnow() - timedelta(minutes=5)).isoformat() # Past time for testing
    
    test_pdf_content = b"This is a dummy PDF file content."
    data = {
        'center_id': center_id,
        'release_time': future_time,
        'file': (io.BytesIO(test_pdf_content), 'dummy_paper.pdf')
    }
    
    resp = client.post('/admin/upload', data=data, content_type='multipart/form-data',
                       headers={'Authorization': f'Bearer {admin_token}'})
    
    assert resp.status_code == 201
    paper_id = resp.json['paper_id']
    
    # 3. Download Paper (Center)
    resp = client.get(f'/center/download/{paper_id}', headers={'Authorization': f'Bearer {center_token}'})
    assert resp.status_code == 200
    
    download_data = resp.json
    
    # 4. Decrypt Paper
    decrypt_payload = {
        'encrypted_blob': download_data['encrypted_blob'],
        'wrapped_aes_key': download_data['wrapped_aes_key'],
        'signature': download_data['signature'],
        'center_private_key': center_priv_key,
        'admin_public_key': admin_pub_key
    }
    
    resp = client.post('/center/decrypt', json=decrypt_payload)
    assert resp.status_code == 200
    assert resp.data == test_pdf_content

def test_time_lock(client):
    # Setup Auth
    admin_token, center_token, center_id, center_priv_key, admin_pub_key = test_auth_flow(client)
    
    # Upload Paper (Future release time)
    future_time = (datetime.utcnow() + timedelta(hours=1)).isoformat()
    
    data = {
        'center_id': center_id,
        'release_time': future_time,
        'file': (io.BytesIO(b"test"), 'test.txt')
    }
    
    resp = client.post('/admin/upload', data=data, content_type='multipart/form-data',
                       headers={'Authorization': f'Bearer {admin_token}'})
    assert resp.status_code == 201
    paper_id = resp.json['paper_id']
    
    # Try Download - should fail due to time block
    resp = client.get(f'/center/download/{paper_id}', headers={'Authorization': f'Bearer {center_token}'})
    assert resp.status_code == 403
    assert 'Not yet released' in resp.json['error']
