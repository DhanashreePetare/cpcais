import os
from flask import Flask, jsonify
from flask_cors import CORS
from config import Config
from models import db

def create_app(config_class=Config):
    app = Flask(__name__)
    CORS(app)
    app.config.from_object(config_class)

    # Initialize extensions
    db.init_app(app)
    
    # Ensure upload folder exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Register Blueprints
    # To be imported locally to avoid circular dependencies if any
    from auth import auth_bp
    from admin import admin_bp
    from center import center_bp

    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(center_bp, url_prefix='/center')

    @app.route('/')
    def index():
        return jsonify({"status": "Secure Question Paper Distribution API is running"}), 200

    @app.errorhandler(413)
    def request_entity_too_large(error):
        return jsonify({'error': 'File too large. Max 16MB.'}), 413
        
    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({'error': 'Forbidden.'}), 403
        
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Not found.'}), 404

    from werkzeug.exceptions import HTTPException
    
    # Global error handler for generic uncaught exceptions (for testing convenience)
    @app.errorhandler(Exception)
    def handle_exception(e):
        if isinstance(e, HTTPException):
            return jsonify({'error': e.description}), e.code
        return jsonify({'error': str(e)}), 500

    return app

if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        db.create_all()
    app.run(debug=False, use_reloader=False, port=5000)
