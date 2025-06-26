from flask import Flask
from backend.routes import bp as main_routes
import os
from dotenv import load_dotenv

def create_app():
    # Load environment variables from .env
    load_dotenv()

    # Compute absolute path to your frontend folder
    base_dir = os.path.abspath(os.path.dirname(__file__))
    templates_path = os.path.abspath(os.path.join(base_dir, '../frontend'))

    # Tell Flask to look in frontend/ for templates
    app = Flask(__name__, template_folder=templates_path)

    app.config['MONGO_URI'] = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
    app.register_blueprint(main_routes)
    return app
