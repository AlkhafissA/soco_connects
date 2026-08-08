import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import timedelta
from flask import Flask, render_template
from flask_migrate import Migrate
from config import Config
from app.extensions import db, mail, login_manager
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()

def create_app(config_class=Config):
    app = Flask(__name__)
    # 🛡️ Sécurités de cookies chargées depuis config.py :
    app.config.from_object(config_class)

    # Durée de vie de la session
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

    # Initialisation des extensions
    db.init_app(app)
    migrate = Migrate(app, db, render_as_batch=True)
    mail.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'
    login_manager.login_message = "Votre session a expiré. Veuillez vous reconnecter."
    login_manager.login_message_category = "info"

    csrf.init_app(app)

    # --- CONFIGURATION DU FICHIER LOG ---
    if not app.debug:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        
        file_handler = RotatingFileHandler('logs/mcat_errors.log', maxBytes=102400, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.info('Démarrage du système MCAT - Surveillance active')

    # Enregistrement du Blueprint
    from app.routes import main as main_bp
    app.register_blueprint(main_bp)

    # --- GESTIONNAIRES D'ERREURS ---
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback() # Annule les transactions BDD en cours en cas de crash
        return render_template('errors/500.html'), 500
    
    @app.errorhandler(413)
    def file_too_large(error):
        return render_template('errors/413.html'), 413
    
    # --- INITIALISATION BASE DE DONNÉES ---
    with app.app_context():
        from app import models 
        from sqlalchemy.exc import ProgrammingError, OperationalError
        
        # 🛡️ SÉCURITÉ : On ne force la création des tables que si on est en développement (debug)
        if app.debug:
            db.create_all()
        
        from werkzeug.security import generate_password_hash
        
        # Récupération depuis le .env (Fail-Fast)
        admin_pass = os.environ.get('ADMIN_DEFAULT_PASSWORD')
        superadmin_pass = os.environ.get('SUPERADMIN_DEFAULT_PASSWORD')
        
        if not admin_pass or not superadmin_pass:
            raise ValueError(
                "ERREUR CRITIQUE : Les variables d'environnement ADMIN_DEFAULT_PASSWORD "
                "et SUPERADMIN_DEFAULT_PASSWORD doivent être définies dans le fichier .env"
            )

        # Try...except pour éviter un crash si les tables n'existent pas encore
        try:
            # Création du compte Admin si absent
            if not models.User.query.filter_by(username='Admin').first():
                hashed_admin = generate_password_hash(admin_pass, method='pbkdf2:sha256')
                db.session.add(models.User(
                    username='Admin',
                    email=os.environ.get('ADMIN_EMAIL', 'admin@sococim.sn'),
                    password_hash=hashed_admin,
                    role='admin'
                ))
            
            
        except (ProgrammingError, OperationalError):
            # Les tables ne sont pas encore créées
            pass

    return app

@login_manager.user_loader
def load_user(user_id):
    from app.models import User
    return db.session.get(User, int(user_id))
