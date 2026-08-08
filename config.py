import os
from dotenv import load_dotenv

# 1. On définit le dossier de base (racine du projet)
basedir = os.path.abspath(os.path.dirname(__file__))

# 2. On charge le .env qui est au même niveau que ce fichier config.py
load_dotenv(os.path.join(basedir, '.env'))

class Config:
    # ✅ CORRECTION CRITIQUE : SECRET_KEY est OBLIGATOIRE
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
        raise ValueError(
            "ERREUR CRITIQUE : La variable d'environnement 'SECRET_KEY' doit être "
            "définie dans le fichier .env pour la sécurité des sessions Flask"
        )
    
    # 3. PRIORITÉ : On cherche DATABASE_URL dans le .env. 
    # Si c'est vide, ALORS on utilise SQLite (développement).
    database_url = os.environ.get('DATABASE_URL')
    
    # ✅ FIX : Pour PostgreSQL, on s'assure que l'URL commence par postgresql://
    if database_url and database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    
    SQLALCHEMY_DATABASE_URI = database_url or 'sqlite:///' + os.path.join(basedir, 'soco_connect.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Paramètres soco_connect (aussi obligatoires)
    MOT_DE_PASSE_PAR_DEFAUT = os.environ.get('MOT_DE_PASSE_PAR_DEFAUT')
    CLE_DE_VERROUILLAGE = os.environ.get('CLE_DE_VERROUILLAGE')
    
    # ✅ VALIDATION : Ces clés sont importantes pour la sécurité
    if not MOT_DE_PASSE_PAR_DEFAUT or not CLE_DE_VERROUILLAGE:
        raise ValueError(
            "ERREUR CRITIQUE : MOT_DE_PASSE_PAR_DEFAUT et CLE_DE_VERROUILLAGE "
            "doivent être définis dans le .env"
        )

    # 🛡️ NOUVEAU : SÉCURISATION DES COOKIES DE SESSION
    # Empêche le code JavaScript (souvent utilisé par les pirates) de lire le cookie
    SESSION_COOKIE_HTTPONLY = True 
    
    # Empêche le cookie d'être envoyé sur d'autres sites (protège contre les attaques CSRF)
    SESSION_COOKIE_SAMESITE = 'Lax' 
    
    # Note : Si on  mets l'appli en ligne avec HTTPS (cadenas vert), 
    # on décommente la ligne ci-dessous pour obliger le cookie à passer uniquement par une connexion sécurisée.
    # SESSION_COOKIE_SECURE = True
