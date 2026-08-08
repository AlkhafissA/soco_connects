import os
from sqlalchemy import or_
import filetype
from werkzeug.utils import secure_filename
from flask import current_app
from app.forms import EnrolementPrestataireForm, DossierInterventionForm, AjoutIntervenantForm, ModifierIntervenantForm
from app.models import Prestataire, DossierIntervention, Intervenant, DossierIntervenant, RegistreAcces, DemandeAcces, ActionLog, User, LoginAttempt, db
from functools import wraps
from datetime import date, datetime, timezone, timedelta
from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User, LoginAttempt

from app.models import ActionLog # On oublie pas d'importer le modèle !

def enregistrer_log(user_id, action, description):
    """Fonction raccourci pour enregistrer une action dans l'historique"""
    nouveau_log = ActionLog(user_id=user_id, action=action, description=description)
    db.session.add(nouveau_log)
    db.session.commit()

main = Blueprint('main', __name__)

# --- CONFIGURATION SÉCURITÉ ---
MAX_LOGIN_ATTEMPTS = 5
BLOCK_DURATION_MINUTES = 15

# ==========================================
# DÉCORATEUR RBAC (Contrôle d'accès par rôle)
# ==========================================
def role_required(*roles):
    """
    Vérifie si l'utilisateur a le rôle requis pour accéder à la route.
    Le rôle 'SUPERADMIN' a accès à tout par défaut.
    Ex: @role_required('ACHATS', 'HSE')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('main.login'))
            if current_user.role not in roles and current_user.role != 'SUPERADMIN':
                abort(403) # Erreur 403: Accès refusé
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ==========================================
# ROUTE DE CONNEXION (Anti Brute-Force)
# ==========================================
@main.route('/', methods=['GET', 'POST'])
def login():
    
    # Si l'utilisateur est déjà connecté, direction le tableau de bord
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        # Récupération de l'IP du client (gère les proxys)
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        
        # Vérification des tentatives de connexion pour cette IP (Syntaxe SQLAlchemy 2.0)
        attempt = db.session.scalar(db.select(LoginAttempt).filter_by(ip_address=ip_address))
        
        if attempt and attempt.is_blocked:
            # On Vérifie si la durée de blocage est écoulée
            time_passed = datetime.now(timezone.utc) - attempt.last_attempt
            if time_passed < timedelta(minutes=BLOCK_DURATION_MINUTES):
                flash(f'Trop de tentatives. Réessayez dans {BLOCK_DURATION_MINUTES} minutes.', 'danger')
                return render_template('login.html')
            else:
                # Déblocage de l'IP après la durée écoulée
                attempt.is_blocked = False
                attempt.attempts = 0
                db.session.commit()

        username = request.form.get('username')
        password = request.form.get('password')
        
        # Recherche de l'utilisateur
        # NOUVELLE LIGNE (Cherche dans le nom d'utilisateur ET dans l'email) :
        user = db.session.scalar(
            db.select(User).filter((User.username == username) | (User.email == username))
        )
        
        if user and user.check_password(password):
            if not user.is_active:
                flash('Votre compte a été désactivé. Veuillez contacter le support SOCOCIM.', 'warning')
                return render_template('login.html')

            # Connexion réussie via Flask-Login
            login_user(user)

                    # --- INTERCEPTION PREMIÈRE CONNEXION ---
            if getattr(user, 'must_change_password', False):
                return redirect(url_for('main.premiere_connexion'))
            # ---------------------------------------

            # 2. Maintenant que l'utilisateur est connu et connecté, on enregistre l'action
            enregistrer_log(user.id, "CONNEXION", f"L'utilisateur {user.username} s'est connecté au portail.")
            # --------------------------------------------
            
            # Réinitialisation des tentatives pour cette IP
            if attempt:
                attempt.attempts = 0
                attempt.is_blocked = False
                db.session.commit()
            
            flash('Connexion réussie !', 'success')
            
            # Redirection sécurisée (évite la faille "Open Redirect")
            next_page = request.args.get('next')
            if not next_page or not next_page.startswith('/'):
                next_page = url_for('main.dashboard')
            return redirect(next_page)
        
        else:
            # Échec de la connexion : on compte la tentative
            if not attempt:
                attempt = LoginAttempt(ip_address=ip_address, attempts=1, last_attempt=datetime.now(timezone.utc))
                db.session.add(attempt)
            else:
                attempt.attempts += 1
                attempt.last_attempt = datetime.now(timezone.utc)
                if attempt.attempts >= MAX_LOGIN_ATTEMPTS:
                    attempt.is_blocked = True
            db.session.commit()
            
            flash('Identifiants incorrects.', 'danger')
            
    return render_template('login.html')

# ==========================================
# ROUTE TABLEAU DE BORD
# ==========================================
# ==========================================
@main.route('/dashboard')
@login_required
def dashboard():
    # --- VARIABLES COMMUNES POUR LES ALERTES ---
    seuil_alerte = date.today() + timedelta(days=30)
    date_actuelle = date.today()

    # 1. SI C'EST UN PRESTATAIRE
    if current_user.role == 'PRESTATAIRE':
        prestataire = db.session.scalar(db.select(Prestataire).filter_by(user_id=current_user.id))
        
        if not prestataire:
            flash("Bienvenue ! Veuillez d'abord compléter le dossier de votre entreprise.", "info")
            return redirect(url_for('main.enrolement'))
        
        mes_dossiers = db.session.scalars(db.select(DossierIntervention).filter_by(prestataire_id=prestataire.id)).all()
        
        # --- NOUVEAU : ALERTE POUR LE PRESTATAIRE (Filtre par entreprise) ---
        alertes_expiration = db.session.scalars(
            db.select(Intervenant).filter(
                Intervenant.prestataire_id == prestataire.id,
                or_(
                    Intervenant.date_expiration_cni <= seuil_alerte,
                    Intervenant.date_expiration_certificats <= seuil_alerte
                )
            )
        ).all()
        # --------------------------------------------------------------------

        return render_template(
            'dashboard_prestataire.html', 
            prestataire=prestataire, 
            dossiers=mes_dossiers,
            alertes=alertes_expiration,
            date_actuelle=date_actuelle,
            seuil_alerte_30j=seuil_alerte  # <--On transmet bien le seuil
        )

    # 2. SI C'EST LE SERVICE ACHATS (On Récupère TOUS les dossiers pour l'onglet historique)
    elif current_user.role == 'ACHATS':
        dossiers = db.session.scalars(db.select(DossierIntervention).order_by(DossierIntervention.date_creation.desc())).all()
        return render_template('dashboard_achats.html', dossiers=dossiers)

    # 3. SI C'EST LE SERVICE HSE (On Récupère TOUS les dossiers pour l'onglet historique)
    elif current_user.role == 'HSE':
        dossiers = db.session.scalars(db.select(DossierIntervention).order_by(DossierIntervention.date_creation.desc())).all()
        
        # --- NOUVEAU : ALERTE GLOBALE POUR LE HSE (Pas de filtre prestataire) ---
        alertes_expiration = db.session.scalars(
            db.select(Intervenant).filter(
                or_(
                    Intervenant.date_expiration_cni <= seuil_alerte,
                    Intervenant.date_expiration_certificats <= seuil_alerte
                )
            )
        ).all()
        # ------------------------------------------------------------------------

        return render_template(
            'dashboard_hse.html', 
            dossiers=dossiers,
            alertes=alertes_expiration,
            date_actuelle=date_actuelle,
            seuil_alerte_30j=seuil_alerte  # <-- CORRECTION ICI AUSSI
        )

    # 4. SI C'EST L'AGENT DE SÉCURITÉ AU PORTAIL
    elif current_user.role == 'PORTAIL':
        return redirect(url_for('main.dashboard_portail'))

    # 5. ADMIN / SUPERADMIN
    elif current_user.role == 'SUPERADMIN':
        return redirect(url_for('main.dashboard_superadmin'))
    
    else:
        # Sécurité par défaut : si le rôle n'existe pas
        flash("Votre rôle n'est pas reconnu par le système.", "danger")
        return redirect(url_for('main.index'))
    
@main.route('/achats/dossier/<int:dossier_id>', methods=['GET', 'POST'])
@login_required
@role_required('ACHATS')
def dossier_achats(dossier_id):
    dossier = db.session.get(DossierIntervention, dossier_id)
    if not dossier:
        flash("Dossier introuvable.", "danger")
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        action = request.form.get('action')
        commentaire = request.form.get('commentaire', '')

        # Variables pour notre log
        type_action_log = ""
        description_log = ""

        if action == 'valider':
            dossier.statut_achats = 'VALIDE'
            type_action_log = "VALIDATION_ACHATS"
            description_log = f"A validé le dossier administratif de l'entreprise {dossier.entreprise.nom_entreprise}"
            flash(f"Le dossier de {dossier.entreprise.nom_entreprise} a été validé par les Achats.", "success")
        elif action == 'rejeter':
            dossier.statut_achats = 'REJETE'
            type_action_log = "REJET_ACHATS"
            description_log = f"A rejeté le dossier de l'entreprise {dossier.entreprise.nom_entreprise}"
            flash(f"Le dossier de {dossier.entreprise.nom_entreprise} a été rejeté par les Achats.", "warning")

        dossier.commentaire_achats = commentaire
        dossier.date_validation_achats = datetime.now(timezone.utc)
        dossier.valide_par_achats_id = current_user.id
        
        # On sauvegarde les modifications dans la base de données
        db.session.commit()
        
        # --- C'EST ICI QU'ON ENREGISTRE LE LOG ---
        if type_action_log:  # Sécurité : on s'assure qu'une action a bien été choisie
            enregistrer_log(current_user.id, type_action_log, description_log)
        # -----------------------------------------

        return redirect(url_for('main.dashboard'))

    return render_template('dossier_achats.html', dossier=dossier)


@main.route('/hse/dossier/<int:dossier_id>', methods=['GET', 'POST'])
@login_required
@role_required('HSE')
def dossier_hse(dossier_id):
    dossier = db.session.get(DossierIntervention, dossier_id)
    if not dossier:
        flash("Dossier introuvable.", "danger")
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        action = request.form.get('action')
        commentaire = request.form.get('commentaire', '')

        # Variables pour notre log
        type_action_log = ""
        description_log = ""

        if action == 'valider':
            dossier.statut_hse = 'VALIDE'
            type_action_log = "VALIDATION_HSE"
            description_log = f"A validé le dossier sécuritaire de l'entreprise {dossier.entreprise.nom_entreprise}"
            flash(f"Le dossier HSE de {dossier.entreprise.nom_entreprise} a été validé.", "success")
        elif action == 'rejeter':
            dossier.statut_hse = 'REJETE'
            type_action_log = "REJET_HSE"
            description_log = f"A rejeté le dossier sécuritaire de l'entreprise {dossier.entreprise.nom_entreprise}"
            flash(f"Le dossier HSE de {dossier.entreprise.nom_entreprise} a été rejeté.", "warning")

        dossier.commentaire_hse = commentaire
        dossier.date_validation_hse = datetime.now(timezone.utc)
        dossier.valide_par_hse_id = current_user.id
        
        # On sauvegarde les modifications
        db.session.commit()

        # --- C'EST ICI QU'ON ENREGISTRE LE LOG ---
        if type_action_log:
            enregistrer_log(current_user.id, type_action_log, description_log)
        # -----------------------------------------

        return redirect(url_for('main.dashboard'))

    return render_template('dossier_hse.html', dossier=dossier)
        
# ==========================================
# ROUTE DE DÉCONNEXION
# ==========================================
@main.route('/logout')
@login_required
def logout():
    logout_user() # CECI fait proprement le travail de session.clear()
    flash('Vous avez été déconnecté.', 'info')
    return redirect(url_for('main.login'))
    
    
    
# ==========================================
# FONCTION UTILITAIRE : SAUVEGARDE SÉCURISÉE
# ==========================================
def save_secure_file(file_obj, subfolder="documents"):
    """
    Vérifie la signature binaire du fichier et le sauvegarde hors de la zone publique.
    """
    # 1. Vérification des Magic Bytes (Prévention contre l'usurpation d'extension)
    file_bytes = file_obj.read(2048) # Lit les 2 premiers Ko
    file_obj.seek(0) # Remet le curseur au début pour la sauvegarde
    
    kind = filetype.guess(file_bytes)
    if kind is None or kind.mime != 'application/pdf':
        return None # Fichier falsifié ou invalide
        
    # 2. Nettoyage du nom de fichier et unicité
    original_filename = secure_filename(file_obj.filename)
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
    unique_filename = f"{timestamp}_{original_filename}"
    
    # 3. Création du dossier sécurisé (hors du dossier 'static')
    # Les fichiers seront stockés dans app/secure_uploads/...
    upload_path = os.path.join(current_app.root_path, 'secure_uploads', subfolder)
    os.makedirs(upload_path, exist_ok=True)
    
    # 4. Sauvegarde physique
    file_path = os.path.join(upload_path, unique_filename)
    file_obj.save(file_path)
    
    return file_path

import os
from flask import send_file, request, abort

@main.route('/download')
@login_required
def download_file():
    filepath = request.args.get('filepath')
    if not filepath or not os.path.exists(filepath):
        flash("Le fichier demandé est introuvable sur le serveur.", "danger")
        return redirect(request.referrer or url_for('main.dashboard'))
    return send_file(filepath)


# ==========================================
# ROUTE : ENRÔLEMENT DU PRESTATAIRE
# ==========================================
@main.route('/enrolement', methods=['GET', 'POST'])
@login_required
@role_required('PRESTATAIRE')
def enrolement():
    # Vérifie si le prestataire a déjà soumis un dossier
    existing_prestataire = db.session.scalar(
        db.select(Prestataire).filter_by(user_id=current_user.id)
    )
    if existing_prestataire:
        flash("Vous avez déjà soumis votre dossier d'entreprise.", "info")
        return redirect(url_for('main.dashboard'))

    form = EnrolementPrestataireForm()
    
    if form.validate_on_submit():
        path_ninea = save_secure_file(form.fichier_ninea.data, subfolder='ninea')
        path_rc = save_secure_file(form.fichier_rc.data, subfolder='rc')
        
        if not path_ninea or not path_rc:
            flash("Alerte de sécurité : L'un des fichiers n'est pas un PDF valide.", "danger")
            return render_template('enrolement.html', form=form)
        
        nouveau_prestataire = Prestataire(
            user_id=current_user.id,
            nom_entreprise=form.nom_entreprise.data,
            ninea=form.ninea.data,
            registre_commerce=form.registre_commerce.data,
            domaine_activite=form.domaine_activite.data,
            fichier_ninea=path_ninea,
            fichier_rc=path_rc
        )
        
        db.session.add(nouveau_prestataire)
        db.session.commit()

        # --- LOG : Enrôlement ---
        enregistrer_log(current_user.id, "ENROLEMENT_ENTREPRISE", f"A soumis le dossier administratif pour l'entreprise {nouveau_prestataire.nom_entreprise}")
        
        flash("Votre dossier a été soumis avec succès. Il est en attente de validation par les Achats.", "success")
        return redirect(url_for('main.dashboard'))
        
    return render_template('enrolement.html', form=form)
    

@main.route('/nouveau_dossier', methods=['GET', 'POST'])
@login_required
@role_required('PRESTATAIRE')
def nouveau_dossier():
    prestataire = db.session.scalar(db.select(Prestataire).filter_by(user_id=current_user.id))
    
    if not prestataire:
        flash("Vous devez d'abord enrôler votre entreprise avant de créer un dossier.", "warning")
        return redirect(url_for('main.enrolement'))

    form = DossierInterventionForm()
    
    if form.validate_on_submit():
        path_plan = save_secure_file(form.fichier_plan_prevention.data, subfolder='plans_prevention')
        
        if not path_plan:
            flash("Alerte : Le fichier du plan de prévention n'est pas un PDF valide.", "danger")
            return render_template('nouveau_dossier.html', form=form)
        
        nouveau_dossier = DossierIntervention(
            prestataire_id=prestataire.id,
            titre_intervention=form.titre_intervention.data,
            description=form.description.data,
            zone_site=form.zone_site.data,
            date_debut=form.date_debut.data,
            date_fin=form.date_fin.data,
            fichier_plan_prevention=path_plan,
            statut_achats='EN_ATTENTE',
            statut_hse='EN_ATTENTE'
        )
        
        db.session.add(nouveau_dossier)
        db.session.commit()

        # --- LOG : Création de dossier ---
        enregistrer_log(current_user.id, "CREATION_DOSSIER", f"A créé le dossier d'intervention '{nouveau_dossier.titre_intervention}' pour la zone {nouveau_dossier.zone_site}")
        
        flash("Le dossier d'intervention a été créé avec succès !", "success")
        return redirect(url_for('main.dashboard'))
        
    return render_template('nouveau_dossier.html', form=form)

@main.route('/dossier/<int:dossier_id>', methods=['GET', 'POST'])
@login_required
@role_required('PRESTATAIRE')
def detail_dossier(dossier_id):
    prestataire = db.session.scalar(db.select(Prestataire).filter_by(user_id=current_user.id))
    dossier = db.session.get(DossierIntervention, dossier_id)
    
    if not dossier or dossier.prestataire_id != prestataire.id:
        flash("Accès refusé ou dossier introuvable.", "danger")
        return redirect(url_for('main.dashboard'))

    form = AjoutIntervenantForm()

    if form.validate_on_submit():
        # 1. Sauvegarde sécurisée de la CNI
        path_cni = save_secure_file(form.fichier_cni.data, subfolder='cni_intervenants')
        if not path_cni:
            flash("La CNI transmise n'est pas un fichier PDF valide.", "danger")
            # CORRECTION ICI AUSSI : On passe les liaisons, pas "dossier.intervenants"
            return render_template('dossier_detail.html', dossier=dossier, form=form, liaisons=dossier.dossier_intervenants)

        # 2. Sauvegarde des habilitations (si fourni)
        path_hab = None
        if form.fichier_habilitations.data:
            path_hab = save_secure_file(form.fichier_habilitations.data, subfolder='habilitations_intervenants')

        # 3. Création de l'intervenant
        nouvel_intervenant = Intervenant(
            prenom=form.prenom.data,
            nom=form.nom.data,
            numero_piece=form.numero_cni.data,  
            fichier_cni=path_cni,
            fichier_certificats=path_hab,       
            prestataire_id=prestataire.id,   

            # --- AJOUT DES DATES D'EXPIRATION ---
            date_expiration_cni=form.date_expiration_cni.data,
            date_expiration_certificats=form.date_expiration_habilitations.data,
            # ------------------------------------   
            
            # --- AJOUT DES CASES À COCHER ---
            hab_travail_hauteur=form.hab_travail_hauteur.data,
            hab_espace_confine=form.hab_espace_confine.data,
            hab_risque_electrique=form.hab_risque_electrique.data,
            hab_conduite_engins=form.hab_conduite_engins.data,
            hab_incendie=form.hab_incendie.data
        )
        
        # 4. Ajout en base pour générer son ID
        db.session.add(nouvel_intervenant)
        db.session.flush() # Force la base à attribuer un ID à nouvel_intervenant
        
        # 5. CORRECTION : Association au dossier via la table de liaison avec statut EN_ATTENTE
        liaison = DossierIntervenant(
            dossier_id=dossier.id,
            intervenant_id=nouvel_intervenant.id,
            statut_hse='EN_ATTENTE'
        )
        db.session.add(liaison)
        
        db.session.commit()

        # --- LOG : Ajout intervenant ---
        enregistrer_log(current_user.id, "AJOUT_INTERVENANT", f"A ajouté l'intervenant {nouvel_intervenant.prenom} {nouvel_intervenant.nom} au dossier #{dossier.id}")
        
        flash(f"{form.prenom.data} {form.nom.data} a été ajouté au dossier (en attente HSE).", "success")
        return redirect(url_for('main.detail_dossier', dossier_id=dossier.id))

    # Récupération des liaisons pour l'affichage dans le template
    liaisons = dossier.dossier_intervenants
    # Remplacement 'dossier_detail.html' par 'detail_dossier.html' si nécessaire :
    return render_template('dossier_detail.html', dossier=dossier, form=form, liaisons=liaisons)

@main.route('/hse/dossier/<int:dossier_id>/intervenant/<int:intervenant_id>/valider', methods=['POST'])
@login_required
@role_required('HSE')
def valider_intervenant(dossier_id, intervenant_id):
    # On cherche la liaison spécifique entre ce dossier et cet intervenant
    liaison = DossierIntervenant.query.filter_by(
        dossier_id=dossier_id, 
        intervenant_id=intervenant_id
    ).first_or_404()
    
    # On modifie le statut individuel
    liaison.statut_hse = 'VALIDE'
    db.session.commit()

    # --- LOG : Validation intervenant par HSE ---
    enregistrer_log(current_user.id, "VALIDATION_HSE_INTERVENANT", f"A validé l'intervenant {liaison.intervenant.prenom} {liaison.intervenant.nom} pour le dossier #{dossier_id}")
    
    flash(f"L'intervenant {liaison.intervenant.prenom} {liaison.intervenant.nom} a été autorisé.", "success")
    return redirect(url_for('main.dossier_hse', dossier_id=dossier_id))


@main.route('/hse/dossier/<int:dossier_id>/intervenant/<int:intervenant_id>/rejeter', methods=['POST'])
@login_required
@role_required('HSE')
def rejeter_intervenant(dossier_id, intervenant_id):
    # On cherche la liaison spécifique
    liaison = DossierIntervenant.query.filter_by(
        dossier_id=dossier_id, 
        intervenant_id=intervenant_id
    ).first_or_404()
    
    # On modifie le statut individuel
    liaison.statut_hse = 'REJETE'
    db.session.commit()

    # --- LOG : Rejet intervenant par HSE ---
    enregistrer_log(current_user.id, "REJET_HSE_INTERVENANT", f"A refusé l'accès à l'intervenant {liaison.intervenant.prenom} {liaison.intervenant.nom} pour le dossier #{dossier_id}")
    
    flash(f"L'accès a été refusé pour {liaison.intervenant.prenom} {liaison.intervenant.nom}.", "danger")
    return redirect(url_for('main.dossier_hse', dossier_id=dossier_id))

from datetime import date

from datetime import date
from flask_login import current_user 
@main.route('/portail/dashboard')
@login_required
@role_required('PORTAIL')
def dashboard_portail():
    aujourd_hui = date.today()
    
    # 1. On récupère les dossiers valides pour aujourd'hui
    dossiers_actifs = DossierIntervention.query.filter(
        DossierIntervention.statut_hse == 'VALIDE',
        DossierIntervention.date_debut <= aujourd_hui,
        DossierIntervention.date_fin >= aujourd_hui
    ).all()
    
    # 2. On détermine qui est actuellement à l'intérieur
    intervenants_sur_site = []
    
    for dossier in dossiers_actifs:
        for liaison in dossier.dossier_intervenants:
            if liaison.statut_hse == 'VALIDE':
                # On cherche le tout dernier mouvement enregistré pour cet intervenant
                dernier_mouvement = RegistreAcces.query.filter_by(
                    intervenant_id=liaison.intervenant_id,
                    dossier_id=dossier.id
                ).order_by(RegistreAcces.horodatage.desc()).first()
                
                # Si son dernier mouvement est "ENTREE", on l'ajoute à la liste de ceux sur site
                if dernier_mouvement and dernier_mouvement.type_mouvement == 'ENTREE':
                    intervenants_sur_site.append(liaison.intervenant_id)
    
    return render_template(
        'dashboard_portail.html', 
        dossiers=dossiers_actifs, 
        aujourd_hui=aujourd_hui,
        intervenants_sur_site=intervenants_sur_site
    )


@main.route('/portail/entree/<int:dossier_id>/<int:intervenant_id>', methods=['POST'])
@login_required
@role_required('PORTAIL')
def pointer_entree(dossier_id, intervenant_id):
    try:
        # --- 🔒 NOUVELLE SÉCURITÉ (Les 3 Feux Verts) ---
        intervenant = db.session.get(Intervenant, intervenant_id)
        aujourd_hui = date.today()
        
        # On vérifie la validité à l'instant T
        cni_valide = intervenant.date_expiration_cni and intervenant.date_expiration_cni >= aujourd_hui
        hab_valide = intervenant.date_expiration_certificats and intervenant.date_expiration_certificats >= aujourd_hui
        
        if not cni_valide or not hab_valide:
            # Blocage immédiat avec message d'erreur clair
            flash(f"Accès refusé pour {intervenant.prenom} {intervenant.nom} : CNI ou Habilitation expirée.", "danger")
            # --- LOG : Tentative d'accès refusée ---
            enregistrer_log(
                current_user.id, 
                "TENTATIVE_ENTREE_REFUSEE", 
                f"A tenté de faire entrer {intervenant.prenom} {intervenant.nom} mais document expiré (Dossier #{dossier_id})"
            )
            return redirect(url_for('main.dashboard_portail'))
        # -----------------------------------------------

        # Vérification classique du dernier mouvement
        dernier_mouvement = RegistreAcces.query.filter_by(
            intervenant_id=intervenant_id, dossier_id=dossier_id
        ).order_by(RegistreAcces.horodatage.desc()).first()

        if dernier_mouvement and dernier_mouvement.type_mouvement == 'ENTREE':
            flash("Cet intervenant est déjà pointé en entrée.", "warning")
            return redirect(url_for('main.dashboard_portail'))

        # Enregistrement de l'entrée
        nouveau_mouvement = RegistreAcces(
            dossier_id=dossier_id,
            intervenant_id=intervenant_id,
            agent_portail_id=current_user.id,
            type_mouvement='ENTREE'
        )
        db.session.add(nouveau_mouvement)
        db.session.commit()

        # --- LOG : Entrée sur site ---
        enregistrer_log(
            current_user.id, 
            "ENTREE_SITE", 
            f"A autorisé l'entrée de l'intervenant {intervenant.prenom} {intervenant.nom} (Dossier #{dossier_id})"
        )
        # ------------------------------

        flash("Entrée enregistrée avec succès.", "success")
        
    except Exception as e:
        db.session.rollback()
        print(f"ERREUR TECHNIQUE : {str(e)}")
        flash(f"Erreur lors de l'enregistrement : {str(e)}", "danger")

    return redirect(url_for('main.dashboard_portail'))

@main.route('/portail/sortie/<int:dossier_id>/<int:intervenant_id>', methods=['POST'])
@login_required
@role_required('PORTAIL')
def pointer_sortie(dossier_id, intervenant_id):
    try:
        dernier_mouvement = RegistreAcces.query.filter_by(
            intervenant_id=intervenant_id, dossier_id=dossier_id
        ).order_by(RegistreAcces.horodatage.desc()).first()

        if not dernier_mouvement or dernier_mouvement.type_mouvement == 'SORTIE':
            flash("Cet intervenant est déjà pointé en sortie (ou n'est jamais entré).", "warning")
            return redirect(url_for('main.dashboard_portail'))

        nouveau_mouvement = RegistreAcces(
            dossier_id=dossier_id,
            intervenant_id=intervenant_id,
            agent_portail_id=current_user.id,
            type_mouvement='SORTIE'
        )
        db.session.add(nouveau_mouvement)
        db.session.commit()

        # --- LOG : Sortie du site ---
        intervenant = db.session.get(Intervenant, intervenant_id)
        if intervenant:
            enregistrer_log(
                current_user.id, 
                "SORTIE_SITE", 
                f"A enregistré la sortie de l'intervenant {intervenant.prenom} {intervenant.nom} (Dossier #{dossier_id})"
            )
        # ------------------------------
        
        flash("Sortie enregistrée avec succès.", "success")
        
    except Exception as e:
        db.session.rollback()
        print(f"ERREUR TECHNIQUE : {str(e)}")
        flash(f"Erreur lors de l'enregistrement : {str(e)}", "danger")

    return redirect(url_for('main.dashboard_portail'))

@main.route('/portail/controles')
@login_required
@role_required('PORTAIL')
def controles_portail():
    # On récupère tout le registre, trié par date la plus récente en premier (descendant)
    mouvements = RegistreAcces.query.order_by(RegistreAcces.horodatage.desc()).all()
    
    return render_template('controles_portail.html', mouvements=mouvements)

import string
import random
from flask import render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from app.models import User, RegistreAcces, DemandeAcces, ActionLog, db 
# ==========================================
# ROUTE PUBLIQUE : FORMULAIRE DE DEMANDE D'ACCÈS
# ==========================================
@main.route('/demande-acces', methods=['GET', 'POST'])
def demande_acces():
    if request.method == 'POST':
        nom_entreprise = request.form.get('nom_entreprise')
        nom_contact = request.form.get('nom_contact')
        email_contact = request.form.get('email_contact')
        telephone = request.form.get('telephone')
        motif = request.form.get('motif')

        # Vérification si un compte existe déjà avec cet email
        if User.query.filter_by(email=email_contact).first():
            flash("Un compte existe déjà avec cet email. Veuillez vous connecter.", "warning")
            return redirect(url_for('main.login'))

        nouvelle_demande = DemandeAcces(
            nom_entreprise=nom_entreprise,
            nom_contact=nom_contact,
            email_contact=email_contact,
            telephone=telephone,
            motif=motif
        )
        db.session.add(nouvelle_demande)
        db.session.commit()

        flash("Votre demande d'accès a été transmise au service HSE/Administration.", "success")
        return redirect(url_for('main.login'))

    return render_template('demande_acces.html')


# ==========================================
# DASHBOARD SUPERADMIN (Mis à jour avec demandes)
# ==========================================

@main.route('/superadmin/dashboard')
@login_required
@role_required('SUPERADMIN')
def dashboard_superadmin():
    utilisateurs = User.query.all()
    historique = RegistreAcces.query.order_by(RegistreAcces.horodatage.desc()).limit(50).all()
    # Récupération des demandes d'accès en attente pour le template
    demandes = DemandeAcces.query.filter_by(statut='En attente').order_by(DemandeAcces.date_demande.desc()).all()
    
    # === AJOUT ICI : Récupérer tous les dossiers pour l'historique des achats ===
    dossiers = DossierIntervention.query.all()
    
    return render_template(
        'superadmin_dashboard.html', 
        utilisateurs=utilisateurs, 
        historique=historique, 
        demandes=demandes,
        dossiers=dossiers  # === AJOUT ICI : Envoyer la variable au template ===
    )


# ==========================================
# CRÉATION MANUELLE D'UTILISATEUR
# ==========================================
@main.route('/superadmin/creer_utilisateur', methods=['POST'])
@login_required
@role_required('SUPERADMIN')
def creer_utilisateur():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    role = request.form.get('role')
    
    user_exists = User.query.filter_by(email=email).first()
    if user_exists:
        flash("Cet email est déjà utilisé par un autre compte.", "danger")
        return redirect(url_for('main.dashboard_superadmin'))
        
    nouvel_utilisateur = User(
        username=username, 
        email=email, 
        role=role,
        must_change_password=True  #   On Force le changement à la 1ère connexion
    )
    nouvel_utilisateur.set_password(password)
    
    db.session.add(nouvel_utilisateur)
    db.session.commit()
    
    flash(f"Le compte {role} pour {username} a été créé avec succès !", "success")
    return redirect(url_for('main.dashboard_superadmin'))


# ==========================================
# VALIDATION OU REJET D'UNE DEMANDE D'ACCÈS
# ==========================================
@main.route('/demande/<int:demande_id>/action', methods=['POST'])
@login_required
@role_required('SUPERADMIN')
def action_demande(demande_id):
    demande = DemandeAcces.query.get_or_404(demande_id)
    action = request.form.get('action')

    if action == 'valider':
        # 1.   On Vérifie si l'utilisateur existe déjà
        if User.query.filter_by(email=demande.email_contact).first():
            flash(f"Un compte avec l'email {demande.email_contact} existe déjà.", "danger")
            return redirect(url_for('main.dashboard_superadmin'))

        # 2. Puis On Génére une clé/mot de passe provisoire aléatoire
        caracteres = string.ascii_letters + string.digits
        cle_provisoire = "SOCO-" + "".join(random.choice(caracteres) for _ in range(6))

        # 3. Ensuite On Crée le compte prestataire
        nouvel_utilisateur = User(
            username=demande.nom_entreprise,
            email=demande.email_contact,
            role='PRESTATAIRE',
            must_change_password=True  #Ceci Bloque l'accès jusqu'au changement de mot de passe
        )
        nouvel_utilisateur.set_password(cle_provisoire)

        demande.statut = 'Validée'
        db.session.add(nouvel_utilisateur)
        
        flash(f"Demande validée ! Compte '{demande.nom_entreprise}' créé. Email: {demande.email_contact} | Clé provisoire: {cle_provisoire}", "success")
        
    elif action == 'rejeter':
        demande.statut = 'Rejetée'
        flash(f"La demande de {demande.nom_entreprise} a été rejetée.", "warning")

    db.session.commit()
    return redirect(url_for('main.dashboard_superadmin'))


# ==========================================
# PREMIÈRE CONNEXION (Changement obligatoire)
# ==========================================
@main.route('/premiere-connexion', methods=['GET', 'POST'])
@login_required
def premiere_connexion():
    # 1. FIX : On Redirige vers l'accueil normal si pas besoin de changer le mdp
    if not getattr(current_user, 'must_change_password', False):
        return redirect(url_for('main.dashboard')) 
    if request.method == 'POST':
        nouveau_mdp = request.form.get('nouveau_mdp')
        confirm_mdp = request.form.get('confirm_mdp')

        if nouveau_mdp != confirm_mdp:
            flash("Les mots de passe ne correspondent pas.", "danger")
        elif len(nouveau_mdp) < 8:
            flash("Le mot de passe doit contenir au moins 8 caractères.", "danger")
        else:
            current_user.set_password(nouveau_mdp)
            current_user.must_change_password = False
            db.session.commit()
            
            flash("Votre mot de passe a été mis à jour avec succès !", "success")
            # 2. FIX : On  Redirige vers le tableau de bord du prestataire/normal
            return redirect(url_for('main.dashboard')) 

    return render_template('premiere_connexion.html')

# ==========================================
# PISTE D'AUDIT (SuperAdmin)
# ==========================================
@main.route('/superadmin/logs')
@login_required
@role_required('SUPERADMIN')
def voir_logs():
    logs = db.session.scalars(
        db.select(ActionLog).order_by(ActionLog.timestamp.desc()).limit(200)
    ).all()
    
    return render_template('superadmin_logs.html', logs=logs)


@main.route('/dossier/<int:dossier_id>/intervenant/<int:intervenant_id>/retirer', methods=['POST'])
@login_required
def retirer_intervenant(dossier_id, intervenant_id):
    # Sécurité : Seul le prestataire a le droit de faire ça
    if current_user.role != 'PRESTATAIRE':
        flash("Action non autorisée.", "danger")
        return redirect(url_for('main.dashboard'))
        
    # On cherche le lien entre ce dossier et cet intervenant
    liaison = DossierIntervenant.query.filter_by(
        dossier_id=dossier_id, 
        intervenant_id=intervenant_id
    ).first_or_404()
    
    # On supprime le lien
    db.session.delete(liaison)
    db.session.commit()
    
    flash("L'intervenant a été retiré du dossier avec succès.", "success")
    return redirect(url_for('main.detail_dossier', dossier_id=dossier_id))

@main.route('/dossier/<int:dossier_id>/intervenant/<int:intervenant_id>/modifier', methods=['GET', 'POST'])
@login_required
def modifier_intervenant(dossier_id, intervenant_id):
    if current_user.role != 'PRESTATAIRE':
        flash("Action non autorisée.", "danger")
        return redirect(url_for('main.dashboard'))

    intervenant = Intervenant.query.get_or_404(intervenant_id)
    dossier = DossierIntervention.query.get_or_404(dossier_id)
    
    # 1. ON UTILISE LE NOUVEAU FORMULAIRE ICI
    form = ModifierIntervenantForm(obj=intervenant)

    # 2. ON FORCE L'AFFICHAGE DES DONNÉES EXISTANTES À L'OUVERTURE
    if request.method == 'GET':
        form.numero_cni.data = intervenant.numero_piece
        form.date_expiration_habilitations.data = intervenant.date_expiration_certificats

    if form.validate_on_submit():
        # Mise à jour des informations textes et dates
        intervenant.prenom = form.prenom.data
        intervenant.nom = form.nom.data
        intervenant.numero_piece = form.numero_cni.data
        intervenant.date_expiration_cni = form.date_expiration_cni.data
        intervenant.date_expiration_certificats = form.date_expiration_habilitations.data
        
        # Mise à jour des cases à cocher
        intervenant.hab_travail_hauteur = form.hab_travail_hauteur.data
        intervenant.hab_espace_confine = form.hab_espace_confine.data
        intervenant.hab_risque_electrique = form.hab_risque_electrique.data
        intervenant.hab_conduite_engins = form.hab_conduite_engins.data
        intervenant.hab_incendie = form.hab_incendie.data
        
        # On remet le statut HSE "En attente"
        liaison = DossierIntervenant.query.filter_by(dossier_id=dossier.id, intervenant_id=intervenant.id).first()
        if liaison:
            liaison.statut_hse = 'EN_ATTENTE'

        db.session.commit()
        flash("Les informations de l'intervenant ont été mises à jour.", "success")
        return redirect(url_for('main.detail_dossier', dossier_id=dossier.id))

    return render_template('modifier_intervenant.html', form=form, intervenant=intervenant, dossier=dossier)
