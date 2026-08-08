from typing import Optional, List
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import String, Integer, DateTime, Boolean, ForeignKey, Text
from flask_login import UserMixin
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app import db

# ==========================================
# 1. SÉCURITÉ ET UTILISATEURS
# ==========================================

class LoginAttempt(db.Model):
    __tablename__ = 'login_attempt'
    
    id: Mapped[int] = mapped_column(primary_key=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, unique=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_attempt: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    is_blocked: Mapped[bool] = mapped_column(Boolean, default=False)


class User(db.Model, UserMixin): 
    __tablename__ = 'users'
    
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), index=True, unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(120), index=True, unique=True, nullable=False)
    password_hash: Mapped[Optional[str]] = mapped_column(String(256))
    
    # Rôles : PRESTATAIRE, ACHATS, HSE, PORTAIL, ADMIN, SUPERADMIN
    role: Mapped[str] = mapped_column(String(20), nullable=False, default='PRESTATAIRE')
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    prestataire: Mapped[Optional["Prestataire"]] = relationship(back_populates="gestionnaire")

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    # ON AJOUTE CETTE LIGNE :
    must_change_password = db.Column(db.Boolean, default=False)


# ==========================================
# 2. ENTREPRISES PRESTATAIRES (Volet Achats)
# ==========================================

class Prestataire(db.Model):
    __tablename__ = 'prestataires'
    
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), nullable=False)
    
    nom_entreprise: Mapped[str] = mapped_column(String(150), nullable=False)
    ninea: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    registre_commerce: Mapped[str] = mapped_column(String(50), nullable=False)
    domaine_activite: Mapped[str] = mapped_column(String(100), nullable=False) 
    
    fichier_ninea: Mapped[Optional[str]] = mapped_column(String(255))
    fichier_rc: Mapped[Optional[str]] = mapped_column(String(255))
    
    gestionnaire: Mapped["User"] = relationship(back_populates="prestataire")
    intervenants: Mapped[List["Intervenant"]] = relationship(back_populates="entreprise", cascade="all, delete-orphan")
    dossiers: Mapped[List["DossierIntervention"]] = relationship(back_populates="entreprise", cascade="all, delete-orphan")


# ==========================================
# 3. INTERVENANTS ET ASSOCIATION DOSSIER
# ==========================================

class DossierIntervenant(db.Model):
    """
    Table de liaison entre un dossier et un intervenant.
    Permet la validation HSE INDIVIDUELLE de chaque intervenant.
    """
    __tablename__ = 'dossier_intervenants'
    
    dossier_id: Mapped[int] = mapped_column(ForeignKey('dossiers_intervention.id'), primary_key=True)
    intervenant_id: Mapped[int] = mapped_column(ForeignKey('intervenants.id'), primary_key=True)
    
    # Statut individuel de l'intervenant pour ce dossier : EN_ATTENTE, VALIDE, REJETE
    statut_hse: Mapped[str] = mapped_column(String(20), default='EN_ATTENTE')
    commentaire_hse: Mapped[Optional[str]] = mapped_column(Text)
    date_validation_hse: Mapped[Optional[datetime]] = mapped_column(DateTime)
    
    dossier: Mapped["DossierIntervention"] = relationship(back_populates="dossier_intervenants")
    intervenant: Mapped["Intervenant"] = relationship(back_populates="dossier_intervenants")


class Intervenant(db.Model):
    __tablename__ = 'intervenants'
    
    id: Mapped[int] = mapped_column(primary_key=True)
    prestataire_id: Mapped[int] = mapped_column(ForeignKey('prestataires.id'), nullable=False)
    
    nom: Mapped[str] = mapped_column(String(100), nullable=False)
    prenom: Mapped[str] = mapped_column(String(100), nullable=False)
    numero_piece: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)

    fichier_cni: Mapped[Optional[str]] = mapped_column(String(255))  # <-- AJOUTER CETTE LIGNE
    fichier_certificats: Mapped[Optional[str]] = mapped_column(String(255))
    
    # Habilitations spécifiques
    hab_travail_hauteur: Mapped[bool] = mapped_column(Boolean, default=False)
    hab_espace_confine: Mapped[bool] = mapped_column(Boolean, default=False)
    hab_risque_electrique: Mapped[bool] = mapped_column(Boolean, default=False)
    hab_conduite_engins: Mapped[bool] = mapped_column(Boolean, default=False)
    hab_incendie: Mapped[bool] = mapped_column(Boolean, default=False)
    
    fichier_certificats: Mapped[Optional[str]] = mapped_column(String(255))

    entreprise: Mapped["Prestataire"] = relationship(back_populates="intervenants")
    dossier_intervenants: Mapped[List["DossierIntervenant"]] = relationship(back_populates="intervenant", cascade="all, delete-orphan")
    acces_registre: Mapped[List["RegistreAcces"]] = relationship(back_populates="intervenant")

    # NOUVELLES COLONNES : Dates d'expiration
    date_expiration_cni = db.Column(db.Date, nullable=True)
    date_expiration_certificats = db.Column(db.Date, nullable=True)


# ==========================================
# 4. DEMANDES D'ACCÈS / DOSSIERS
# ==========================================

class DossierIntervention(db.Model):
    __tablename__ = 'dossiers_intervention'
    
    id: Mapped[int] = mapped_column(primary_key=True)
    prestataire_id: Mapped[int] = mapped_column(ForeignKey('prestataires.id'), nullable=False)
    
    titre_intervention: Mapped[str] = mapped_column(String(200), nullable=False)
    zone_site: Mapped[str] = mapped_column(String(100), nullable=False) 
    description: Mapped[str] = mapped_column(Text, nullable=False)
    date_debut: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    date_fin: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    
    fichier_assurance: Mapped[Optional[str]] = mapped_column(String(255))         
    fichier_plan_prevention: Mapped[Optional[str]] = mapped_column(String(255))   
    
    entreprise: Mapped["Prestataire"] = relationship(back_populates="dossiers")
    dossier_intervenants: Mapped[List["DossierIntervenant"]] = relationship(back_populates="dossier", cascade="all, delete-orphan")

    # Validation ACHATS (Globale pour l'entreprise)
    statut_achats: Mapped[str] = mapped_column(String(20), default='EN_ATTENTE')
    commentaire_achats: Mapped[Optional[str]] = mapped_column(Text)
    date_validation_achats: Mapped[Optional[datetime]] = mapped_column(DateTime)
    valide_par_achats_id: Mapped[Optional[int]] = mapped_column(ForeignKey('users.id'))
    
    # Validation HSE (Globale pour le Plan de Prévention / Zone)
    statut_hse: Mapped[str] = mapped_column(String(20), default='EN_ATTENTE') 
    commentaire_hse: Mapped[Optional[str]] = mapped_column(Text)
    date_validation_hse: Mapped[Optional[datetime]] = mapped_column(DateTime)
    valide_par_hse_id: Mapped[Optional[int]] = mapped_column(ForeignKey('users.id'))
    
    date_creation: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    @property
    def statut_global(self) -> str:
        if self.statut_achats == 'VALIDE' and self.statut_hse == 'VALIDE':
            return 'AUTORISE'
        elif self.statut_achats == 'REJETE' or self.statut_hse == 'REJETE':
            return 'REFUSE'
        return 'EN_ATTENTE'


# ==========================================
# 5. REGISTRE PORTAIL (Contrôle d'Accès Physique)
# ==========================================

class RegistreAcces(db.Model):
    """
    Historique des Entrées et Sorties physiques scannées ou enregistrées au portail.
    """
    __tablename__ = 'registre_acces'

    id: Mapped[int] = mapped_column(primary_key=True)
    intervenant_id: Mapped[int] = mapped_column(ForeignKey('intervenants.id'), nullable=False)
    dossier_id: Mapped[int] = mapped_column(ForeignKey('dossiers_intervention.id'), nullable=False)
    agent_portail_id: Mapped[int] = mapped_column(ForeignKey('users.id'), nullable=False)

    type_mouvement: Mapped[str] = mapped_column(String(10), nullable=False)  # 'ENTREE' ou 'SORTIE'
    horodatage: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    intervenant: Mapped["Intervenant"] = relationship(back_populates="acces_registre")
    dossier: Mapped["DossierIntervention"] = relationship()
    agent_portail: Mapped["User"] = relationship()


   

class ActionLog(db.Model):
    __tablename__ = 'action_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True) # Celui qui a fait l'action
    action = db.Column(db.String(100), nullable=False) # Ex: "CONNEXION", "VALIDATION_HSE"
    description = db.Column(db.String(255)) # Ex: "A validé la demande n°15"
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relation avec l'utilisateur pour récupérer son nom facilement
    user = db.relationship('User', backref='logs')


class DemandeAcces(db.Model):
    __tablename__ = 'demandes_acces'

    id = db.Column(db.Integer, primary_key=True)
    nom_entreprise = db.Column(db.String(150), nullable=False)
    nom_contact = db.Column(db.String(100), nullable=False)
    email_contact = db.Column(db.String(120), nullable=False)
    telephone = db.Column(db.String(20), nullable=False)
    motif = db.Column(db.Text, nullable=True) # Ex: "Sous-traitant pour le projet X"
        
    # Statut de la demande : 'En attente', 'Validée', 'Rejetée'
    statut = db.Column(db.String(20), default='En attente') 
    date_demande = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<DemandeAcces {self.nom_entreprise} - {self.statut}>"