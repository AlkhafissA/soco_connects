from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
# Ajout de TextAreaField et DateField ici :
from wtforms import StringField, SubmitField, SelectField, TextAreaField, DateField
from wtforms.validators import DataRequired, Length, Optional

# ==========================================
# 1. FORMULAIRE D'ENRÔLEMENT
# ==========================================
class EnrolementPrestataireForm(FlaskForm):
    # --- INFORMATIONS DE L'ENTREPRISE ---
    nom_entreprise = StringField(
        'Nom de l\'entreprise', 
        validators=[DataRequired(message="Ce champ est obligatoire."), Length(max=150)]
    )
    
    ninea = StringField(
        'Numéro NINEA', 
        validators=[DataRequired(message="Le NINEA est obligatoire."), Length(max=50)]
    )
    
    registre_commerce = StringField(
        'Registre de Commerce (RC)', 
        validators=[DataRequired(message="Le RC est obligatoire."), Length(max=50)]
    )
    
    domaine_activite = SelectField(
        'Domaine d\'activité principal',
        choices=[
            ('', 'Sélectionnez un domaine'),
            ('BTP', 'Bâtiment et Travaux Publics (BTP)'),
            ('MAINTENANCE', 'Maintenance Industrielle / Mécanique'),
            ('TRANSPORT', 'Transport et Logistique'),
            ('FOURNITURE', 'Fourniture d\'équipements'),
            ('NETTOYAGE', 'Nettoyage Industriel'),
            ('AUTRE', 'Autre')
        ],
        validators=[DataRequired(message="Veuillez sélectionner un domaine.")]
    )

    # --- DOCUMENTS LÉGAUX (PDF Uniquement) ---
    fichier_ninea = FileField(
        'Copie du NINEA (PDF uniquement)', 
        validators=[
            FileRequired(message="Le fichier NINEA est obligatoire."),
            FileAllowed(['pdf'], 'Seuls les documents au format PDF sont acceptés.')
        ]
    )
    
    fichier_rc = FileField(
        'Copie du Registre de Commerce (PDF uniquement)', 
        validators=[
            FileRequired(message="Le fichier du Registre de Commerce est obligatoire."),
            FileAllowed(['pdf'], 'Seuls les documents au format PDF sont acceptés.')
        ]
    )

    submit = SubmitField('Soumettre le dossier d\'enrôlement')

# ==========================================
# 2. FORMULAIRE DE DOSSIER D'INTERVENTION
# ==========================================
class DossierInterventionForm(FlaskForm):
    titre_intervention = StringField(
        'Titre de l\'intervention', 
        validators=[DataRequired(message="Le titre est obligatoire.")]
    )
    
    description = TextAreaField(
        'Description des travaux', 
        validators=[DataRequired(message="Veuillez décrire l'intervention.")]
    )
    
    zone_site = StringField(
        'Zone / Atelier (Ex: Four, Broyeur, Carrière)', 
        validators=[DataRequired(message="La zone d'intervention est obligatoire.")]
    )
    
    date_debut = DateField(
        'Date de début', 
        format='%Y-%m-%d', 
        validators=[DataRequired(message="La date de début est obligatoire.")]
    )
    
    date_fin = DateField(
        'Date de fin prévue', 
        format='%Y-%m-%d', 
        validators=[DataRequired(message="La date de fin est obligatoire.")]
    )
    
    fichier_plan_prevention = FileField(
        'Plan de Prévention (PDF)', 
        validators=[
            FileRequired(message="Le plan de prévention est obligatoire."),
            FileAllowed(['pdf'], 'Seuls les fichiers PDF sont autorisés.')
        ]
    )
    
    submit = SubmitField('Créer le dossier')

from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, SubmitField, SelectField, TextAreaField, DateField, BooleanField
from wtforms.validators import DataRequired, Length

# ... [On Garde EnrolementPrestataireForm et DossierInterventionForm inchangés] ...

class AjoutIntervenantForm(FlaskForm):
    prenom = StringField('Prénom', validators=[DataRequired(message="Le prénom est obligatoire.")])
    nom = StringField('Nom', validators=[DataRequired(message="Le nom est obligatoire.")])
    numero_cni = StringField('Numéro CNI', validators=[DataRequired(message="Le numéro CNI est obligatoire.")])
    
    # Fichier CNI obligatoire
    fichier_cni = FileField('Copie CNI (PDF)', validators=[
        FileRequired(message="La copie de la CNI est obligatoire."),
        FileAllowed(['pdf'], 'Seuls les fichiers PDF sont acceptés.')
    ])

    # Habilitations cimenterie
    hab_travail_hauteur = BooleanField('Travail en hauteur')
    hab_espace_confine = BooleanField('Espace confiné')
    hab_risque_electrique = BooleanField('Risque électrique')
    hab_conduite_engins = BooleanField('Conduite d\'engins')
    hab_incendie = BooleanField('Sécurité incendie')
    
    # Fichier Habilitations optionnel
    fichier_habilitations = FileField('Certificats / Habilitations (PDF)', validators=[
        FileAllowed(['pdf'], 'Seuls les fichiers PDF sont acceptés.')
    ])
    
    submit = SubmitField('Ajouter à l\'intervention')


    # NOUVEAUX CHAMPS : Sélecteurs de date
    date_expiration_cni = DateField("Date d'expiration de la CNI", format='%Y-%m-%d', validators=[Optional()])
    date_expiration_habilitations = DateField("Date d'expiration des habilitations", format='%Y-%m-%d', validators=[Optional()])


    # On ajoute ceci à la toute fin de app/forms.py
class ModifierIntervenantForm(AjoutIntervenantForm):
    # On écrase le champ fichier_cni pour retirer le "FileRequired"
    fichier_cni = FileField('Copie CNI (PDF)', validators=[
        FileAllowed(['pdf'], 'Seuls les fichiers PDF sont acceptés.')
    ])