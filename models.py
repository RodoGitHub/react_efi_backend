from app import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    password_hash = db.Column(db.String(300), nullable=False)
    is_admin = db.Column(db.Boolean)
    is_viewer = db.Column(db.Boolean)
    is_editor = db.Column(db.Boolean)
    activo = db.Column(db.Boolean, default=True, nullable=False)


class Marca(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(255), nullable=False, unique=True)
    activo = db.Column(db.Boolean, default=True, nullable=False)

class Modelo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(255), nullable=False, unique=True)
    id_marca = db.Column(db.Integer, db.ForeignKey('marca.id'), nullable=False)
    activo = db.Column(db.Boolean, default=True, nullable=False)

    marca = db.relationship('Marca', backref=db.backref('modelos', lazy=True))