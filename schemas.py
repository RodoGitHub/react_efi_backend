from app import ma

from marshmallow import validates, ValidationError

from models import User, Marca, Modelo

class UserSchema(ma.SQLAlchemySchema):
    class Meta:
        model = User

    id = ma.auto_field()
    username = ma.auto_field()
    password_hash = ma.auto_field()
    is_admin = ma.auto_field()
    is_viewer = ma.auto_field()
    is_editor = ma.auto_field()
    activo = ma.auto_field()

class UserMinimalSchema(ma.SQLAlchemySchema):
    class Meta:
        model = User

    username = ma.auto_field()

class MarcaSchema(ma.SQLAlchemySchema):
    class Meta:
        model = Marca
        
    id = ma.auto_field()
    nombre = ma.auto_field()
    activo = ma.auto_field()

class ModeloSchema(ma.SQLAlchemySchema):
    class Meta:
        model = Modelo
        
    id = ma.auto_field()
    nombre = ma.auto_field()
    id_marca = ma.auto_field(required=True)
