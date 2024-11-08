from flask import Blueprint, request, make_response, jsonify

from flask_jwt_extended import (
    get_jwt,
    jwt_required,
)

from app import db
from models import Marca


from schemas import MarcaSchema

marca_bp = Blueprint('marca', __name__)

from base64 import b64decode

@marca_bp.route('/marca', methods=['GET','POST'])
@jwt_required()
def marca():
    marca = Marca.query.filter_by(activo=True).all()

    additional_data = get_jwt()
    visor = additional_data.get('visor')
    admin = additional_data.get('administrador')

    if request.method == 'POST':
        print("aca")
        if  admin:
            data = request.get_json()
            errors = MarcaSchema().validate(data)
            if errors:
                return make_response(jsonify(errors))
            
            nueva_marca = Marca(
                nombre=data.get('nombre'),
            )
            db.session.add(nueva_marca)
            db.session.commit()
            return MarcaSchema().dump(nueva_marca), 201
        else:
            return jsonify(Mensaje= "Solo el admin puede crear nuevas marcas")
    if visor or admin:
        return MarcaSchema().dump(marca, many=True)
    return jsonify(Mensaje="El usuario no tiene permiso")

@marca_bp.route('/marca/deactivate', methods=['POST'])
@jwt_required()
def deactivate_marca():
    data = request.get_json()
    marca_id = data.get('marca_id')

    marca = Marca.query.get_or_404(marca_id)
    
    if marca.activo:
        additional_data = get_jwt()
        administrador = additional_data.get('administrador')
        editor = additional_data.get('editor')

        if administrador or editor:
            marca.activo = False
            db.session.commit()
            return jsonify({"Mensaje": "marca borrado correctamente", "Usuario": marca.nombre})
        else:
            return jsonify({"Mensaje": "No tienes permisos para borrar marca"}), 401
    else:
        return jsonify({"Mensaje": "Esta marca ya estaba borrado", "Usuario": marca.nombre}), 401

@marca_bp.route('/marca/borrar', methods=['POST'])
@jwt_required()
def marca_borrar():
    data = request.get_json()
    id_borrar = int(data.get('id'))
    marca = Marca.query.get_or_404(id_borrar)
    
    if marca.activo is True:
        additional_data = get_jwt()
        editor = additional_data.get('editor')
        admin = additional_data.get('administrador')

        if editor or admin:
            
            
            """errors = MarcaSchema().validate(data)
            if errors:
                return make_response(jsonify(errors))"""
            marca.activo = False
            db.session.commit()
            
            return jsonify(Mensaje= "El borrado fue exitoso",Marca=marca.nombre)
        else:
            return jsonify(Mensaje= "Usted no tiene permiso de borrar marca")
    else:
        return jsonify(Mensaje= "Esta marca fue borrada anteriormente", Marca=marca.nombre)
    
@marca_bp.route('/marca/editar', methods=['POST'])
@jwt_required()
def marca_editar():
    additional_data = get_jwt()
    data = request.get_json()
    id_editar = data.get('id')
    nombre_editar = data.get('nombre')

    marca = Marca.query.get_or_404(id_editar)
    print("1")
    
    if marca.activo is True:
        additional_data = get_jwt()
        editor = additional_data.get('editor')
        admin = additional_data.get('administrador')
        print("2")
        if editor or admin:
            print("3")
            
            """errors = MarcaSchema().validate(data)
            if errors:
                return make_response(jsonify(errors))"""
            marca.nombre = nombre_editar
            db.session.commit()
            
            return jsonify(Mensaje= "La marca fue editada extosamente",Marca=marca.nombre)
        else:
            return jsonify(Mensaje= "Usted no tiene permiso de editar marca")
    else:
        return jsonify(Mensaje= "Esta marca fue borrada")
     



