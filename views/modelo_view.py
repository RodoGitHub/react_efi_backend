from flask import Blueprint, request, make_response, jsonify
from flask_jwt_extended import get_jwt, jwt_required

from app import db
from models import Modelo
from schemas import ModeloSchema  # Cambiamos MarcaSchema por ModeloSchema

modelo_bp = Blueprint('modelo', __name__)

@modelo_bp.route('/modelo', methods=['GET', 'POST'])
@jwt_required()
def modelo():
    data = request.get_json()
    id_marca = data.get('id_marca')
    modelos = Modelo.query.filter_by(activo=True).all()
    
    additional_data = get_jwt()
    visor = additional_data.get('visor')
    admin = additional_data.get('administrador')
  
    if request.method == 'POST':
        
        if admin:            
            nuevo_modelo = Modelo(
                nombre=data.get('nombre'),
                id_marca=id_marca
            )
            db.session.add(nuevo_modelo)
            db.session.commit()
            return ModeloSchema().dump(nuevo_modelo), 201
        else:
            return jsonify({"Mensaje": "Solo el admin puede crear nuevos modelos"})

    if visor or admin:
        return jsonify(ModeloSchema(many=True).dump(modelos))

    return jsonify({"Mensaje": "El usuario no tiene permiso"})

@modelo_bp.route('/modelo/borrar', methods=['POST'])
@jwt_required()
def modelo_borrar():
    data = request.get_json()
    id_borrar = int(data.get('id'))
    modelo = Modelo.query.get_or_404(id_borrar)
    
    if modelo.activo is True:
        additional_data = get_jwt()
        editor = additional_data.get('tipo')
        admin = additional_data.get('administrador')

        if editor or admin:
            
            """errors = MarcaSchema().validate(data)
            if errors:
                return make_response(jsonify(errors))"""
            modelo.activo = False
            db.session.commit()
            
            return jsonify(Mensaje= "El borrado fue exitoso",Marca=modelo.nombre)
        else:
            return jsonify(Mensaje= "Usted no tiene permiso de borrar modelo")
    else:
        return jsonify(Mensaje= "Esta marca fue borrada anteriormente", Marca=modelo.nombre)
    
@modelo_bp.route('/modelo/editar', methods=['POST'])
@jwt_required()
def modelo_editar():
    data = request.get_json()
    id_marca = int(data.get('id_marca'))
    modelo_editar = data.get('nombre')
    id_editar = int(data.get('id'))

    modelo = Modelo.query.get_or_404(id_editar)
    
    if modelo.activo is True:
        additional_data = get_jwt()
        editor = additional_data.get('editor')
        admin = additional_data.get('administrador')

        if editor or admin:
            
            modelo.nombre = modelo_editar
            modelo.id_marca = id_marca
        
            db.session.commit()
            
            return jsonify(Mensaje="El modelo fue editado exitosamente", Modelo=modelo.nombre)
        else:
            return jsonify(Mensaje="Usted no tiene permiso de editar Modelos")
    else:
        return jsonify(Mensaje="El modelo fue borrado")
