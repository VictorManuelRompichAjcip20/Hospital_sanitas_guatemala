from flask import Flask, request, jsonify, session, render_template, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import datetime
import os
import traceback

# Inicialización de Flask
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', '1234')

# Configuración de la base de datos
DATABASE_URL = os.environ.get('DATABASE_URL')

if DATABASE_URL:
    # Producción - Render proporciona DATABASE_URL automáticamente
    if DATABASE_URL.startswith('postgresql://'):
        DATABASE_URL = DATABASE_URL.replace('postgresql://', 'postgresql+psycopg://', 1)
    elif DATABASE_URL.startswith('postgres://'):
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql+psycopg://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
else:
    # Desarrollo
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg://hospital_user:p3uUDHnQELqMfoeskYDZZUaOVVXQzx1o@dpg-d3t9mui4d50c73d2m8m0-a.oregon-postgres.render.com:5432/hospital_db_adl5'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

# Extensiones de archivo permitidas
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'dcm', 'dicom'}

db = SQLAlchemy(app)

# Crear carpeta de uploads si no existe
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ===================== DECORADORES DE SEGURIDAD =====================

def login_required(f):
    """Decorador para rutas que requieren autenticación"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'usuario_id' not in session:
            return jsonify({'success': False, 'message': 'No autorizado'}), 401
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    """Decorador para rutas que requieren roles específicos"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'rol' not in session or session['rol'] not in roles:
                return jsonify({'success': False, 'message': 'Acceso denegado'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ===================== FUNCIONES AUXILIARES =====================

def allowed_file(filename):
    """Verifica si el archivo tiene una extensión permitida"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_paciente_id_from_user():
    """Obtiene el ID del paciente desde el usuario en sesión"""
    if session.get('rol') == 'paciente':
        cursor = db.session.connection().connection.cursor()
        cursor.execute("SELECT id FROM pacientes WHERE usuario_id = %s", (session['usuario_id'],))
        result = cursor.fetchone()
        return result[0] if result else None
    return None

# ===================== RUTAS DE AUTENTICACIÓN =====================

@app.route('/')
def index():
    """Página principal"""
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    """Endpoint para iniciar sesión con redirección según rol"""
    try:
        data = request.get_json()
        email = data.get('email')
        contrasena = data.get('contrasena')

        if not email or not contrasena:
            return jsonify({'success': False, 'message': 'Email y contraseña son requeridos'}), 400

        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            SELECT id, email, contrasena, rol, activo
            FROM usuarios 
            WHERE email = %s
        """, (email,))
        
        result = cursor.fetchone()
        if not result:
            return jsonify({'success': False, 'message': 'Usuario no encontrado'}), 404
        
        columns = ['id', 'email', 'contrasena', 'rol', 'activo']
        user_data = dict(zip(columns, result))
        
        if not user_data['activo']:
            return jsonify({'success': False, 'message': 'Usuario inactivo'}), 403
        
        # En producción usar hash (bcrypt), aquí simplificado
        if user_data['contrasena'] == contrasena:
            session['usuario_id'] = user_data['id']
            session['email'] = user_data['email']
            session['rol'] = user_data['rol']

            # Actualizar último acceso
            cursor.execute("""
                UPDATE usuarios SET ultimo_acceso = NOW() WHERE id = %s
            """, (user_data['id'],))
            db.session.commit()

            # Determinar redirección según rol
            if user_data['rol'] == 'administrador':
                redirect_url = '/dashboard-admin'
            elif user_data['rol'] == 'medico':
                redirect_url = '/dashboard-medico'
            else:
                redirect_url = '/dashboard-paciente'

            return jsonify({
                'success': True,
                'message': 'Login exitoso',
                'email': user_data['email'],
                'rol': user_data['rol'],
                'redirect': redirect_url
            })
        else:
            return jsonify({'success': False, 'message': 'Contraseña incorrecta'}), 401

    except Exception as e:
        db.session.rollback()
        print(f"Error en login: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    """Cerrar sesión"""
    session.clear()
    return jsonify({'success': True, 'message': 'Sesión cerrada exitosamente'})

@app.route('/register', methods=['GET'])
def register_page():
    """Página de registro"""
    return render_template('registro.html')

@app.route('/register', methods=['POST'])
def register():
    """Registro de nuevo usuario/paciente"""
    try:
        data = request.get_json()
        
        # Validar datos requeridos
        required_fields = ['email', 'contrasena', 'nombres', 'apellidos', 'identificacion', 'fecha_nacimiento']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'message': f'Campo {field} es requerido'}), 400

        cursor = db.session.connection().connection.cursor()
        
        # Verificar si el email ya existe
        cursor.execute("SELECT id FROM usuarios WHERE email = %s", (data['email'],))
        if cursor.fetchone():
            return jsonify({'success': False, 'message': 'El email ya está registrado'}), 400
        
        # Verificar si la identificación ya existe
        cursor.execute("SELECT id FROM pacientes WHERE identificacion = %s", (data['identificacion'],))
        if cursor.fetchone():
            return jsonify({'success': False, 'message': 'La identificación ya está registrada'}), 400

        # Crear usuario
        cursor.execute("""
            INSERT INTO usuarios (email, contrasena, rol, activo, fecha_creacion)
            VALUES (%s, %s, 'paciente', true, NOW())
            RETURNING id
        """, (data['email'], data['contrasena']))
        
        usuario_id = cursor.fetchone()[0]

        # Crear paciente
        cursor.execute("""
            INSERT INTO pacientes (
                usuario_id, nombres, apellidos, identificacion, 
                fecha_nacimiento, genero, telefono, direccion,
                contacto_emergencia_nombre, contacto_emergencia_telefono, 
                contacto_emergencia_relacion
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            usuario_id,
            data['nombres'],
            data['apellidos'],
            data['identificacion'],
            data['fecha_nacimiento'],
            data.get('genero'),
            data.get('telefono'),
            data.get('direccion'),
            data.get('contacto_emergencia_nombre'),
            data.get('contacto_emergencia_telefono'),
            data.get('contacto_emergencia_relacion')
        ))
        
        paciente_id = cursor.fetchone()[0]
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Registro exitoso',
            'usuario_id': usuario_id,
            'paciente_id': paciente_id
        }), 201

    except Exception as e:
        db.session.rollback()
        print(f"Error en registro: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

# ===================== RUTAS DE PACIENTES =====================

@app.route('/pacientes', methods=['GET'])
@login_required
@role_required('medico', 'administrador')
def get_pacientes():
    """Obtener lista de pacientes (solo médicos y administradores)"""
    try:
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            SELECT p.id, p.nombres, p.apellidos, p.identificacion, 
                   p.fecha_nacimiento, p.genero, p.telefono, u.email
            FROM pacientes p
            JOIN usuarios u ON p.usuario_id = u.id
            WHERE u.activo = true
            ORDER BY p.apellidos, p.nombres
        """)
        
        columns = ['id', 'nombres', 'apellidos', 'identificacion', 
                   'fecha_nacimiento', 'genero', 'telefono', 'email']
        pacientes = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        # Convertir fecha a string
        for p in pacientes:
            if p['fecha_nacimiento']:
                p['fecha_nacimiento'] = p['fecha_nacimiento'].isoformat()
        
        return jsonify({'success': True, 'pacientes': pacientes})
    
    except Exception as e:
        print(f"Error al obtener pacientes: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/mi-informacion', methods=['GET'])
@login_required
@role_required('paciente')
def get_mi_informacion():
    """Obtener información del paciente autenticado"""
    try:
        cursor = db.session.connection().connection.cursor()
        
        # Obtener ID del paciente desde el usuario en sesión
        cursor.execute("""
            SELECT p.*, u.email
            FROM pacientes p
            JOIN usuarios u ON p.usuario_id = u.id
            WHERE p.usuario_id = %s
        """, (session['usuario_id'],))
        
        result = cursor.fetchone()
        if not result:
            return jsonify({'success': False, 'message': 'Paciente no encontrado'}), 404
        
        columns = [desc[0] for desc in cursor.description]
        paciente = dict(zip(columns, result))
        
        # Convertir fecha a string
        if paciente['fecha_nacimiento']:
            paciente['fecha_nacimiento'] = paciente['fecha_nacimiento'].isoformat()
        
        return jsonify({'success': True, 'paciente': paciente})
    
    except Exception as e:
        print(f"Error al obtener información del paciente: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/pacientes/<int:paciente_id>', methods=['GET'])
@login_required
def get_paciente(paciente_id):
    """Obtener información detallada de un paciente"""
    try:
        # Verificar permisos
        if session['rol'] == 'paciente':
            # Un paciente solo puede ver su propia información
            mi_paciente_id = get_paciente_id_from_user()
            if paciente_id != mi_paciente_id:
                return jsonify({'success': False, 'message': 'No autorizado'}), 403

        cursor = db.session.connection().connection.cursor()
        
        # Datos básicos del paciente
        cursor.execute("""
            SELECT p.*, u.email
            FROM pacientes p
            JOIN usuarios u ON p.usuario_id = u.id
            WHERE p.id = %s
        """, (paciente_id,))
        
        result = cursor.fetchone()
        if not result:
            return jsonify({'success': False, 'message': 'Paciente no encontrado'}), 404
        
        columns = [desc[0] for desc in cursor.description]
        paciente = dict(zip(columns, result))
        
        # Convertir fecha a string
        if paciente['fecha_nacimiento']:
            paciente['fecha_nacimiento'] = paciente['fecha_nacimiento'].isoformat()
        
        return jsonify({'success': True, 'paciente': paciente})
    
    except Exception as e:
        print(f"Error al obtener paciente: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

# ===================== RUTAS DE ALERGIAS =====================

@app.route('/pacientes/<int:paciente_id>/alergias', methods=['GET'])
@login_required
def get_alergias(paciente_id):
    """Obtener alergias de un paciente"""
    try:
        # Verificar permisos
        if session['rol'] == 'paciente' and get_paciente_id_from_user() != paciente_id:
            return jsonify({'success': False, 'message': 'No autorizado'}), 403

        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            SELECT id, nombre, tipo, severidad, reaccion, fecha_diagnostico, notas
            FROM alergias
            WHERE paciente_id = %s
            ORDER BY fecha_diagnostico DESC
        """, (paciente_id,))
        
        columns = [desc[0] for desc in cursor.description]
        alergias = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        # Convertir fechas a string
        for a in alergias:
            if a['fecha_diagnostico']:
                a['fecha_diagnostico'] = a['fecha_diagnostico'].isoformat()
        
        return jsonify({'success': True, 'alergias': alergias})
    
    except Exception as e:
        print(f"Error al obtener alergias: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/pacientes/<int:paciente_id>/alergias', methods=['POST'])
@login_required
@role_required('medico', 'administrador')
def add_alergia(paciente_id):
    """Agregar nueva alergia a un paciente"""
    try:
        data = request.get_json()
        
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            INSERT INTO alergias (
                paciente_id, nombre, tipo, severidad, reaccion, 
                fecha_diagnostico, notas, fecha_registro
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
            RETURNING id
        """, (
            paciente_id,
            data.get('nombre'),
            data.get('tipo'),
            data.get('severidad'),
            data.get('reaccion'),
            data.get('fecha_diagnostico'),
            data.get('notas')
        ))
        
        alergia_id = cursor.fetchone()[0]
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Alergia registrada exitosamente',
            'alergia_id': alergia_id
        }), 201
    
    except Exception as e:
        db.session.rollback()
        print(f"Error al agregar alergia: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

# ===================== RUTAS DE ENFERMEDADES =====================

@app.route('/pacientes/<int:paciente_id>/enfermedades', methods=['GET'])
@login_required
def get_enfermedades(paciente_id):
    """Obtener enfermedades de un paciente"""
    try:
        if session['rol'] == 'paciente' and get_paciente_id_from_user() != paciente_id:
            return jsonify({'success': False, 'message': 'No autorizado'}), 403

        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            SELECT id, nombre, tipo, fecha_diagnostico, estado, tratamiento, notas
            FROM enfermedades
            WHERE paciente_id = %s
            ORDER BY fecha_diagnostico DESC
        """, (paciente_id,))
        
        columns = [desc[0] for desc in cursor.description]
        enfermedades = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        for e in enfermedades:
            if e['fecha_diagnostico']:
                e['fecha_diagnostico'] = e['fecha_diagnostico'].isoformat()
        
        return jsonify({'success': True, 'enfermedades': enfermedades})
    
    except Exception as e:
        print(f"Error al obtener enfermedades: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/pacientes/<int:paciente_id>/enfermedades', methods=['POST'])
@login_required
@role_required('medico', 'administrador')
def add_enfermedad(paciente_id):
    """Agregar nueva enfermedad a un paciente"""
    try:
        data = request.get_json()
        
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            INSERT INTO enfermedades (
                paciente_id, nombre, tipo, fecha_diagnostico, 
                estado, tratamiento, notas, fecha_registro
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
            RETURNING id
        """, (
            paciente_id,
            data.get('nombre'),
            data.get('tipo'),
            data.get('fecha_diagnostico'),
            data.get('estado', 'activa'),
            data.get('tratamiento'),
            data.get('notas')
        ))
        
        enfermedad_id = cursor.fetchone()[0]
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Enfermedad registrada exitosamente',
            'enfermedad_id': enfermedad_id
        }), 201
    
    except Exception as e:
        db.session.rollback()
        print(f"Error al agregar enfermedad: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

# ===================== RUTAS DE CIRUGÍAS =====================

@app.route('/pacientes/<int:paciente_id>/cirugias', methods=['GET'])
@login_required
def get_cirugias(paciente_id):
    """Obtener cirugías de un paciente"""
    try:
        if session['rol'] == 'paciente' and get_paciente_id_from_user() != paciente_id:
            return jsonify({'success': False, 'message': 'No autorizado'}), 403

        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            SELECT id, nombre, fecha_cirugia, hospital, cirujano, 
                   complicaciones, notas
            FROM cirugias
            WHERE paciente_id = %s
            ORDER BY fecha_cirugia DESC
        """, (paciente_id,))
        
        columns = [desc[0] for desc in cursor.description]
        cirugias = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        for c in cirugias:
            if c['fecha_cirugia']:
                c['fecha_cirugia'] = c['fecha_cirugia'].isoformat()
        
        return jsonify({'success': True, 'cirugias': cirugias})
    
    except Exception as e:
        print(f"Error al obtener cirugías: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/pacientes/<int:paciente_id>/cirugias', methods=['POST'])
@login_required
@role_required('medico', 'administrador')
def add_cirugia(paciente_id):
    """Agregar nueva cirugía a un paciente"""
    try:
        data = request.get_json()
        
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            INSERT INTO cirugias (
                paciente_id, nombre, fecha_cirugia, hospital, 
                cirujano, complicaciones, notas, fecha_registro
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
            RETURNING id
        """, (
            paciente_id,
            data.get('nombre'),
            data.get('fecha_cirugia'),
            data.get('hospital'),
            data.get('cirujano'),
            data.get('complicaciones'),
            data.get('notas')
        ))
        
        cirugia_id = cursor.fetchone()[0]
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Cirugía registrada exitosamente',
            'cirugia_id': cirugia_id
        }), 201
    
    except Exception as e:
        db.session.rollback()
        print(f"Error al agregar cirugía: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

# ===================== RUTAS DE VACUNAS =====================

@app.route('/pacientes/<int:paciente_id>/vacunas', methods=['GET'])
@login_required
def get_vacunas(paciente_id):
    """Obtener vacunas de un paciente"""
    try:
        if session['rol'] == 'paciente' and get_paciente_id_from_user() != paciente_id:
            return jsonify({'success': False, 'message': 'No autorizado'}), 403

        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            SELECT id, nombre, fecha_aplicacion, dosis, lote, 
                   proxima_dosis, notas
            FROM vacunas
            WHERE paciente_id = %s
            ORDER BY fecha_aplicacion DESC
        """, (paciente_id,))
        
        columns = [desc[0] for desc in cursor.description]
        vacunas = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        for v in vacunas:
            if v['fecha_aplicacion']:
                v['fecha_aplicacion'] = v['fecha_aplicacion'].isoformat()
            if v['proxima_dosis']:
                v['proxima_dosis'] = v['proxima_dosis'].isoformat()
        
        return jsonify({'success': True, 'vacunas': vacunas})
    
    except Exception as e:
        print(f"Error al obtener vacunas: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/pacientes/<int:paciente_id>/vacunas', methods=['POST'])
@login_required
@role_required('medico', 'administrador')
def add_vacuna(paciente_id):
    """Agregar nueva vacuna a un paciente"""
    try:
        data = request.get_json()
        
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            INSERT INTO vacunas (
                paciente_id, nombre, fecha_aplicacion, dosis, 
                lote, proxima_dosis, notas, fecha_registro
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
            RETURNING id
        """, (
            paciente_id,
            data.get('nombre'),
            data.get('fecha_aplicacion'),
            data.get('dosis'),
            data.get('lote'),
            data.get('proxima_dosis'),
            data.get('notas')
        ))
        
        vacuna_id = cursor.fetchone()[0]
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Vacuna registrada exitosamente',
            'vacuna_id': vacuna_id
        }), 201
    
    except Exception as e:
        db.session.rollback()
        print(f"Error al agregar vacuna: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

# ===================== RUTAS DE MEDICAMENTOS =====================

@app.route('/pacientes/<int:paciente_id>/medicamentos', methods=['GET'])
@login_required
def get_medicamentos(paciente_id):
    """Obtener medicamentos de un paciente"""
    try:
        if session['rol'] == 'paciente' and get_paciente_id_from_user() != paciente_id:
            return jsonify({'success': False, 'message': 'No autorizado'}), 403

        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            SELECT id, nombre, dosis, frecuencia, via_administracion, 
                   fecha_inicio, fecha_fin, medico_prescriptor, notas
            FROM medicamentos
            WHERE paciente_id = %s
            ORDER BY fecha_inicio DESC
        """, (paciente_id,))
        
        columns = [desc[0] for desc in cursor.description]
        medicamentos = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        for m in medicamentos:
            if m['fecha_inicio']:
                m['fecha_inicio'] = m['fecha_inicio'].isoformat()
            if m['fecha_fin']:
                m['fecha_fin'] = m['fecha_fin'].isoformat()
        
        return jsonify({'success': True, 'medicamentos': medicamentos})
    
    except Exception as e:
        print(f"Error al obtener medicamentos: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/pacientes/<int:paciente_id>/medicamentos', methods=['POST'])
@login_required
@role_required('medico', 'administrador')
def add_medicamento(paciente_id):
    """Agregar nuevo medicamento a un paciente"""
    try:
        data = request.get_json()
        
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            INSERT INTO medicamentos (
                paciente_id, nombre, dosis, frecuencia, via_administracion,
                fecha_inicio, fecha_fin, medico_prescriptor, notas, fecha_registro
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
            RETURNING id
        """, (
            paciente_id,
            data.get('nombre'),
            data.get('dosis'),
            data.get('frecuencia'),
            data.get('via_administracion'),
            data.get('fecha_inicio'),
            data.get('fecha_fin'),
            data.get('medico_prescriptor'),
            data.get('notas')
        ))
        
        medicamento_id = cursor.fetchone()[0]
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Medicamento registrado exitosamente',
            'medicamento_id': medicamento_id
        }), 201
    
    except Exception as e:
        db.session.rollback()
        print(f"Error al agregar medicamento: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

# ===================== RUTAS DE HÁBITOS =====================

@app.route('/pacientes/<int:paciente_id>/habitos', methods=['GET'])
@login_required
def get_habitos(paciente_id):
    """Obtener hábitos de salud de un paciente"""
    try:
        if session['rol'] == 'paciente' and get_paciente_id_from_user() != paciente_id:
            return jsonify({'success': False, 'message': 'No autorizado'}), 403

        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            SELECT id, tipo, descripcion, frecuencia, fecha_inicio, 
                   fecha_fin, notas
            FROM habitos
            WHERE paciente_id = %s
            ORDER BY fecha_inicio DESC
        """, (paciente_id,))
        
        columns = [desc[0] for desc in cursor.description]
        habitos = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        for h in habitos:
            if h['fecha_inicio']:
                h['fecha_inicio'] = h['fecha_inicio'].isoformat()
            if h['fecha_fin']:
                h['fecha_fin'] = h['fecha_fin'].isoformat()
        
        return jsonify({'success': True, 'habitos': habitos})
    
    except Exception as e:
        print(f"Error al obtener hábitos: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/pacientes/<int:paciente_id>/habitos', methods=['POST'])
@login_required
@role_required('medico', 'administrador')
def add_habito(paciente_id):
    """Agregar nuevo hábito de salud a un paciente"""
    try:
        data = request.get_json()
        
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            INSERT INTO habitos (
                paciente_id, tipo, descripcion, frecuencia,
                fecha_inicio, fecha_fin, notas, fecha_registro
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
            RETURNING id
        """, (
            paciente_id,
            data.get('tipo'),
            data.get('descripcion'),
            data.get('frecuencia'),
            data.get('fecha_inicio'),
            data.get('fecha_fin'),
            data.get('notas')
        ))
        
        habito_id = cursor.fetchone()[0]
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Hábito registrado exitosamente',
            'habito_id': habito_id
        }), 201
    
    except Exception as e:
        db.session.rollback()
        print(f"Error al agregar hábito: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

# ===================== RUTAS DE ANTECEDENTES FAMILIARES =====================

@app.route('/pacientes/<int:paciente_id>/antecedentes-familiares', methods=['GET'])
@login_required
def get_antecedentes_familiares(paciente_id):
    """Obtener antecedentes familiares de un paciente"""
    try:
        if session['rol'] == 'paciente' and get_paciente_id_from_user() != paciente_id:
            return jsonify({'success': False, 'message': 'No autorizado'}), 403

        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            SELECT id, parentesco, enfermedad, edad_diagnostico, 
                   estado, notas
            FROM antecedentes_familiares
            WHERE paciente_id = %s
            ORDER BY parentesco, enfermedad
        """, (paciente_id,))
        
        columns = [desc[0] for desc in cursor.description]
        antecedentes = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        return jsonify({'success': True, 'antecedentes_familiares': antecedentes})
    
    except Exception as e:
        print(f"Error al obtener antecedentes familiares: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/pacientes/<int:paciente_id>/antecedentes-familiares', methods=['POST'])
@login_required
@role_required('medico', 'administrador')
def add_antecedente_familiar(paciente_id):
    """Agregar nuevo antecedente familiar a un paciente"""
    try:
        data = request.get_json()
        
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            INSERT INTO antecedentes_familiares (
                paciente_id, parentesco, enfermedad, edad_diagnostico,
                estado, notas, fecha_registro
            ) VALUES (%s, %s, %s, %s, %s, %s, NOW())
            RETURNING id
        """, (
            paciente_id,
            data.get('parentesco'),
            data.get('enfermedad'),
            data.get('edad_diagnostico'),
            data.get('estado'),
            data.get('notas')
        ))
        
        antecedente_id = cursor.fetchone()[0]
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Antecedente familiar registrado exitosamente',
            'antecedente_id': antecedente_id
        }), 201
    
    except Exception as e:
        db.session.rollback()
        print(f"Error al agregar antecedente familiar: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

# ===================== RUTAS DE ARCHIVOS MÉDICOS =====================

@app.route('/pacientes/<int:paciente_id>/archivos', methods=['GET'])
@login_required
def get_archivos(paciente_id):
    """Obtener archivos médicos de un paciente"""
    try:
        # Validar permisos: los médicos pueden ver todos, los pacientes solo los suyos
        if session['rol'] == 'paciente' and get_paciente_id_from_user() != paciente_id:
            return jsonify({'success': False, 'message': 'No autorizado'}), 403

        cursor = db.session.connection().connection.cursor()
        # Consulta simplificada para evitar errores de JOIN
        cursor.execute("""
            SELECT id, nombre_archivo, tipo_archivo, categoria,
                   descripcion, fecha_subida, tamano_kb
            FROM archivos_medicos
            WHERE paciente_id = %s
            ORDER BY fecha_subida DESC
        """, (paciente_id,))
        
        columns = [desc[0] for desc in cursor.description]
        archivos = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        # Convertir fechas a string ISO
        for a in archivos:
            if a.get('fecha_subida'):
                a['fecha_subida'] = a['fecha_subida'].isoformat()
        
        return jsonify({'success': True, 'archivos': archivos})
    
    except Exception as e:
        print(f"Error al obtener archivos: {str(e)}")
        import traceback
        traceback.print_exc()  # Esto imprimirá el error completo en la consola
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/pacientes/<int:paciente_id>/archivos', methods=['POST'])
@login_required
@role_required('medico', 'administrador')
def upload_archivo(paciente_id):
    """Subir archivo médico para un paciente"""
    try:
        # Verificar que el paciente existe
        cursor = db.session.connection().connection.cursor()
        cursor.execute("SELECT id FROM pacientes WHERE id = %s", (paciente_id,))
        if not cursor.fetchone():
            return jsonify({'success': False, 'message': 'Paciente no encontrado'}), 404

        # Verificar que se envió un archivo
        if 'archivo' not in request.files:
            return jsonify({'success': False, 'message': 'No se envió ningún archivo'}), 400
        
        file = request.files['archivo']
        
        if file.filename == '':
            return jsonify({'success': False, 'message': 'Nombre de archivo vacío'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'success': False, 'message': 'Tipo de archivo no permitido'}), 400
        
        # Crear nombre de archivo seguro y único
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        unique_filename = f"{paciente_id}_{timestamp}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        # Guardar archivo
        file.save(filepath)
        
        # Obtener tamaño del archivo en KB
        file_size_kb = os.path.getsize(filepath) / 1024
        
        # Obtener ID del médico si es médico
        medico_id = None
        if session['rol'] == 'medico':
            cursor.execute("SELECT id FROM medicos WHERE usuario_id = %s", (session['usuario_id'],))
            result = cursor.fetchone()
            medico_id = result[0] if result else None
        
        # Registrar en base de datos
        cursor.execute("""
            INSERT INTO archivos_medicos (
                paciente_id, nombre_archivo, nombre_original, tipo_archivo,
                categoria, descripcion, ruta_archivo, tamano_kb,
                subido_por_medico_id, fecha_subida
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
            RETURNING id
        """, (
            paciente_id,
            unique_filename,
            filename,
            file.content_type,
            request.form.get('categoria', 'otros'),
            request.form.get('descripcion', ''),
            filepath,
            file_size_kb,
            medico_id
        ))
        
        archivo_id = cursor.fetchone()[0]
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Archivo subido exitosamente',
            'archivo_id': archivo_id,
            'filename': unique_filename
        }), 201
    
    except Exception as e:
        db.session.rollback()
        print(f"Error al subir archivo: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/archivos/<int:archivo_id>/download', methods=['GET'])
@login_required
def download_archivo(archivo_id):
    """Descargar archivo médico"""
    try:
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            SELECT a.nombre_archivo, a.ruta_archivo, a.paciente_id
            FROM archivos_medicos a
            WHERE a.id = %s
        """, (archivo_id,))
        
        result = cursor.fetchone()
        if not result:
            return jsonify({'success': False, 'message': 'Archivo no encontrado'}), 404
        
        nombre_archivo, ruta_archivo, paciente_id = result
        
        # Verificar permisos
        if session['rol'] == 'paciente':
            mi_paciente_id = get_paciente_id_from_user()
            if paciente_id != mi_paciente_id:
                return jsonify({'success': False, 'message': 'No autorizado'}), 403
        
        return send_from_directory(
            app.config['UPLOAD_FOLDER'],
            nombre_archivo,
            as_attachment=True
        )
    
    except Exception as e:
        print(f"Error al descargar archivo: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

# ===================== RUTAS DE HISTORIAL COMPLETO =====================

@app.route('/pacientes/<int:paciente_id>/historial-completo', methods=['GET'])
@login_required
def get_historial_completo(paciente_id):
    """Obtener el historial médico completo de un paciente"""
    try:
        # Verificar permisos
        if session['rol'] == 'paciente' and get_paciente_id_from_user() != paciente_id:
            return jsonify({'success': False, 'message': 'No autorizado'}), 403

        cursor = db.session.connection().connection.cursor()
        
        # Datos del paciente
        cursor.execute("""
            SELECT p.*, u.email
            FROM pacientes p
            JOIN usuarios u ON p.usuario_id = u.id
            WHERE p.id = %s
        """, (paciente_id,))
        
        result = cursor.fetchone()
        if not result:
            return jsonify({'success': False, 'message': 'Paciente no encontrado'}), 404
        
        columns = [desc[0] for desc in cursor.description]
        paciente = dict(zip(columns, result))
        if paciente['fecha_nacimiento']:
            paciente['fecha_nacimiento'] = paciente['fecha_nacimiento'].isoformat()
        
        # Alergias
        cursor.execute("""
            SELECT * FROM alergias WHERE paciente_id = %s ORDER BY fecha_diagnostico DESC
        """, (paciente_id,))
        alergias = [dict(zip([desc[0] for desc in cursor.description], row)) for row in cursor.fetchall()]
        
        # Enfermedades
        cursor.execute("""
            SELECT * FROM enfermedades WHERE paciente_id = %s ORDER BY fecha_diagnostico DESC
        """, (paciente_id,))
        enfermedades = [dict(zip([desc[0] for desc in cursor.description], row)) for row in cursor.fetchall()]
        
        # Cirugías
        cursor.execute("""
            SELECT * FROM cirugias WHERE paciente_id = %s ORDER BY fecha_cirugia DESC
        """, (paciente_id,))
        cirugias = [dict(zip([desc[0] for desc in cursor.description], row)) for row in cursor.fetchall()]
        
        # Vacunas
        cursor.execute("""
            SELECT * FROM vacunas WHERE paciente_id = %s ORDER BY fecha_aplicacion DESC
        """, (paciente_id,))
        vacunas = [dict(zip([desc[0] for desc in cursor.description], row)) for row in cursor.fetchall()]
        
        # Medicamentos
        cursor.execute("""
            SELECT * FROM medicamentos WHERE paciente_id = %s ORDER BY fecha_inicio DESC
        """, (paciente_id,))
        medicamentos = [dict(zip([desc[0] for desc in cursor.description], row)) for row in cursor.fetchall()]
        
        # Hábitos
        cursor.execute("""
            SELECT * FROM habitos WHERE paciente_id = %s ORDER BY fecha_inicio DESC
        """, (paciente_id,))
        habitos = [dict(zip([desc[0] for desc in cursor.description], row)) for row in cursor.fetchall()]
        
        # Antecedentes familiares
        cursor.execute("""
            SELECT * FROM antecedentes_familiares WHERE paciente_id = %s
        """, (paciente_id,))
        antecedentes_familiares = [dict(zip([desc[0] for desc in cursor.description], row)) for row in cursor.fetchall()]
        
        # Archivos
        cursor.execute("""
            SELECT id, nombre_archivo, tipo_archivo, categoria, descripcion, 
                   fecha_subida, tamano_kb
            FROM archivos_medicos WHERE paciente_id = %s ORDER BY fecha_subida DESC
        """, (paciente_id,))
        archivos = [dict(zip([desc[0] for desc in cursor.description], row)) for row in cursor.fetchall()]
        
        # Construir historial completo
        historial_completo = {
            'paciente': paciente,
            'alergias': alergias,
            'enfermedades': enfermedades,
            'cirugias': cirugias,
            'vacunas': vacunas,
            'medicamentos': medicamentos,
            'habitos': habitos,
            'antecedentes_familiares': antecedentes_familiares,
            'archivos': archivos
        }
        
        return jsonify({'success': True, 'historial': historial_completo})
    
    except Exception as e:
        print(f"Error al obtener historial completo: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

# ===================== RUTAS DE MÉDICOS =====================

@app.route('/medicos', methods=['GET'])
@login_required
@role_required('administrador')
def get_medicos():
    """Obtener lista de médicos (solo administradores)"""
    try:
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            SELECT m.id, m.nombres, m.apellidos, m.especialidad, 
                   m.licencia_medica, m.telefono, u.email
            FROM medicos m
            JOIN usuarios u ON m.usuario_id = u.id
            WHERE u.activo = true
            ORDER BY m.apellidos, m.nombres
        """)
        
        columns = ['id', 'nombres', 'apellidos', 'especialidad', 
                   'licencia_medica', 'telefono', 'email']
        medicos = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        return jsonify({'success': True, 'medicos': medicos})
    
    except Exception as e:
        print(f"Error al obtener médicos: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/register-medico', methods=['POST'])
@login_required
@role_required('administrador')
def register_medico():
    """Registrar nuevo médico (solo administradores)"""
    try:
        data = request.get_json()
        
        # Validar datos requeridos
        required_fields = ['email', 'contrasena', 'nombres', 'apellidos', 'especialidad', 'licencia_medica']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'message': f'Campo {field} es requerido'}), 400

        cursor = db.session.connection().connection.cursor()
        
        # Verificar si el email ya existe
        cursor.execute("SELECT id FROM usuarios WHERE email = %s", (data['email'],))
        if cursor.fetchone():
            return jsonify({'success': False, 'message': 'El email ya está registrado'}), 400

        # Crear usuario
        cursor.execute("""
            INSERT INTO usuarios (email, contrasena, rol, activo, fecha_creacion)
            VALUES (%s, %s, 'medico', true, NOW())
            RETURNING id
        """, (data['email'], data['contrasena']))
        
        usuario_id = cursor.fetchone()[0]

        # Crear médico
        cursor.execute("""
            INSERT INTO medicos (
                usuario_id, nombres, apellidos, especialidad, 
                licencia_medica, telefono
            ) VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            usuario_id,
            data['nombres'],
            data['apellidos'],
            data['especialidad'],
            data['licencia_medica'],
            data.get('telefono')
        ))
        
        medico_id = cursor.fetchone()[0]
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Médico registrado exitosamente',
            'usuario_id': usuario_id,
            'medico_id': medico_id
        }), 201

    except Exception as e:
        db.session.rollback()
        print(f"Error en registro de médico: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

# ===================== RUTAS CRUD ADICIONALES =====================

# ===== ACTUALIZAR DATOS DE PACIENTE =====
@app.route('/pacientes/<int:paciente_id>', methods=['PUT'])
@login_required
@role_required('administrador', 'medico')
def update_paciente(paciente_id):
    """Actualizar información de un paciente"""
    try:
        data = request.get_json()
        cursor = db.session.connection().connection.cursor()
        
        # Construir query dinámica
        campos = []
        valores = []
        
        if 'nombres' in data:
            campos.append("nombres = %s")
            valores.append(data['nombres'])
        if 'apellidos' in data:
            campos.append("apellidos = %s")
            valores.append(data['apellidos'])
        if 'identificacion' in data:
            campos.append("identificacion = %s")
            valores.append(data['identificacion'])
        if 'fecha_nacimiento' in data:
            campos.append("fecha_nacimiento = %s")
            valores.append(data['fecha_nacimiento'])
        if 'genero' in data:
            campos.append("genero = %s")
            valores.append(data['genero'])
        if 'telefono' in data:
            campos.append("telefono = %s")
            valores.append(data['telefono'])
        if 'direccion' in data:
            campos.append("direccion = %s")
            valores.append(data['direccion'])
        if 'contacto_emergencia_nombre' in data:
            campos.append("contacto_emergencia_nombre = %s")
            valores.append(data['contacto_emergencia_nombre'])
        if 'contacto_emergencia_telefono' in data:
            campos.append("contacto_emergencia_telefono = %s")
            valores.append(data['contacto_emergencia_telefono'])
        if 'contacto_emergencia_relacion' in data:
            campos.append("contacto_emergencia_relacion = %s")
            valores.append(data['contacto_emergencia_relacion'])
        
        if not campos:
            return jsonify({'success': False, 'message': 'No hay campos para actualizar'}), 400
        
        valores.append(paciente_id)
        query = f"UPDATE pacientes SET {', '.join(campos)} WHERE id = %s"
        
        cursor.execute(query, tuple(valores))
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Paciente actualizado exitosamente'})
    
    except Exception as e:
        db.session.rollback()
        print(f"Error al actualizar paciente: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

# ===== ELIMINAR PACIENTE =====
@app.route('/pacientes/<int:paciente_id>', methods=['DELETE'])
@login_required
@role_required('administrador')
def delete_paciente(paciente_id):
    """Eliminar un paciente (solo administrador)"""
    try:
        cursor = db.session.connection().connection.cursor()
        
        # Primero obtener el usuario_id
        cursor.execute("SELECT usuario_id FROM pacientes WHERE id = %s", (paciente_id,))
        result = cursor.fetchone()
        
        if not result:
            return jsonify({'success': False, 'message': 'Paciente no encontrado'}), 404
        
        usuario_id = result[0]
        
        # Eliminar paciente (las foreign keys en CASCADE eliminarán registros relacionados)
        cursor.execute("DELETE FROM pacientes WHERE id = %s", (paciente_id,))
        cursor.execute("DELETE FROM usuarios WHERE id = %s", (usuario_id,))
        
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Paciente eliminado exitosamente'})
    
    except Exception as e:
        db.session.rollback()
        print(f"Error al eliminar paciente: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

# ===== ACTUALIZAR DATOS DE MÉDICO =====
@app.route('/medicos/<int:medico_id>', methods=['PUT'])
@login_required
@role_required('administrador')
def update_medico(medico_id):
    """Actualizar información de un médico"""
    try:
        data = request.get_json()
        cursor = db.session.connection().connection.cursor()
        
        campos = []
        valores = []
        
        if 'nombres' in data:
            campos.append("nombres = %s")
            valores.append(data['nombres'])
        if 'apellidos' in data:
            campos.append("apellidos = %s")
            valores.append(data['apellidos'])
        if 'especialidad' in data:
            campos.append("especialidad = %s")
            valores.append(data['especialidad'])
        if 'licencia_medica' in data:
            campos.append("licencia_medica = %s")
            valores.append(data['licencia_medica'])
        if 'telefono' in data:
            campos.append("telefono = %s")
            valores.append(data['telefono'])
        
        if not campos:
            return jsonify({'success': False, 'message': 'No hay campos para actualizar'}), 400
        
        valores.append(medico_id)
        query = f"UPDATE medicos SET {', '.join(campos)} WHERE id = %s"
        
        cursor.execute(query, tuple(valores))
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Médico actualizado exitosamente'})
    
    except Exception as e:
        db.session.rollback()
        print(f"Error al actualizar médico: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

# ===== ELIMINAR MÉDICO =====
@app.route('/medicos/<int:medico_id>', methods=['DELETE'])
@login_required
@role_required('administrador')
def delete_medico(medico_id):
    """Eliminar un médico (solo administrador)"""
    try:
        cursor = db.session.connection().connection.cursor()
        
        # Obtener usuario_id
        cursor.execute("SELECT usuario_id FROM medicos WHERE id = %s", (medico_id,))
        result = cursor.fetchone()
        
        if not result:
            return jsonify({'success': False, 'message': 'Médico no encontrado'}), 404
        
        usuario_id = result[0]
        
        # Eliminar médico
        cursor.execute("DELETE FROM medicos WHERE id = %s", (medico_id,))
        cursor.execute("DELETE FROM usuarios WHERE id = %s", (usuario_id,))
        
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Médico eliminado exitosamente'})
    
    except Exception as e:
        db.session.rollback()
        print(f"Error al eliminar médico: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

# ===== ACTUALIZAR REGISTROS MÉDICOS (Alergias, Enfermedades, etc.) =====
@app.route('/pacientes/<int:paciente_id>/alergias/<int:alergia_id>', methods=['PUT'])
@login_required
def update_alergia(paciente_id, alergia_id):
    """Actualizar alergia"""
    try:
        # Verificar permisos
        if session['rol'] == 'paciente' and get_paciente_id_from_user() != paciente_id:
            return jsonify({'success': False, 'message': 'No autorizado'}), 403
        
        data = request.get_json()
        cursor = db.session.connection().connection.cursor()
        
        campos = []
        valores = []
        
        if 'nombre' in data:
            campos.append("nombre = %s")
            valores.append(data['nombre'])
        if 'tipo' in data:
            campos.append("tipo = %s")
            valores.append(data['tipo'])
        if 'severidad' in data:
            campos.append("severidad = %s")
            valores.append(data['severidad'])
        if 'reaccion' in data:
            campos.append("reaccion = %s")
            valores.append(data['reaccion'])
        if 'notas' in data:
            campos.append("notas = %s")
            valores.append(data['notas'])
        
        if not campos:
            return jsonify({'success': False, 'message': 'No hay campos para actualizar'}), 400
        
        valores.extend([alergia_id, paciente_id])
        query = f"UPDATE alergias SET {', '.join(campos)} WHERE id = %s AND paciente_id = %s"
        
        cursor.execute(query, tuple(valores))
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Alergia actualizada exitosamente'})
    
    except Exception as e:
        db.session.rollback()
        print(f"Error al actualizar alergia: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/pacientes/<int:paciente_id>/alergias/<int:alergia_id>', methods=['DELETE'])
@login_required
def delete_alergia(paciente_id, alergia_id):
    """Eliminar alergia"""
    try:
        # Verificar permisos
        if session['rol'] == 'paciente' and get_paciente_id_from_user() != paciente_id:
            return jsonify({'success': False, 'message': 'No autorizado'}), 403
        
        cursor = db.session.connection().connection.cursor()
        cursor.execute("DELETE FROM alergias WHERE id = %s AND paciente_id = %s", (alergia_id, paciente_id))
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Alergia eliminada exitosamente'})
    
    except Exception as e:
        db.session.rollback()
        print(f"Error al eliminar alergia: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

# Rutas similares para enfermedades, cirugías, medicamentos, vacunas, hábitos
@app.route('/pacientes/<int:paciente_id>/enfermedades/<int:enfermedad_id>', methods=['DELETE'])
@login_required
def delete_enfermedad(paciente_id, enfermedad_id):
    """Eliminar enfermedad"""
    try:
        if session['rol'] == 'paciente' and get_paciente_id_from_user() != paciente_id:
            return jsonify({'success': False, 'message': 'No autorizado'}), 403
        
        cursor = db.session.connection().connection.cursor()
        cursor.execute("DELETE FROM enfermedades WHERE id = %s AND paciente_id = %s", (enfermedad_id, paciente_id))
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Enfermedad eliminada exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/pacientes/<int:paciente_id>/cirugias/<int:cirugia_id>', methods=['DELETE'])
@login_required
def delete_cirugia(paciente_id, cirugia_id):
    """Eliminar cirugía"""
    try:
        if session['rol'] == 'paciente' and get_paciente_id_from_user() != paciente_id:
            return jsonify({'success': False, 'message': 'No autorizado'}), 403
        
        cursor = db.session.connection().connection.cursor()
        cursor.execute("DELETE FROM cirugias WHERE id = %s AND paciente_id = %s", (cirugia_id, paciente_id))
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Cirugía eliminada exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/pacientes/<int:paciente_id>/medicamentos/<int:medicamento_id>', methods=['DELETE'])
@login_required
def delete_medicamento(paciente_id, medicamento_id):
    """Eliminar medicamento"""
    try:
        if session['rol'] == 'paciente' and get_paciente_id_from_user() != paciente_id:
            return jsonify({'success': False, 'message': 'No autorizado'}), 403
        
        cursor = db.session.connection().connection.cursor()
        cursor.execute("DELETE FROM medicamentos WHERE id = %s AND paciente_id = %s", (medicamento_id, paciente_id))
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Medicamento eliminado exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/pacientes/<int:paciente_id>/vacunas/<int:vacuna_id>', methods=['DELETE'])
@login_required
def delete_vacuna(paciente_id, vacuna_id):
    """Eliminar vacuna"""
    try:
        if session['rol'] == 'paciente' and get_paciente_id_from_user() != paciente_id:
            return jsonify({'success': False, 'message': 'No autorizado'}), 403
        
        cursor = db.session.connection().connection.cursor()
        cursor.execute("DELETE FROM vacunas WHERE id = %s AND paciente_id = %s", (vacuna_id, paciente_id))
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Vacuna eliminada exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/pacientes/<int:paciente_id>/habitos/<int:habito_id>', methods=['DELETE'])
@login_required
def delete_habito(paciente_id, habito_id):
    """Eliminar hábito"""
    try:
        if session['rol'] == 'paciente' and get_paciente_id_from_user() != paciente_id:
            return jsonify({'success': False, 'message': 'No autorizado'}), 403
        
        cursor = db.session.connection().connection.cursor()
        cursor.execute("DELETE FROM habitos WHERE id = %s AND paciente_id = %s", (habito_id, paciente_id))
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Hábito eliminado exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/pacientes/<int:paciente_id>/antecedentes-familiares/<int:antecedente_id>', methods=['DELETE'])
@login_required
def delete_antecedente(paciente_id, antecedente_id):
    """Eliminar antecedente familiar"""
    try:
        if session['rol'] == 'paciente' and get_paciente_id_from_user() != paciente_id:
            return jsonify({'success': False, 'message': 'No autorizado'}), 403
        
        cursor = db.session.connection().connection.cursor()
        cursor.execute("DELETE FROM antecedentes_familiares WHERE id = %s AND paciente_id = %s", (antecedente_id, paciente_id))
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Antecedente familiar eliminado exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/medico/archivos/<int:archivo_id>', methods=['DELETE'])
@login_required
def delete_archivo(archivo_id):
    """Eliminar archivo médico"""
    try:
        cursor = db.session.connection().connection.cursor()
        
        # Obtener info del archivo
        cursor.execute("SELECT paciente_id, ruta_archivo FROM archivos_medicos WHERE id = %s", (archivo_id,))
        result = cursor.fetchone()
        
        if not result:
            return jsonify({'success': False, 'message': 'Archivo no encontrado'}), 404
        
        paciente_id, ruta_archivo = result
        
        # Verificar permisos
        if session['rol'] == 'paciente' and get_paciente_id_from_user() != paciente_id:
            return jsonify({'success': False, 'message': 'No autorizado'}), 403
        
        # Eliminar archivo físico
        if ruta_archivo:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], ruta_archivo)
            if os.path.exists(file_path):
                os.remove(file_path)
        
        # Eliminar registro de base de datos
        cursor.execute("DELETE FROM archivos_medicos WHERE id = %s", (archivo_id,))
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Archivo eliminado exitosamente'})
    
    except Exception as e:
        db.session.rollback()
        print(f"Error al eliminar archivo: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

# ===================== GENERACIÓN DE PDF CON REPORTLAB =====================

@app.route('/pacientes/<int:paciente_id>/reporte-pdf', methods=['GET'])
@login_required
def generar_reporte_pdf(paciente_id):
    """Generar PDF del historial médico completo"""
    try:
        # Verificar permisos
        if session['rol'] == 'paciente' and get_paciente_id_from_user() != paciente_id:
            return jsonify({'success': False, 'message': 'No autorizado'}), 403
        
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        from io import BytesIO
        
        cursor = db.session.connection().connection.cursor()
        
        # Obtener datos del paciente
        cursor.execute("""
            SELECT p.*, u.email
            FROM pacientes p
            JOIN usuarios u ON p.usuario_id = u.id
            WHERE p.id = %s
        """, (paciente_id,))
        
        result = cursor.fetchone()
        if not result:
            return jsonify({'success': False, 'message': 'Paciente no encontrado'}), 404
        
        columns = [desc[0] for desc in cursor.description]
        paciente = dict(zip(columns, result))
        
        # Obtener historial médico
        cursor.execute("SELECT * FROM alergias WHERE paciente_id = %s ORDER BY fecha_diagnostico DESC", (paciente_id,))
        alergias = [dict(zip([desc[0] for desc in cursor.description], row)) for row in cursor.fetchall()]
        
        cursor.execute("SELECT * FROM enfermedades WHERE paciente_id = %s ORDER BY fecha_diagnostico DESC", (paciente_id,))
        enfermedades = [dict(zip([desc[0] for desc in cursor.description], row)) for row in cursor.fetchall()]
        
        cursor.execute("SELECT * FROM cirugias WHERE paciente_id = %s ORDER BY fecha_cirugia DESC", (paciente_id,))
        cirugias = [dict(zip([desc[0] for desc in cursor.description], row)) for row in cursor.fetchall()]
        
        cursor.execute("SELECT * FROM medicamentos WHERE paciente_id = %s ORDER BY fecha_inicio DESC", (paciente_id,))
        medicamentos = [dict(zip([desc[0] for desc in cursor.description], row)) for row in cursor.fetchall()]
        
        cursor.execute("SELECT * FROM vacunas WHERE paciente_id = %s ORDER BY fecha_aplicacion DESC", (paciente_id,))
        vacunas = [dict(zip([desc[0] for desc in cursor.description], row)) for row in cursor.fetchall()]
        
        # Crear PDF en memoria
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()
        
        # Estilo personalizado para título
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#667eea'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        
        subtitle_style = ParagraphStyle(
            'Subtitle',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#764ba2'),
            spaceAfter=12,
            spaceBefore=12
        )
        
        # Título
        elements.append(Paragraph("HOSPITAL SANITAS", title_style))
        elements.append(Paragraph("Historial Médico del Paciente", styles['Heading2']))
        elements.append(Spacer(1, 0.3*inch))
        
        # Información del paciente
        elements.append(Paragraph("DATOS DEL PACIENTE", subtitle_style))
        
        datos_paciente = [
            ['Nombre Completo:', f"{paciente['nombres']} {paciente['apellidos']}"],
            ['Identificación:', paciente['identificacion'] or 'N/A'],
            ['Fecha de Nacimiento:', str(paciente['fecha_nacimiento']) if paciente.get('fecha_nacimiento') else 'N/A'],
            ['Género:', paciente['genero'] or 'N/A'],
            ['Teléfono:', paciente['telefono'] or 'N/A'],
            ['Email:', paciente['email']],
        ]
        
        tabla_paciente = Table(datos_paciente, colWidths=[2*inch, 4*inch])
        tabla_paciente.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f5f7fa')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e0e0e0')),
        ]))
        elements.append(tabla_paciente)
        elements.append(Spacer(1, 0.3*inch))
        
        # Alergias
        if alergias:
            elements.append(Paragraph("ALERGIAS", subtitle_style))
            data_alergias = [['Nombre', 'Tipo', 'Severidad', 'Reacción']]
            for a in alergias:
                data_alergias.append([
                    a['nombre'],
                    a['tipo'] or 'N/A',
                    a['severidad'] or 'N/A',
                    a['reaccion'] or 'N/A'
                ])
            
            tabla_alergias = Table(data_alergias, colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 2*inch])
            tabla_alergias.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            elements.append(tabla_alergias)
            elements.append(Spacer(1, 0.2*inch))
        
        # Enfermedades
        if enfermedades:
            elements.append(Paragraph("ENFERMEDADES", subtitle_style))
            data_enfermedades = [['Nombre', 'Estado', 'Fecha Diagnóstico', 'Tratamiento']]
            for e in enfermedades:
                data_enfermedades.append([
                    e['nombre'],
                    e['estado'] or 'N/A',
                    str(e['fecha_diagnostico']) if e.get('fecha_diagnostico') else 'N/A',
                    e['tratamiento'][:30] + '...' if e.get('tratamiento') and len(e['tratamiento']) > 30 else e.get('tratamiento', 'N/A')
                ])
            
            tabla_enfermedades = Table(data_enfermedades, colWidths=[1.5*inch, 1.3*inch, 1.5*inch, 2.2*inch])
            tabla_enfermedades.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            elements.append(tabla_enfermedades)
            elements.append(Spacer(1, 0.2*inch))
        
        # Cirugías
        if cirugias:
            elements.append(Paragraph("CIRUGÍAS", subtitle_style))
            data_cirugias = [['Nombre', 'Fecha', 'Hospital', 'Cirujano']]
            for c in cirugias:
                data_cirugias.append([
                    c['nombre'],
                    str(c['fecha_cirugia']) if c.get('fecha_cirugia') else 'N/A',
                    c['hospital'] or 'N/A',
                    c['cirujano'] or 'N/A'
                ])
            
            tabla_cirugias = Table(data_cirugias, colWidths=[1.8*inch, 1.3*inch, 1.8*inch, 1.6*inch])
            tabla_cirugias.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            elements.append(tabla_cirugias)
            elements.append(Spacer(1, 0.2*inch))
        
        # Medicamentos
        if medicamentos:
            elements.append(Paragraph("MEDICAMENTOS", subtitle_style))
            data_medicamentos = [['Nombre', 'Dosis', 'Frecuencia', 'Fecha Inicio']]
            for m in medicamentos:
                data_medicamentos.append([
                    m['nombre'],
                    m['dosis'] or 'N/A',
                    m['frecuencia'] or 'N/A',
                    str(m['fecha_inicio']) if m.get('fecha_inicio') else 'N/A'
                ])
            
            tabla_medicamentos = Table(data_medicamentos, colWidths=[2*inch, 1.5*inch, 1.5*inch, 1.5*inch])
            tabla_medicamentos.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            elements.append(tabla_medicamentos)
            elements.append(Spacer(1, 0.2*inch))
        
        # Vacunas
        if vacunas:
            elements.append(Paragraph("VACUNAS", subtitle_style))
            data_vacunas = [['Nombre', 'Fecha Aplicación', 'Dosis', 'Institución']]
            for v in vacunas:
                data_vacunas.append([
                    v['nombre'],
                    str(v['fecha_aplicacion']) if v.get('fecha_aplicacion') else 'N/A',
                    v['dosis'] or 'N/A',
                    v.get('institucion', 'N/A')
                ])
            
            tabla_vacunas = Table(data_vacunas, colWidths=[2*inch, 1.5*inch, 1*inch, 2*inch])
            tabla_vacunas.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            elements.append(tabla_vacunas)
        
        # Footer
        elements.append(Spacer(1, 0.5*inch))
        fecha_generacion = datetime.now().strftime('%d/%m/%Y %H:%M')
        elements.append(Paragraph(f"<i>Reporte generado el: {fecha_generacion}</i>", styles['Normal']))
        elements.append(Paragraph("<i>Hospital Sanitas - Sistema de Gestión de Registros Médicos</i>", styles['Normal']))
        
        # Construir PDF
        doc.build(elements)
        
        # Enviar PDF
        buffer.seek(0)
        return send_from_directory(
            directory=os.path.dirname(buffer.name) if hasattr(buffer, 'name') else '.',
            path=buffer.name if hasattr(buffer, 'name') else 'reporte.pdf',
            as_attachment=True,
            download_name=f'historial_medico_{paciente["nombres"]}_{paciente["apellidos"]}.pdf',
            mimetype='application/pdf'
        ) if hasattr(buffer, 'name') else (buffer.getvalue(), 200, {
            'Content-Type': 'application/pdf',
            'Content-Disposition': f'attachment; filename=historial_medico_{paciente["nombres"]}_{paciente["apellidos"]}.pdf'
        })
    
    except Exception as e:
        print(f"Error al generar PDF: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': str(e)}), 500


# ===================== RUTAS DE VISTAS HTML =====================

@app.route('/dashboard-paciente')
@login_required
@role_required('paciente')
def dashboard_paciente():
    """Dashboard para pacientes"""
    return render_template('dashboard_paciente.html')

@app.route('/dashboard-medico')
@login_required
@role_required('medico')
def dashboard_medico():
    """Dashboard para médicos"""
    return render_template('dashboard_medico.html')

@app.route('/dashboard-admin')
@login_required
@role_required('administrador')
def dashboard_admin():
    """Dashboard para administradores"""
    return render_template('dashboard_admin.html')
# ===================== ENDPOINTS CRUD PARA PACIENTES =====================

@app.route('/api/paciente/alergias', methods=['POST'])
@login_required
@role_required('paciente')
def add_alergia_paciente():
    """Agregar una nueva alergia (paciente)"""
    try:
        data = request.get_json()
        paciente_id = get_paciente_id_from_user()
        
        if not paciente_id:
            return jsonify({'success': False, 'message': 'Paciente no encontrado'}), 404

        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            INSERT INTO alergias (paciente_id, nombre, tipo, severidad, reaccion, notas, fecha_diagnostico)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (paciente_id, data.get('nombre'), data.get('tipo'), data.get('severidad'), 
              data.get('reaccion'), data.get('notas'), data.get('fecha_diagnostico')))
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Alergia agregada exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/paciente/alergias/<int:id>', methods=['PUT'])
@login_required
@role_required('paciente')
def update_alergia_paciente(id):
    """Actualizar una alergia (paciente)"""
    try:
        data = request.get_json()
        paciente_id = get_paciente_id_from_user()
        
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            UPDATE alergias SET nombre=%s, tipo=%s, severidad=%s, reaccion=%s, notas=%s, fecha_diagnostico=%s
            WHERE id=%s AND paciente_id=%s
        """, (data.get('nombre'), data.get('tipo'), data.get('severidad'), data.get('reaccion'),
              data.get('notas'), data.get('fecha_diagnostico'), id, paciente_id))
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Alergia actualizada exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/paciente/alergias/<int:id>', methods=['DELETE'])
@login_required
@role_required('paciente')
def delete_alergia_paciente(id):
    """Eliminar una alergia (paciente)"""
    try:
        paciente_id = get_paciente_id_from_user()
        cursor = db.session.connection().connection.cursor()
        cursor.execute("DELETE FROM alergias WHERE id=%s AND paciente_id=%s", (id, paciente_id))
        db.session.commit()
        return jsonify({'success': True, 'message': 'Alergia eliminada exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/paciente/enfermedades', methods=['POST'])
@login_required
@role_required('paciente')
def add_enfermedad_paciente():
    """Agregar una nueva enfermedad (paciente)"""
    try:
        data = request.get_json()
        paciente_id = get_paciente_id_from_user()
        
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            INSERT INTO enfermedades (paciente_id, nombre, estado, fecha_diagnostico, tratamiento, notas)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (paciente_id, data.get('nombre'), data.get('estado'), data.get('fecha_diagnostico'),
              data.get('tratamiento'), data.get('notas')))
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Enfermedad agregada exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/paciente/enfermedades/<int:id>', methods=['PUT'])
@login_required
@role_required('paciente')
def update_enfermedad_paciente(id):
    """Actualizar una enfermedad (paciente)"""
    try:
        data = request.get_json()
        paciente_id = get_paciente_id_from_user()
        
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            UPDATE enfermedades SET nombre=%s, estado=%s, fecha_diagnostico=%s, tratamiento=%s, notas=%s
            WHERE id=%s AND paciente_id=%s
        """, (data.get('nombre'), data.get('estado'), data.get('fecha_diagnostico'),
              data.get('tratamiento'), data.get('notas'), id, paciente_id))
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Enfermedad actualizada exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/paciente/enfermedades/<int:id>', methods=['DELETE'])
@login_required
@role_required('paciente')
def delete_enfermedad_paciente(id):
    """Eliminar una enfermedad (paciente)"""
    try:
        paciente_id = get_paciente_id_from_user()
        cursor = db.session.connection().connection.cursor()
        cursor.execute("DELETE FROM enfermedades WHERE id=%s AND paciente_id=%s", (id, paciente_id))
        db.session.commit()
        return jsonify({'success': True, 'message': 'Enfermedad eliminada exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/paciente/cirugias', methods=['POST'])
@login_required
@role_required('paciente')
def add_cirugia_paciente():
    """Agregar una nueva cirugía (paciente)"""
    try:
        data = request.get_json()
        paciente_id = get_paciente_id_from_user()
        
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            INSERT INTO cirugias (paciente_id, nombre, fecha_cirugia, hospital, cirujano, complicaciones, notas)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (paciente_id, data.get('nombre'), data.get('fecha_cirugia'), data.get('hospital'),
              data.get('cirujano'), data.get('complicaciones'), data.get('notas')))
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Cirugía agregada exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/paciente/cirugias/<int:id>', methods=['PUT'])
@login_required
@role_required('paciente')
def update_cirugia_paciente(id):
    """Actualizar una cirugía (paciente)"""
    try:
        data = request.get_json()
        paciente_id = get_paciente_id_from_user()
        
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            UPDATE cirugias SET nombre=%s, fecha_cirugia=%s, hospital=%s, cirujano=%s, 
                              complicaciones=%s, notas=%s
            WHERE id=%s AND paciente_id=%s
        """, (data.get('nombre'), data.get('fecha_cirugia'), data.get('hospital'),
              data.get('cirujano'), data.get('complicaciones'), data.get('notas'), id, paciente_id))
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Cirugía actualizada exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/paciente/cirugias/<int:id>', methods=['DELETE'])
@login_required
@role_required('paciente')
def delete_cirugia_paciente(id):
    """Eliminar una cirugía (paciente)"""
    try:
        paciente_id = get_paciente_id_from_user()
        cursor = db.session.connection().connection.cursor()
        cursor.execute("DELETE FROM cirugias WHERE id=%s AND paciente_id=%s", (id, paciente_id))
        db.session.commit()
        return jsonify({'success': True, 'message': 'Cirugía eliminada exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/paciente/medicamentos', methods=['POST'])
@login_required
@role_required('paciente')
def add_medicamento_paciente():
    """Agregar un nuevo medicamento (paciente)"""
    try:
        data = request.get_json()
        paciente_id = get_paciente_id_from_user()
        
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            INSERT INTO medicamentos (paciente_id, nombre, dosis, frecuencia, via_administracion, 
                                     fecha_inicio, fecha_fin, prescrito_por, notas)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (paciente_id, data.get('nombre'), data.get('dosis'), data.get('frecuencia'),
              data.get('via_administracion'), data.get('fecha_inicio'), data.get('fecha_fin'),
              data.get('prescrito_por'), data.get('notas')))
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Medicamento agregado exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/paciente/medicamentos/<int:id>', methods=['PUT'])
@login_required
@role_required('paciente')
def update_medicamento_paciente(id):
    """Actualizar un medicamento (paciente)"""
    try:
        data = request.get_json()
        paciente_id = get_paciente_id_from_user()
        
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            UPDATE medicamentos SET nombre=%s, dosis=%s, frecuencia=%s, via_administracion=%s,
                                   fecha_inicio=%s, fecha_fin=%s, prescrito_por=%s, notas=%s
            WHERE id=%s AND paciente_id=%s
        """, (data.get('nombre'), data.get('dosis'), data.get('frecuencia'), data.get('via_administracion'),
              data.get('fecha_inicio'), data.get('fecha_fin'), data.get('prescrito_por'),
              data.get('notas'), id, paciente_id))
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Medicamento actualizado exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/paciente/medicamentos/<int:id>', methods=['DELETE'])
@login_required
@role_required('paciente')
def delete_medicamento_paciente(id):
    """Eliminar un medicamento (paciente)"""
    try:
        paciente_id = get_paciente_id_from_user()
        cursor = db.session.connection().connection.cursor()
        cursor.execute("DELETE FROM medicamentos WHERE id=%s AND paciente_id=%s", (id, paciente_id))
        db.session.commit()
        return jsonify({'success': True, 'message': 'Medicamento eliminado exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/paciente/vacunas', methods=['POST'])
@login_required
@role_required('paciente')
def add_vacuna_paciente():
    """Agregar una nueva vacuna (paciente)"""
    try:
        data = request.get_json()
        paciente_id = get_paciente_id_from_user()
        
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            INSERT INTO vacunas (paciente_id, nombre, fecha_aplicacion, dosis, lote, 
                                institucion, profesional, proxima_dosis, notas)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (paciente_id, data.get('nombre'), data.get('fecha_aplicacion'), data.get('dosis'),
              data.get('lote'), data.get('institucion'), data.get('profesional'),
              data.get('proxima_dosis'), data.get('notas')))
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Vacuna agregada exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/paciente/vacunas/<int:id>', methods=['PUT'])
@login_required
@role_required('paciente')
def update_vacuna_paciente(id):
    """Actualizar una vacuna (paciente)"""
    try:
        data = request.get_json()
        paciente_id = get_paciente_id_from_user()
        
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            UPDATE vacunas SET nombre=%s, fecha_aplicacion=%s, dosis=%s, lote=%s,
                             institucion=%s, profesional=%s, proxima_dosis=%s, notas=%s
            WHERE id=%s AND paciente_id=%s
        """, (data.get('nombre'), data.get('fecha_aplicacion'), data.get('dosis'), data.get('lote'),
              data.get('institucion'), data.get('profesional'), data.get('proxima_dosis'),
              data.get('notas'), id, paciente_id))
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Vacuna actualizada exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/paciente/vacunas/<int:id>', methods=['DELETE'])
@login_required
@role_required('paciente')
def delete_vacuna_paciente(id):
    """Eliminar una vacuna (paciente)"""
    try:
        paciente_id = get_paciente_id_from_user()
        cursor = db.session.connection().connection.cursor()
        cursor.execute("DELETE FROM vacunas WHERE id=%s AND paciente_id=%s", (id, paciente_id))
        db.session.commit()
        return jsonify({'success': True, 'message': 'Vacuna eliminada exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/paciente/habitos', methods=['POST'])
@login_required
@role_required('paciente')
def add_habito_paciente():
    """Agregar un nuevo hábito (paciente)"""
    try:
        data = request.get_json()
        paciente_id = get_paciente_id_from_user()
        
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            INSERT INTO habitos_salud (paciente_id, tipo, descripcion, frecuencia, 
                                      fecha_inicio, fecha_fin, notas)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (paciente_id, data.get('tipo'), data.get('descripcion'), data.get('frecuencia'),
              data.get('fecha_inicio'), data.get('fecha_fin'), data.get('notas')))
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Hábito agregado exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/paciente/habitos/<int:id>', methods=['PUT'])
@login_required
@role_required('paciente')
def update_habito_paciente(id):
    """Actualizar un hábito (paciente)"""
    try:
        data = request.get_json()
        paciente_id = get_paciente_id_from_user()
        
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            UPDATE habitos_salud SET tipo=%s, descripcion=%s, frecuencia=%s,
                                   fecha_inicio=%s, fecha_fin=%s, notas=%s
            WHERE id=%s AND paciente_id=%s
        """, (data.get('tipo'), data.get('descripcion'), data.get('frecuencia'),
              data.get('fecha_inicio'), data.get('fecha_fin'), data.get('notas'), id, paciente_id))
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Hábito actualizado exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/paciente/habitos/<int:id>', methods=['DELETE'])
@login_required
@role_required('paciente')
def delete_habito_paciente(id):
    """Eliminar un hábito (paciente)"""
    try:
        paciente_id = get_paciente_id_from_user()
        cursor = db.session.connection().connection.cursor()
        cursor.execute("DELETE FROM habitos_salud WHERE id=%s AND paciente_id=%s", (id, paciente_id))
        db.session.commit()
        return jsonify({'success': True, 'message': 'Hábito eliminado exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

# ===================== ENDPOINTS CRUD PARA MÉDICOS =====================

@app.route('/api/medico/pacientes/<int:paciente_id>/alergias', methods=['POST'])
@login_required
@role_required('medico')
def add_alergia_medico(paciente_id):
    """Agregar una nueva alergia a un paciente (médico)"""
    try:
        data = request.get_json()
        
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            INSERT INTO alergias (paciente_id, nombre, tipo, severidad, reaccion, notas, fecha_diagnostico)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (paciente_id, data.get('nombre'), data.get('tipo'), data.get('severidad'),
              data.get('reaccion'), data.get('notas'), data.get('fecha_diagnostico')))
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Alergia agregada exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/medico/alergias/<int:id>', methods=['PUT'])
@login_required
@role_required('medico')
def update_alergia_medico(id):
    """Actualizar una alergia (médico)"""
    try:
        data = request.get_json()
        
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            UPDATE alergias SET nombre=%s, tipo=%s, severidad=%s, reaccion=%s, notas=%s, fecha_diagnostico=%s
            WHERE id=%s
        """, (data.get('nombre'), data.get('tipo'), data.get('severidad'), data.get('reaccion'),
              data.get('notas'), data.get('fecha_diagnostico'), id))
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Alergia actualizada exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/medico/alergias/<int:id>', methods=['DELETE'])
@login_required
@role_required('medico')
def delete_alergia_medico(id):
    """Eliminar una alergia (médico)"""
    try:
        cursor = db.session.connection().connection.cursor()
        cursor.execute("DELETE FROM alergias WHERE id=%s", (id,))
        db.session.commit()
        return jsonify({'success': True, 'message': 'Alergia eliminada exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/medico/pacientes/<int:paciente_id>/enfermedades', methods=['POST'])
@login_required
@role_required('medico')
def add_enfermedad_medico(paciente_id):
    """Agregar una nueva enfermedad (médico)"""
    try:
        data = request.get_json()
        
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            INSERT INTO enfermedades (paciente_id, nombre, estado, fecha_diagnostico, tratamiento, notas)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (paciente_id, data.get('nombre'), data.get('estado'), data.get('fecha_diagnostico'),
              data.get('tratamiento'), data.get('notas')))
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Enfermedad agregada exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/medico/enfermedades/<int:id>', methods=['PUT'])
@login_required
@role_required('medico')
def update_enfermedad_medico(id):
    """Actualizar una enfermedad (médico)"""
    try:
        data = request.get_json()
        
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            UPDATE enfermedades SET nombre=%s, estado=%s, fecha_diagnostico=%s, tratamiento=%s, notas=%s
            WHERE id=%s
        """, (data.get('nombre'), data.get('estado'), data.get('fecha_diagnostico'),
              data.get('tratamiento'), data.get('notas'), id))
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Enfermedad actualizada exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/medico/enfermedades/<int:id>', methods=['DELETE'])
@login_required
@role_required('medico')
def delete_enfermedad_medico(id):
    """Eliminar una enfermedad (médico)"""
    try:
        cursor = db.session.connection().connection.cursor()
        cursor.execute("DELETE FROM enfermedades WHERE id=%s", (id,))
        db.session.commit()
        return jsonify({'success': True, 'message': 'Enfermedad eliminada exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/medico/pacientes/<int:paciente_id>/medicamentos', methods=['POST'])
@login_required
@role_required('medico')
def add_medicamento_medico(paciente_id):
    """Agregar un nuevo medicamento (médico)"""
    try:
        data = request.get_json()
        
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            INSERT INTO medicamentos (paciente_id, nombre, dosis, frecuencia, via_administracion,
                                     fecha_inicio, fecha_fin, prescrito_por, notas)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (paciente_id, data.get('nombre'), data.get('dosis'), data.get('frecuencia'),
              data.get('via_administracion'), data.get('fecha_inicio'), data.get('fecha_fin'),
              data.get('prescrito_por'), data.get('notas')))
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Medicamento agregado exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/medico/medicamentos/<int:id>', methods=['PUT'])
@login_required
@role_required('medico')
def update_medicamento_medico(id):
    """Actualizar un medicamento (médico)"""
    try:
        data = request.get_json()
        
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            UPDATE medicamentos SET nombre=%s, dosis=%s, frecuencia=%s, via_administracion=%s,
                                   fecha_inicio=%s, fecha_fin=%s, prescrito_por=%s, notas=%s
            WHERE id=%s
        """, (data.get('nombre'), data.get('dosis'), data.get('frecuencia'), data.get('via_administracion'),
              data.get('fecha_inicio'), data.get('fecha_fin'), data.get('prescrito_por'),
              data.get('notas'), id))
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Medicamento actualizado exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/medico/medicamentos/<int:id>', methods=['DELETE'])
@login_required
@role_required('medico')
def delete_medicamento_medico(id):
    """Eliminar un medicamento (médico)"""
    try:
        cursor = db.session.connection().connection.cursor()
        cursor.execute("DELETE FROM medicamentos WHERE id=%s", (id,))
        db.session.commit()
        return jsonify({'success': True, 'message': 'Medicamento eliminado exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/medico/pacientes/<int:paciente_id>/pdf')
@login_required
def generar_pdf_medico(paciente_id):
    """Generar PDF del historial médico del paciente (médico)"""
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from io import BytesIO
    
    cursor = db.session.connection().connection.cursor()
    
    # Obtener datos del paciente
    cursor.execute("""
        SELECT p.*, u.email
        FROM pacientes p
        JOIN usuarios u ON p.usuario_id = u.id
        WHERE p.id = %s
    """, (paciente_id,))
    
    result = cursor.fetchone()
    if not result:
        return jsonify({'success': False, 'message': 'Paciente no encontrado'}), 404
    
    columns = [desc[0] for desc in cursor.description]
    paciente = dict(zip(columns, result))
    
    # Obtener historial médico
    cursor.execute("SELECT * FROM alergias WHERE paciente_id = %s ORDER BY fecha_diagnostico DESC", (paciente_id,))
    alergias = [dict(zip([desc[0] for desc in cursor.description], row)) for row in cursor.fetchall()]
    
    cursor.execute("SELECT * FROM enfermedades WHERE paciente_id = %s ORDER BY fecha_diagnostico DESC", (paciente_id,))
    enfermedades = [dict(zip([desc[0] for desc in cursor.description], row)) for row in cursor.fetchall()]
    
    cursor.execute("SELECT * FROM cirugias WHERE paciente_id = %s ORDER BY fecha_cirugia DESC", (paciente_id,))
    cirugias = [dict(zip([desc[0] for desc in cursor.description], row)) for row in cursor.fetchall()]
    
    cursor.execute("SELECT * FROM medicamentos WHERE paciente_id = %s ORDER BY fecha_inicio DESC", (paciente_id,))
    medicamentos = [dict(zip([desc[0] for desc in cursor.description], row)) for row in cursor.fetchall()]
    
    cursor.execute("SELECT * FROM vacunas WHERE paciente_id = %s ORDER BY fecha_aplicacion DESC", (paciente_id,))
    vacunas = [dict(zip([desc[0] for desc in cursor.description], row)) for row in cursor.fetchall()]
    
    # Crear PDF en memoria
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()
    
    # Estilo personalizado para título
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#667eea'),
        spaceAfter=30,
        alignment=TA_CENTER
    )
    
    subtitle_style = ParagraphStyle(
        'Subtitle',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=colors.HexColor('#764ba2'),
        spaceAfter=12,
        spaceBefore=12
    )
    
    # Título
    elements.append(Paragraph("HOSPITAL SANITAS", title_style))
    elements.append(Paragraph("Historial Médico del Paciente", styles['Heading2']))
    elements.append(Spacer(1, 0.3*inch))
    
    # Información del paciente
    elements.append(Paragraph("DATOS DEL PACIENTE", subtitle_style))
    
    datos_paciente = [
        ['Nombre Completo:', f"{paciente['nombres']} {paciente['apellidos']}"],
        ['Identificación:', paciente['identificacion'] or 'N/A'],
        ['Fecha de Nacimiento:', str(paciente['fecha_nacimiento']) if paciente.get('fecha_nacimiento') else 'N/A'],
        ['Género:', paciente['genero'] or 'N/A'],
        ['Teléfono:', paciente['telefono'] or 'N/A'],
        ['Email:', paciente['email']],
    ]
    
    tabla_paciente = Table(datos_paciente, colWidths=[2*inch, 4*inch])
    tabla_paciente.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f5f7fa')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e0e0e0')),
    ]))
    elements.append(tabla_paciente)
    elements.append(Spacer(1, 0.3*inch))
    
    # Alergias
    if alergias:
        elements.append(Paragraph("ALERGIAS", subtitle_style))
        data_alergias = [['Nombre', 'Tipo', 'Severidad', 'Reacción']]
        for a in alergias:
            data_alergias.append([
                a['nombre'],
                a['tipo'] or 'N/A',
                a['severidad'] or 'N/A',
                a['reaccion'] or 'N/A'
            ])
        
        tabla_alergias = Table(data_alergias, colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 2*inch])
        tabla_alergias.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(tabla_alergias)
        elements.append(Spacer(1, 0.2*inch))
    
    # Enfermedades
    if enfermedades:
        elements.append(Paragraph("ENFERMEDADES", subtitle_style))
        data_enfermedades = [['Nombre', 'Estado', 'Fecha Diagnóstico', 'Tratamiento']]
        for e in enfermedades:
            data_enfermedades.append([
                e['nombre'],
                e['estado'] or 'N/A',
                str(e['fecha_diagnostico']) if e.get('fecha_diagnostico') else 'N/A',
                e['tratamiento'][:30] + '...' if e.get('tratamiento') and len(e['tratamiento']) > 30 else e.get('tratamiento', 'N/A')
            ])
        
        tabla_enfermedades = Table(data_enfermedades, colWidths=[1.5*inch, 1.3*inch, 1.5*inch, 2.2*inch])
        tabla_enfermedades.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(tabla_enfermedades)
        elements.append(Spacer(1, 0.2*inch))
    
    # Cirugías
    if cirugias:
        elements.append(Paragraph("CIRUGÍAS", subtitle_style))
        data_cirugias = [['Nombre', 'Fecha', 'Hospital', 'Cirujano']]
        for c in cirugias:
            data_cirugias.append([
                c['nombre'],
                str(c['fecha_cirugia']) if c.get('fecha_cirugia') else 'N/A',
                c['hospital'] or 'N/A',
                c['cirujano'] or 'N/A'
            ])
        
        tabla_cirugias = Table(data_cirugias, colWidths=[1.8*inch, 1.3*inch, 1.8*inch, 1.6*inch])
        tabla_cirugias.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(tabla_cirugias)
        elements.append(Spacer(1, 0.2*inch))
    
    # Medicamentos
    if medicamentos:
        elements.append(Paragraph("MEDICAMENTOS", subtitle_style))
        data_medicamentos = [['Nombre', 'Dosis', 'Frecuencia', 'Fecha Inicio']]
        for m in medicamentos:
            data_medicamentos.append([
                m['nombre'],
                m['dosis'] or 'N/A',
                m['frecuencia'] or 'N/A',
                str(m['fecha_inicio']) if m.get('fecha_inicio') else 'N/A'
            ])
        
        tabla_medicamentos = Table(data_medicamentos, colWidths=[2*inch, 1.5*inch, 1.5*inch, 1.5*inch])
        tabla_medicamentos.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(tabla_medicamentos)
        elements.append(Spacer(1, 0.2*inch))
    
    # Vacunas
    if vacunas:
        elements.append(Paragraph("VACUNAS", subtitle_style))
        data_vacunas = [['Nombre', 'Fecha Aplicación', 'Dosis', 'Institución']]
        for v in vacunas:
            data_vacunas.append([
                v['nombre'],
                str(v['fecha_aplicacion']) if v.get('fecha_aplicacion') else 'N/A',
                v['dosis'] or 'N/A',
                v.get('institucion', 'N/A')
            ])
        
        tabla_vacunas = Table(data_vacunas, colWidths=[2*inch, 1.5*inch, 1*inch, 2*inch])
        tabla_vacunas.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(tabla_vacunas)
    
    # Footer
    elements.append(Spacer(1, 0.5*inch))
    fecha_generacion = datetime.now().strftime('%d/%m/%Y %H:%M')
    elements.append(Paragraph(f"<i>Reporte generado el: {fecha_generacion}</i>", styles['Normal']))
    elements.append(Paragraph("<i>Hospital Sanitas - Sistema de Gestión de Registros Médicos</i>", styles['Normal']))
    
    # Construir PDF
    doc.build(elements)
    
    # Enviar PDF
    buffer.seek(0)
    return send_from_directory(
        directory=os.path.dirname(buffer.name) if hasattr(buffer, 'name') else '.',
        path=buffer.name if hasattr(buffer, 'name') else 'reporte.pdf',
        as_attachment=True,
        download_name=f'historial_medico_{paciente["nombres"]}_{paciente["apellidos"]}.pdf',
        mimetype='application/pdf'
    ) if hasattr(buffer, 'name') else (buffer.getvalue(), 200, {
        'Content-Type': 'application/pdf',
        'Content-Disposition': f'attachment; filename=historial_medico_{paciente["nombres"]}_{paciente["apellidos"]}.pdf'
    })
        

# ===================== RUTAS API PARA DASHBOARDS =====================
# Agregar estas rutas a tu app.py

# ===== RUTAS API PARA MÉDICOS =====

@app.route('/api/medico/pacientes/<int:paciente_id>/alergias', methods=['GET'])
@login_required
@role_required('medico', 'administrador')
def api_medico_get_alergias(paciente_id):
    """Obtener alergias de un paciente (médico)"""
    try:
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            SELECT * FROM alergias 
            WHERE paciente_id = %s 
            ORDER BY fecha_diagnostico DESC
        """, (paciente_id,))
        
        columns = [desc[0] for desc in cursor.description]
        alergias = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        # Convertir fechas a string
        for a in alergias:
            if a.get('fecha_diagnostico'):
                a['fecha_diagnostico'] = a['fecha_diagnostico'].isoformat()
        
        return jsonify({'success': True, 'alergias': alergias})
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/medico/pacientes/<int:paciente_id>/enfermedades', methods=['GET'])
@login_required
@role_required('medico', 'administrador')
def api_medico_get_enfermedades(paciente_id):
    """Obtener enfermedades de un paciente (médico)"""
    try:
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            SELECT * FROM enfermedades 
            WHERE paciente_id = %s 
            ORDER BY fecha_diagnostico DESC
        """, (paciente_id,))
        
        columns = [desc[0] for desc in cursor.description]
        enfermedades = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        for e in enfermedades:
            if e.get('fecha_diagnostico'):
                e['fecha_diagnostico'] = e['fecha_diagnostico'].isoformat()
        
        return jsonify({'success': True, 'enfermedades': enfermedades})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/medico/pacientes/<int:paciente_id>/medicamentos', methods=['GET'])
@login_required
@role_required('medico', 'administrador')
def api_medico_get_medicamentos(paciente_id):
    """Obtener medicamentos de un paciente (médico)"""
    try:
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            SELECT * FROM medicamentos 
            WHERE paciente_id = %s 
            ORDER BY fecha_inicio DESC
        """, (paciente_id,))
        
        columns = [desc[0] for desc in cursor.description]
        medicamentos = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        for m in medicamentos:
            if m.get('fecha_inicio'):
                m['fecha_inicio'] = m['fecha_inicio'].isoformat()
        
        return jsonify({'success': True, 'medicamentos': medicamentos})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/medico/pacientes/<int:paciente_id>/cirugias', methods=['GET'])
@login_required
@role_required('medico', 'administrador')
def api_medico_get_cirugias(paciente_id):
    """Obtener cirugías de un paciente (médico)"""
    try:
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            SELECT * FROM cirugias 
            WHERE paciente_id = %s 
            ORDER BY fecha_cirugia DESC
        """, (paciente_id,))
        
        columns = [desc[0] for desc in cursor.description]
        cirugias = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        for c in cirugias:
            if c.get('fecha_cirugia'):
                c['fecha_cirugia'] = c['fecha_cirugia'].isoformat()
        
        return jsonify({'success': True, 'cirugias': cirugias})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/medico/pacientes/<int:paciente_id>/vacunas', methods=['GET'])
@login_required
@role_required('medico', 'administrador')
def api_medico_get_vacunas(paciente_id):
    """Obtener vacunas de un paciente (médico)"""
    try:
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            SELECT * FROM vacunas 
            WHERE paciente_id = %s 
            ORDER BY fecha_aplicacion DESC
        """, (paciente_id,))
        
        columns = [desc[0] for desc in cursor.description]
        vacunas = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        for v in vacunas:
            if v.get('fecha_aplicacion'):
                v['fecha_aplicacion'] = v['fecha_aplicacion'].isoformat()
            if v.get('proxima_dosis'):
                v['proxima_dosis'] = v['proxima_dosis'].isoformat()
        
        return jsonify({'success': True, 'vacunas': vacunas})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/medico/pacientes/<int:paciente_id>/habitos', methods=['GET'])
@login_required
@role_required('medico', 'administrador')
def api_medico_get_habitos(paciente_id):
    """Obtener hábitos de un paciente (médico)"""
    try:
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            SELECT * FROM habitos 
            WHERE paciente_id = %s 
            ORDER BY fecha_inicio DESC
        """, (paciente_id,))
        
        columns = [desc[0] for desc in cursor.description]
        habitos = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        for h in habitos:
            if h.get('fecha_inicio'):
                h['fecha_inicio'] = h['fecha_inicio'].isoformat()
        
        return jsonify({'success': True, 'habitos': habitos})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/medico/pacientes/<int:paciente_id>/antecedentes-familiares', methods=['GET'])
@login_required
@role_required('medico', 'administrador')
def api_medico_get_antecedentes(paciente_id):
    """Obtener antecedentes familiares de un paciente (médico)"""
    try:
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            SELECT * FROM antecedentes_familiares 
            WHERE paciente_id = %s 
            ORDER BY fecha_registro DESC
        """, (paciente_id,))
        
        columns = [desc[0] for desc in cursor.description]
        antecedentes_familiares = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        for a in antecedentes_familiares:
            if a.get('fecha_registro'):
                a['fecha_registro'] = a['fecha_registro'].isoformat()
        
        return jsonify({'success': True, 'antecedentes_familiares': antecedentes_familiares})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# ===== RUTAS POST PARA MÉDICOS =====

@app.route('/api/medico/pacientes/<int:paciente_id>/alergias', methods=['POST'])
@login_required
@role_required('medico', 'administrador')
def api_medico_add_alergia(paciente_id):
    """Agregar alergia (médico)"""
    try:
        data = request.get_json()
        cursor = db.session.connection().connection.cursor()
        
        cursor.execute("""
            INSERT INTO alergias (
                paciente_id, nombre, tipo, severidad, reaccion, 
                fecha_diagnostico, notas
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            paciente_id,
            data.get('nombre'),
            data.get('tipo'),
            data.get('severidad'),
            data.get('reaccion'),
            data.get('fecha_diagnostico'),
            data.get('notas')
        ))
        
        alergia_id = cursor.fetchone()[0]
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Alergia agregada exitosamente',
            'alergia_id': alergia_id
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/medico/pacientes/<int:paciente_id>/enfermedades', methods=['POST'])
@login_required
@role_required('medico', 'administrador')
def api_medico_add_enfermedad(paciente_id):
    """Agregar enfermedad (médico)"""
    try:
        data = request.get_json()
        cursor = db.session.connection().connection.cursor()
        
        cursor.execute("""
            INSERT INTO enfermedades (
                paciente_id, nombre, estado, fecha_diagnostico, 
                tratamiento, notas
            ) VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            paciente_id,
            data.get('nombre'),
            data.get('estado'),
            data.get('fecha_diagnostico'),
            data.get('tratamiento'),
            data.get('notas')
        ))
        
        enfermedad_id = cursor.fetchone()[0]
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Enfermedad agregada exitosamente',
            'enfermedad_id': enfermedad_id
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/medico/pacientes/<int:paciente_id>/medicamentos', methods=['POST'])
@login_required
@role_required('medico', 'administrador')
def api_medico_add_medicamento(paciente_id):
    """Agregar medicamento (médico)"""
    try:
        data = request.get_json()
        cursor = db.session.connection().connection.cursor()
        
        cursor.execute("""
            INSERT INTO medicamentos (
                paciente_id, nombre, dosis, frecuencia, 
                via_administracion, fecha_inicio, notas
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            paciente_id,
            data.get('nombre'),
            data.get('dosis'),
            data.get('frecuencia'),
            data.get('via_administracion'),
            data.get('fecha_inicio'),
            data.get('notas')
        ))
        
        medicamento_id = cursor.fetchone()[0]
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Medicamento agregado exitosamente',
            'medicamento_id': medicamento_id
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/medico/pacientes/<int:paciente_id>/cirugias', methods=['POST'])
@login_required
@role_required('medico', 'administrador')
def api_medico_add_cirugia(paciente_id):
    """Agregar cirugía (médico)"""
    try:
        data = request.get_json()
        cursor = db.session.connection().connection.cursor()
        
        cursor.execute("""
            INSERT INTO cirugias (
                paciente_id, nombre, fecha_cirugia, hospital, 
                cirujano, complicaciones, notas
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            paciente_id,
            data.get('nombre'),
            data.get('fecha_cirugia'),
            data.get('hospital'),
            data.get('cirujano'),
            data.get('complicaciones'),
            data.get('notas')
        ))
        
        cirugia_id = cursor.fetchone()[0]
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Cirugía agregada exitosamente',
            'cirugia_id': cirugia_id
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/medico/pacientes/<int:paciente_id>/vacunas', methods=['POST'])
@login_required
@role_required('medico', 'administrador')
def api_medico_add_vacuna(paciente_id):
    """Agregar vacuna (médico)"""
    try:
        data = request.get_json()
        cursor = db.session.connection().connection.cursor()
        
        cursor.execute("""
            INSERT INTO vacunas (
                paciente_id, nombre, fecha_aplicacion, dosis, proxima_dosis
            ) VALUES (%s, %s, %s, %s, %s)
            RETURNING id
        """, (
            paciente_id,
            data.get('nombre'),
            data.get('fecha_aplicacion'),
            data.get('dosis'),
            data.get('proxima_dosis')
        ))
        
        vacuna_id = cursor.fetchone()[0]
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Vacuna agregada exitosamente',
            'vacuna_id': vacuna_id
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/medico/pacientes/<int:paciente_id>/habitos', methods=['POST'])
@login_required
@role_required('medico', 'administrador')
def api_medico_add_habito(paciente_id):
    """Agregar hábito (médico)"""
    try:
        data = request.get_json()
        cursor = db.session.connection().connection.cursor()
        
        cursor.execute("""
            INSERT INTO habitos (
                paciente_id, tipo, descripcion, frecuencia, 
                fecha_inicio, notas
            ) VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            paciente_id,
            data.get('tipo'),
            data.get('descripcion'),
            data.get('frecuencia'),
            data.get('fecha_inicio'),
            data.get('notas')
        ))
        
        habito_id = cursor.fetchone()[0]
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Hábito agregado exitosamente',
            'habito_id': habito_id
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/medico/pacientes/<int:paciente_id>/antecedentes-familiares', methods=['POST'])
@login_required
@role_required('medico', 'administrador')
def api_medico_add_antecedente(paciente_id):
    """Agregar antecedente familiar (médico)"""
    try:
        data = request.get_json()
        cursor = db.session.connection().connection.cursor()
        
        cursor.execute("""
            INSERT INTO antecedentes_familiares (
                paciente_id, parentesco, enfermedad, edad_diagnostico,
                estado, notas, fecha_registro
            ) VALUES (%s, %s, %s, %s, %s, %s, NOW())
            RETURNING id
        """, (
            paciente_id,
            data.get('parentesco'),
            data.get('enfermedad'),
            data.get('edad_diagnostico'),
            data.get('estado'),
            data.get('notas')
        ))
        
        antecedente_id = cursor.fetchone()[0]
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Antecedente familiar agregado exitosamente',
            'antecedente_id': antecedente_id
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

# ===== RUTAS PUT Y DELETE PARA MÉDICOS =====

@app.route('/api/medico/<tipo>/<int:item_id>', methods=['PUT'])
@login_required
@role_required('medico', 'administrador')
def api_medico_update_item(tipo, item_id):
    """Actualizar cualquier tipo de registro médico"""
    try:
        data = request.get_json()
        cursor = db.session.connection().connection.cursor()
        
        # Mapeo de tipos a tablas
        tabla_map = {
            'alergias': 'alergias',
            'enfermedades': 'enfermedades',
            'medicamentos': 'medicamentos',
            'cirugias': 'cirugias',
            'vacunas': 'vacunas',
            'habitos': 'habitos',
            'antecedentes': 'antecedentes_familiares'
        }
        
        tabla = tabla_map.get(tipo)
        if not tabla:
            return jsonify({'success': False, 'message': 'Tipo no válido'}), 400
        
        # Construir UPDATE dinámico
        campos = []
        valores = []
        
        for key, value in data.items():
            if key not in ['id', 'paciente_id']:
                campos.append(f"{key} = %s")
                valores.append(value)
        
        if not campos:
            return jsonify({'success': False, 'message': 'No hay datos para actualizar'}), 400
        
        valores.append(item_id)
        query = f"UPDATE {tabla} SET {', '.join(campos)} WHERE id = %s"
        
        cursor.execute(query, tuple(valores))
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Registro actualizado exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/medico/<tipo>/<int:item_id>', methods=['DELETE'])
@login_required
@role_required('medico', 'administrador')
def api_medico_delete_item(tipo, item_id):
    """Eliminar cualquier tipo de registro médico"""
    try:
        cursor = db.session.connection().connection.cursor()
        
        tabla_map = {
            'alergias': 'alergias',
            'enfermedades': 'enfermedades',
            'medicamentos': 'medicamentos',
            'cirugias': 'cirugias',
            'vacunas': 'vacunas',
            'habitos': 'habitos',
            'antecedentes': 'antecedentes_familiares'
        }
        
        tabla = tabla_map.get(tipo)
        if not tabla:
            return jsonify({'success': False, 'message': 'Tipo no válido'}), 400
        
        cursor.execute(f"DELETE FROM {tabla} WHERE id = %s", (item_id,))
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Registro eliminado exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

# ===== RUTAS API PARA PACIENTES =====

@app.route('/api/paciente/info', methods=['GET'])
@login_required
@role_required('paciente')
def api_paciente_info():
    """Obtener información del paciente actual"""
    try:
        paciente_id = get_paciente_id_from_user()
        if not paciente_id:
            return jsonify({'success': False, 'message': 'No se encontró información del paciente'}), 404
        
        cursor = db.session.connection().connection.cursor()
        cursor.execute("""
            SELECT p.*, u.email
            FROM pacientes p
            JOIN usuarios u ON p.usuario_id = u.id
            WHERE p.id = %s
        """, (paciente_id,))
        
        result = cursor.fetchone()
        if not result:
            return jsonify({'success': False, 'message': 'Paciente no encontrado'}), 404
        
        columns = [desc[0] for desc in cursor.description]
        paciente = dict(zip(columns, result))
        
        if paciente.get('fecha_nacimiento'):
            paciente['fecha_nacimiento'] = paciente['fecha_nacimiento'].isoformat()
        
        return jsonify({'success': True, 'paciente': paciente})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/paciente/alergias', methods=['GET'])
@login_required
@role_required('paciente')
def api_paciente_get_alergias():
    """Obtener alergias del paciente actual"""
    try:
        paciente_id = get_paciente_id_from_user()
        cursor = db.session.connection().connection.cursor()
        cursor.execute("SELECT * FROM alergias WHERE paciente_id = %s ORDER BY fecha_diagnostico DESC", (paciente_id,))
        
        columns = [desc[0] for desc in cursor.description]
        alergias = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        for a in alergias:
            if a.get('fecha_diagnostico'):
                a['fecha_diagnostico'] = a['fecha_diagnostico'].isoformat()
        
        return jsonify({'success': True, 'alergias': alergias})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/paciente/enfermedades', methods=['GET'])
@login_required
@role_required('paciente')
def api_paciente_get_enfermedades():
    """Obtener enfermedades del paciente actual"""
    try:
        paciente_id = get_paciente_id_from_user()
        cursor = db.session.connection().connection.cursor()
        cursor.execute("SELECT * FROM enfermedades WHERE paciente_id = %s ORDER BY fecha_diagnostico DESC", (paciente_id,))
        
        columns = [desc[0] for desc in cursor.description]
        enfermedades = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        for e in enfermedades:
            if e.get('fecha_diagnostico'):
                e['fecha_diagnostico'] = e['fecha_diagnostico'].isoformat()
        
        return jsonify({'success': True, 'enfermedades': enfermedades})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/paciente/medicamentos', methods=['GET'])
@login_required
@role_required('paciente')
def api_paciente_get_medicamentos():
    """Obtener medicamentos del paciente actual"""
    try:
        paciente_id = get_paciente_id_from_user()
        cursor = db.session.connection().connection.cursor()
        cursor.execute("SELECT * FROM medicamentos WHERE paciente_id = %s ORDER BY fecha_inicio DESC", (paciente_id,))
        
        columns = [desc[0] for desc in cursor.description]
        medicamentos = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        for m in medicamentos:
            if m.get('fecha_inicio'):
                m['fecha_inicio'] = m['fecha_inicio'].isoformat()
        
        return jsonify({'success': True, 'medicamentos': medicamentos})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/paciente/cirugias', methods=['GET'])
@login_required
@role_required('paciente')
def api_paciente_get_cirugias():
    """Obtener cirugías del paciente actual"""
    try:
        paciente_id = get_paciente_id_from_user()
        cursor = db.session.connection().connection.cursor()
        cursor.execute("SELECT * FROM cirugias WHERE paciente_id = %s ORDER BY fecha_cirugia DESC", (paciente_id,))
        
        columns = [desc[0] for desc in cursor.description]
        cirugias = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        for c in cirugias:
            if c.get('fecha_cirugia'):
                c['fecha_cirugia'] = c['fecha_cirugia'].isoformat()
        
        return jsonify({'success': True, 'cirugias': cirugias})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/paciente/vacunas', methods=['GET'])
@login_required
@role_required('paciente')
def api_paciente_get_vacunas():
    """Obtener vacunas del paciente actual"""
    try:
        paciente_id = get_paciente_id_from_user()
        cursor = db.session.connection().connection.cursor()
        cursor.execute("SELECT * FROM vacunas WHERE paciente_id = %s ORDER BY fecha_aplicacion DESC", (paciente_id,))
        
        columns = [desc[0] for desc in cursor.description]
        vacunas = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        for v in vacunas:
            if v.get('fecha_aplicacion'):
                v['fecha_aplicacion'] = v['fecha_aplicacion'].isoformat()
            if v.get('proxima_dosis'):
                v['proxima_dosis'] = v['proxima_dosis'].isoformat()
        
        return jsonify({'success': True, 'vacunas': vacunas})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/paciente/habitos', methods=['GET'])
@login_required
@role_required('paciente')
def api_paciente_get_habitos():
    """Obtener hábitos del paciente actual"""
    try:
        paciente_id = get_paciente_id_from_user()
        cursor = db.session.connection().connection.cursor()
        cursor.execute("SELECT * FROM habitos WHERE paciente_id = %s ORDER BY fecha_inicio DESC", (paciente_id,))
        
        columns = [desc[0] for desc in cursor.description]
        habitos = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        for h in habitos:
            if h.get('fecha_inicio'):
                h['fecha_inicio'] = h['fecha_inicio'].isoformat()
        
        return jsonify({'success': True, 'habitos': habitos})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/paciente/antecedentes-familiares', methods=['GET'])
@login_required
@role_required('paciente')
def api_paciente_get_antecedentes():
    """Obtener antecedentes familiares del paciente actual"""
    try:
        paciente_id = get_paciente_id_from_user()
        cursor = db.session.connection().connection.cursor()
        cursor.execute("SELECT * FROM antecedentes_familiares WHERE paciente_id = %s ORDER BY fecha_registro DESC", (paciente_id,))
        
        columns = [desc[0] for desc in cursor.description]
        antecedentes_familiares = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        for a in antecedentes_familiares:
            if a.get('fecha_registro'):
                a['fecha_registro'] = a['fecha_registro'].isoformat()
        
        return jsonify({'success': True, 'antecedentes_familiares': antecedentes_familiares})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# ===== RUTAS POST PARA PACIENTES =====

@app.route('/api/paciente/<endpoint>', methods=['POST'])
@login_required
@role_required('paciente')
def api_paciente_add_item(endpoint):
    """Agregar registro médico (paciente)"""
    try:
        paciente_id = get_paciente_id_from_user()
        data = request.get_json()
        cursor = db.session.connection().connection.cursor()
        
        if endpoint == 'alergias':
            cursor.execute("""
                INSERT INTO alergias (paciente_id, nombre, tipo, severidad, reaccion, fecha_diagnostico, notas)
                VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id
            """, (paciente_id, data.get('nombre'), data.get('tipo'), data.get('severidad'), 
                  data.get('reaccion'), data.get('fecha_diagnostico'), data.get('notas')))
        elif endpoint == 'enfermedades':
            cursor.execute("""
                INSERT INTO enfermedades (paciente_id, nombre, estado, fecha_diagnostico, tratamiento, notas)
                VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
            """, (paciente_id, data.get('nombre'), data.get('estado'), 
                  data.get('fecha_diagnostico'), data.get('tratamiento'), data.get('notas')))
        elif endpoint == 'medicamentos':
            cursor.execute("""
                INSERT INTO medicamentos (paciente_id, nombre, dosis, frecuencia, via_administracion, fecha_inicio, notas)
                VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id
            """, (paciente_id, data.get('nombre'), data.get('dosis'), data.get('frecuencia'),
                  data.get('via_administracion'), data.get('fecha_inicio'), data.get('notas')))
        elif endpoint == 'cirugias':
            cursor.execute("""
                INSERT INTO cirugias (paciente_id, nombre, fecha_cirugia, hospital, cirujano, complicaciones, notas)
                VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id
            """, (paciente_id, data.get('nombre'), data.get('fecha_cirugia'), data.get('hospital'),
                  data.get('cirujano'), data.get('complicaciones'), data.get('notas')))
        elif endpoint == 'vacunas':
            cursor.execute("""
                INSERT INTO vacunas (paciente_id, nombre, fecha_aplicacion, dosis, proxima_dosis)
                VALUES (%s, %s, %s, %s, %s) RETURNING id
            """, (paciente_id, data.get('nombre'), data.get('fecha_aplicacion'), 
                  data.get('dosis'), data.get('proxima_dosis')))
        elif endpoint == 'habitos':
            cursor.execute("""
                INSERT INTO habitos (paciente_id, tipo, descripcion, frecuencia, fecha_inicio, notas)
                VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
            """, (paciente_id, data.get('tipo'), data.get('descripcion'), data.get('frecuencia'),
                  data.get('fecha_inicio'), data.get('notas')))
        elif endpoint == 'antecedentes-familiares':
            cursor.execute("""
                INSERT INTO antecedentes_familiares (paciente_id, parentesco, enfermedad, edad_diagnostico, estado, notas, fecha_registro)
                VALUES (%s, %s, %s, %s, %s, %s, NOW()) RETURNING id
            """, (paciente_id, data.get('parentesco'), data.get('enfermedad'), 
                  data.get('edad_diagnostico'), data.get('estado'), data.get('notas')))
        else:
            return jsonify({'success': False, 'message': 'Endpoint no válido'}), 400
        
        item_id = cursor.fetchone()[0]
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Registro agregado exitosamente', 'id': item_id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

# ===== RUTAS PUT Y DELETE PARA PACIENTES =====

@app.route('/api/paciente/<endpoint>/<int:item_id>', methods=['PUT'])
@login_required
@role_required('paciente')
def api_paciente_update_item(endpoint, item_id):
    """Actualizar registro médico (paciente)"""
    try:
        paciente_id = get_paciente_id_from_user()
        data = request.get_json()
        cursor = db.session.connection().connection.cursor()
        
        tabla_map = {
            'alergias': 'alergias',
            'enfermedades': 'enfermedades',
            'medicamentos': 'medicamentos',
            'cirugias': 'cirugias',
            'vacunas': 'vacunas',
            'habitos': 'habitos',
            'antecedentes-familiares': 'antecedentes_familiares'
        }
        
        tabla = tabla_map.get(endpoint)
        if not tabla:
            return jsonify({'success': False, 'message': 'Endpoint no válido'}), 400
        
        campos = []
        valores = []
        
        for key, value in data.items():
            if key not in ['id', 'paciente_id']:
                campos.append(f"{key} = %s")
                valores.append(value)
        
        if not campos:
            return jsonify({'success': False, 'message': 'No hay datos para actualizar'}), 400
        
        valores.extend([item_id, paciente_id])
        query = f"UPDATE {tabla} SET {', '.join(campos)} WHERE id = %s AND paciente_id = %s"
        
        cursor.execute(query, tuple(valores))
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Registro actualizado exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/paciente/<endpoint>/<int:item_id>', methods=['DELETE'])
@login_required
@role_required('paciente')
def api_paciente_delete_item(endpoint, item_id):
    """Eliminar registro médico (paciente)"""
    try:
        paciente_id = get_paciente_id_from_user()
        cursor = db.session.connection().connection.cursor()
        
        tabla_map = {
            'alergias': 'alergias',
            'enfermedades': 'enfermedades',
            'medicamentos': 'medicamentos',
            'cirugias': 'cirugias',
            'vacunas': 'vacunas',
            'habitos': 'habitos',
            'antecedentes-familiares': 'antecedentes_familiares'
        }
        
        tabla = tabla_map.get(endpoint)
        if not tabla:
            return jsonify({'success': False, 'message': 'Endpoint no válido'}), 400
        
        cursor.execute(f"DELETE FROM {tabla} WHERE id = %s AND paciente_id = %s", (item_id, paciente_id))
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Registro eliminado exitosamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    
# =========================================================
# RUTAS API MÉDICO: ARCHIVOS (CORREGIDAS)
# =========================================================

@app.route('/api/medico/pacientes/<int:paciente_id>/archivos', methods=['GET'])
@login_required
def get_archivos_medico(paciente_id):
    """Obtener archivos médicos de un paciente"""
    try:
        # Validar permisos: los médicos pueden ver todos, los pacientes solo los suyos
        if session.get('rol') == 'paciente' and get_paciente_id_from_user() != paciente_id:
            return jsonify({'success': False, 'message': 'No autorizado'}), 403

        # Usar with para asegurar el cierre de la conexión
        with db.session.connection().connection.cursor() as cursor:
            # Consulta simplificada para evitar errores de JOIN
            cursor.execute("""
                SELECT id, nombre_archivo, tipo_archivo, categoria,
                        descripcion, fecha_subida, tamano_kb
                FROM archivos_medicos
                WHERE paciente_id = %s
                ORDER BY fecha_subida DESC
            """, (paciente_id,))
            
            columns = [desc[0] for desc in cursor.description]
            archivos = [dict(zip(columns, row)) for row in cursor.fetchall()]
            
            # Convertir fechas a string ISO
            for a in archivos:
                if a.get('fecha_subida'):
                    if isinstance(a['fecha_subida'], datetime):
                        a['fecha_subida'] = a['fecha_subida'].isoformat()
                    else:
                        a['fecha_subida'] = str(a['fecha_subida'])
            
            return jsonify({'success': True, 'archivos': archivos})
    
    except Exception as e:
        print(f"Error al obtener archivos para paciente {paciente_id}: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/medico/pacientes/<int:paciente_id>/archivos', methods=['POST'])
@login_required
@role_required('medico', 'administrador')
def upload_archivo_medico_(paciente_id):
    """Subir archivo médico para un paciente"""
    try:
        with db.session.connection().connection.cursor() as cursor:
            
            # Verificar que el paciente existe
            cursor.execute("SELECT id FROM pacientes WHERE id = %s", (paciente_id,))
            if not cursor.fetchone():
                return jsonify({'success': False, 'message': 'Paciente no encontrado'}), 404

            # Verificar que se envió un archivo
            if 'archivo' not in request.files:
                return jsonify({'success': False, 'message': 'No se envió ningún archivo con la clave \"archivo\"'}), 400
            
            file = request.files['archivo']
            
            if file.filename == '':
                return jsonify({'success': False, 'message': 'Nombre de archivo vacío'}), 400
            
            if not allowed_file(file.filename):
                return jsonify({
                    'success': False,
                    'message': f'Tipo de archivo no permitido. Extensiones válidas: {", ".join(ALLOWED_EXTENSIONS)}'
                }), 400
            
            # Crear nombre de archivo seguro y único
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            unique_filename = f"{paciente_id}_{timestamp}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            
            # Guardar archivo en el disco
            file.save(filepath)
            
            # Obtener tamaño del archivo en KB
            file_size_bytes = os.path.getsize(filepath)
            file_size_kb = file_size_bytes / 1024
            
            # Obtener ID del médico si es médico
            medico_id = None
            if session.get('rol') == 'medico':
                cursor.execute("SELECT id FROM medicos WHERE usuario_id = %s", (session['usuario_id'],))
                result = cursor.fetchone()
                medico_id = result[0] if result else None
            
            # Registrar en base de datos
            cursor.execute("""
                INSERT INTO archivos_medicos (
                    paciente_id, nombre_archivo, nombre_original, tipo_archivo,
                    categoria, descripcion, ruta_archivo, tamano_kb,
                    subido_por_medico_id, fecha_subida
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                RETURNING id
            """, (
                paciente_id,
                unique_filename,
                filename,
                file.content_type,
                request.form.get('categoria', 'otros'),
                request.form.get('descripcion', ''),
                filepath,
                file_size_kb,
                medico_id
            ))
            
            archivo_id = cursor.fetchone()[0]
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Archivo subido exitosamente',
                'archivo_id': archivo_id,
                'filename': unique_filename
            }), 201
    
    except Exception as e:
        db.session.rollback()
        print(f"Error al subir archivo para paciente {paciente_id}: {str(e)}")
        # Si falla el guardado en disco o la DB, intentar limpiar el archivo
        if 'filepath' in locals() and os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({'success': False, 'message': str(e)}), 500




# ===================== FIN DE RUTAS API =====================

# ===================== MAIN =====================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5050))
    print("Iniciando aplicación Flask...")
    print(f"Servidor corriendo en puerto {port}")
    app.run(host='0.0.0.0', port=port, debug=False)