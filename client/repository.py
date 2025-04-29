import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Flask, jsonify, request
import json
import uuid
import os
import sqlite3
from datetime import datetime, timedelta
import random
import hashlib
import sys
import base64
import hmac
import hashlib
import time
import hmac
import hashlib


app = Flask(__name__)

organizations = {}
sessions = {}


CREDENTIALS_DIR = "credentials"


def generate_keys():
    """Gera uma chave pública e privada RSA e salva no local apropriado."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    public_key = private_key.public_key()

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open("server_private_key.pem", "wb") as key_file:
        key_file.write(private_key_pem)

    sio_file_path = os.path.join(os.path.expanduser('~'), '.sio')
    os.makedirs(sio_file_path, exist_ok=True)
    file_path = os.path.join(sio_file_path, 'state.json')

    data = {
        "REP_ADDRESS": "127.0.0.1:5000",
        "REP_PUB_KEY": public_key_pem.decode()  
    }

    with open(file_path, "w") as f:
        json.dump(data, f, indent=4)  

    print(f"Public key saved in {file_path}")

    return private_key_pem.decode(), public_key_pem.decode()

private_key, public_key = generate_keys()



def init_db():
    # Conexões com os bancos de dados
    org_conn = sqlite3.connect("organizations.db")
    session_conn = sqlite3.connect("sessions.db")
    subject_conn = sqlite3.connect("subjects.db")
    doc_conn = sqlite3.connect("documents.db")
    role_conn = sqlite3.connect("roles.db")
    nonce_conn = sqlite3.connect("nonces.db")

    # Criar tabela de organizações
    with org_conn:
        org_conn.execute("""
        CREATE TABLE IF NOT EXISTS organizations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            username TEXT NOT NULL
        )
        """)

    # Criar tabela de sessões
    with session_conn:
        session_conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            organization TEXT NOT NULL,
            username TEXT NOT NULL,
            session_key TEXT NOT NULL,
            hmac TEXT NOT NULL,
            creation_date TEXT NOT NULL,
            expiration_date TEXT NOT NULL,
            roles TEXT DEFAULT NULL
        )
        """)

    # Criar tabela de sujeitos
    with subject_conn:
        subject_conn.execute("""
        CREATE TABLE IF NOT EXISTS subjects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            credentials_file TEXT NOT NULL,
            status TEXT NOT NULL
        )
        """)

    # Criar tabela de documentos
    with doc_conn:
        doc_conn.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_handle TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            create_date TEXT NOT NULL,
            creator TEXT NOT NULL,
            file_handle TEXT NOT NULL,
            acl TEXT NOT NULL,
            deleter TEXT DEFAULT NULL,
            alg TEXT NOT NULL,
            key TEXT NOT NULL,
            iv TEXT NOT NULL,
            organization TEXT NOT NULL          
        )
        """)

    # Criar tabela de papéis
    with role_conn:
        role_conn.execute("""
        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            organization TEXT NOT NULL,
            permissions TEXT DEFAULT '',
            status TEXT DEFAULT 'active'
        )
        """)

        # Criar tabela de associação de papéis e sujeitos
        role_conn.execute("""
        CREATE TABLE IF NOT EXISTS role_subjects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            role_name TEXT NOT NULL,
            organization TEXT NOT NULL,
            subject_username TEXT NOT NULL,
            FOREIGN KEY (role_name) REFERENCES roles (name),
            FOREIGN KEY (organization) REFERENCES organizations (name),
            FOREIGN KEY (subject_username) REFERENCES subjects (username)
        )
        """)


    # Criar tabela de nonces
    with nonce_conn:
        nonce_conn.execute("""
        CREATE TABLE IF NOT EXISTS nonces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nonce TEXT UNIQUE NOT NULL,
            timestamp TEXT NOT NULL
        )
        """)

    # Fechar conexões
    org_conn.close()
    session_conn.close()
    subject_conn.close()
    doc_conn.close()
    role_conn.close()
    nonce_conn.close()

    print("Database initialized successfully.")



@app.route("/organization/create", methods=['POST'])
def rep_create_org():
    dados = request.json

    key = base64.b64decode(dados.get("key"))
    iv = base64.b64decode(dados.get("iv"))
    encrypted_dados = base64.b64decode(dados.get("data"))


    # Desencriptar a chave simétrica com a chave privada do servidor
    private_key = serialization.load_pem_private_key(
        open("server_private_key.pem", "rb").read(),
        password=None,
        backend=default_backend()
    )

    decrypted_key = private_key.decrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

   

    cipher = Cipher(algorithms.AES(decrypted_key), modes.CFB(iv), backend=default_backend())

    decryptor = cipher.decryptor()
    decrypted_dados = decryptor.update(encrypted_dados) + decryptor.finalize()
    dados = json.loads(decrypted_dados)


    org_name = dados.get("org_name")
    username = dados.get("username")
    full_name = dados.get("full_name")
    email = dados.get("email")
    public_key_pem = dados.get("public_key")


    
    if not all([org_name, username, full_name, email, public_key_pem]):
        missing = [field for field in ["org_name", "username", "full_name", "email", "public_key"] if not request.json.get(field)]
        return jsonify({"success": False, "message": f"Missing required fields: {', '.join(missing)}"}), 400

    try:
        
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),  
            backend=default_backend()
        )

        stripped_public_key = "\n".join(
            line.strip()
            for line in public_key_pem.splitlines()
            if "-----" not in line
        )

    except Exception as e:
        return jsonify({"success": False, "message": f"Invalid public key: {str(e)}"}), 400

    try:
        
        conn = sqlite3.connect("organizations.db")
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO organizations (name, username)
            VALUES (?, ?)
        """, (org_name, username))
        conn.commit()


        conn_subjects = sqlite3.connect("subjects.db")
        cursor_subjects = conn_subjects.cursor()



        # Criar o papel "Manager" para a organização
        conn = sqlite3.connect("roles.db")
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO roles (name, organization, permissions, status)
            VALUES (?, ?, ?, ?)
        """, ("Manager", org_name, "ROLE_ACL,SUBJECT_NEW,SUBJECT_DOWN,SUBJECT_UP,DOC_NEW,ROLE_NEW,ROLE_MOD,ROLE_DOWN,ROLE_UP", "active"))
        conn.commit()

        # Associar o criador ao papel "Manager"
        cursor.execute("""
            INSERT INTO role_subjects (role_name, organization, subject_username)
            VALUES (?, ?, ?)
        """, ("Manager", org_name, username))
        conn.commit()
        conn.close()



            
        subject_data = {
            "organization": org_name,
            "username": username,
            "name": full_name,
            "email": email,
            "credentials_file": stripped_public_key,
            "status": "active"  # Define o status como ativo
        }

        cursor_subjects.execute("""
            INSERT INTO subjects (organization, username, name, email, credentials_file, status)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            subject_data["organization"],
            subject_data["username"],
            subject_data["name"],
            subject_data["email"],
            subject_data["credentials_file"],
            subject_data["status"]
        ))
        conn_subjects.commit()

        return jsonify({"success": True, "message": "Organization and subject created successfully."}), 200

    except sqlite3.Error as e:
        return jsonify({"success": False, "message": f"Database error: {str(e)}"}), 500


    finally:
        if conn:
            conn.close()
        if 'conn_subjects' in locals() and conn_subjects:
            conn_subjects.close()


@app.route("/organization/list", methods=['GET'])
def orgs_list():
  
    try:
        connect = sqlite3.connect("organizations.db") 
        cursor = connect.execute("SELECT name FROM organizations") 
        orgs = [row[0] for row in cursor.fetchall()] 
        return jsonify(orgs), 200  
    except sqlite3.Error as e:
        return jsonify({"success": False, "message": f"Database error: {str(e)}"}), 500
    finally:
        connect.close()  



# Funções para armazenamento persistente de nonces
def store_nonce(nonce, timestamp):
    conn = sqlite3.connect("nonces.db")
    with conn:
        conn.execute("INSERT INTO nonces (nonce, timestamp) VALUES (?, ?)", (nonce, timestamp))
    conn.close()

def is_nonce_used(nonce):
    conn = sqlite3.connect("nonces.db")
    result = conn.execute("SELECT 1 FROM nonces WHERE nonce = ?", (nonce,)).fetchone()
    conn.close()
    return result is not None

# Função para limpar nonces antigos
def cleanup_nonces(validity_period_minutes=5):
    conn = sqlite3.connect("nonces.db")
    cutoff_time = datetime.utcnow() - timedelta(minutes=validity_period_minutes)
    conn.execute("DELETE FROM nonces WHERE timestamp < ?", (cutoff_time,))
    conn.commit()
    conn.close()

# Verificação do nonce
def verify_nonce(nonce):

    parts = nonce.split("/")
    if len(parts) != 3:
        return False

    validity_period_minutes=5
    timestamp_str, unique_id, random_bytes = parts
    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%fZ")

    # Verificar intervalo de tempo
    now = datetime.utcnow()
    if now - timestamp > timedelta(minutes=validity_period_minutes):
        return False

    # Verificar se o nonce já foi usado
    if is_nonce_used(nonce):
        return False

    # Registrar o nonce
    store_nonce(nonce, timestamp)

    # Limpar nonces antigos
    cleanup_nonces(validity_period_minutes)

    print("Nonce verified successfully.")

    return True

@app.route("/session/create", methods=['POST'])
def session_create():
    organization = request.json.get("organization")
    username = request.json.get("username")
    password = request.json.get("password")
    credentials_file = request.json.get("credentials_file")
    session_file = request.json.get("session_file")  

    if not organization or not username or not password or not credentials_file or not session_file:
        return jsonify({"success": False, "message": "Missing required fields"}), 400
    

    conn_org = sqlite3.connect("organizations.db")
    org_exists = conn_org.execute("SELECT 1 FROM organizations WHERE name = ?", (organization,)).fetchone()
    conn_org.close()
    if not org_exists:
        return jsonify({"success": False, "message": "Organization does not exist"}), 404
    

    conn_subj = sqlite3.connect("subjects.db")
    subject = conn_subj.execute("""
        SELECT credentials_file FROM subjects WHERE username = ? AND organization = ?
    """, (username, organization)).fetchone()
    conn_subj.close()

    if not subject:
        return jsonify({"success": False, "message": "Subject does not exist"}), 404


    public_key_pem = subject[0]  

        
    if not public_key_pem.startswith("-----BEGIN PUBLIC KEY-----"):
        public_key_pem = f"-----BEGIN PUBLIC KEY-----\n{public_key_pem}\n-----END PUBLIC KEY-----"


    session_id = str(uuid.uuid4())
    creation_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    random_days = random.randint(1, 30)
    expiration_date = datetime.now() + timedelta(days=random_days)
    expiration_date=expiration_date.strftime("%Y-%m-%d %H:%M:%S")  


    # Encrypt the session key with the public key
    sym_key = os.urandom(32)
    encrypted_sym_key = serialization.load_pem_public_key(
    public_key_pem.encode(), backend=default_backend()
        ).encrypt(
            sym_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )


    # Verificar se o sujeito é Manager e adicionar o papel
    conn_role = sqlite3.connect("roles.db")
    cursor = conn_role.execute("""
        SELECT 1 FROM role_subjects WHERE role_name = 'Manager' AND subject_username = ? AND organization = ?
    """, (username, organization))
    is_manager = cursor.fetchone() is not None
    conn_role.close()

    roles = "Manager" if is_manager else None  # Adiciona "Manager" se aplicável

    # Gerar o HMAC da sessão
    hmac = os.urandom(32)

    conn = sqlite3.connect("sessions.db")
    with conn:
        conn.execute("""
        INSERT INTO sessions (session_id, organization, username, session_key, hmac, creation_date, expiration_date, roles)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (session_id, organization, username,  base64.b64encode(sym_key).decode(), base64.b64encode(hmac).decode(), creation_date, expiration_date, None))
    conn.close()

   
    return jsonify({"session_id": session_id, "session_key": base64.b64encode(encrypted_sym_key).decode(),"hmac":base64.b64encode(hmac).decode(), "creation_date": creation_date}), 200



def verify_session(org_name, session_id):
    """Função auxiliar para verificar se a organização e a sessão existem"""
    if org_name not in organizations:
        return {"success": False, "message": "Organization does not exist"}, 404
    if session_id not in sessions or sessions[session_id]["organization"] != org_name:
        return {"success": False, "message": "Session does not exist or is invalid"}, 403
    return None




@app.route("/subject/add", methods=['POST'])
def rep_add_subject():
    
    session_id = request.json.get("session_id")
    encrypted_sensitive_data = base64.b64decode(request.json.get("encrypted_sensitive_data"))
    encrypted_aes_key = request.json.get("encrypted_aes_key")
    iv = request.json.get("iv")
    mac = request.json.get("mac")


    has_perm, error_message = has_permission(session_id, "SUBJECT_NEW")
    if not has_perm:
        return jsonify({"error": error_message}), 403


    if not all([session_id, encrypted_sensitive_data, encrypted_aes_key, iv]):
        return jsonify({"success": False, "message": "Missing required fields"}), 400
    
    # Verificar se o sujeito está suspenso
    suspended, message = verify_subject_status(session_id)
    if suspended:
        print("Error: You are suspended and cannot perform this action.")
        return jsonify({"success": False, "message": message}), 403


    # Validar a sessão usando o session_id
    conn = sqlite3.connect("sessions.db")
    cursor = conn.execute("""
        SELECT username, organization, hmac FROM sessions WHERE session_id = ?
    """, (session_id,))
    session_data = cursor.fetchone()
    conn.close()

    if not session_data:
            return jsonify({"success": False, "message": "Invalid session ID"}), 403
    

    username, organization, hmac_key = session_data

    hmac_encode = hmac_key.encode()
    recalculated_hmac = hmac.new(hmac_encode, encrypted_sensitive_data, hashlib.sha256).hexdigest()

    if mac != recalculated_hmac:
        return jsonify({"success": False, "message": "Invalid MAC"}), 403


    # Desencriptar a chave AES com a chave privada do servidor
    private_key = SERVER_PRIVATE_KEY
    aes_key = private_key.decrypt(
            base64.b64decode(encrypted_aes_key),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    # Desencriptar os dados sensíveis com a chave simétrica
    print("Decrypting sensitive data...")
    print(encrypted_sensitive_data)
    sensitive_data = decrypt(encrypted_sensitive_data, aes_key, iv)
    sensitive_data = json.loads(sensitive_data)



    username = sensitive_data.get("username")
    name = sensitive_data.get("name")
    email = sensitive_data.get("email")
    public_key_pem = sensitive_data.get("credentials_file")
    nonce = sensitive_data.get("nonce")

    if not nonce or not verify_nonce(nonce):
        return jsonify({"success": False, "message": "Invalid nonce"}), 403

    
    lines = public_key_pem.splitlines()
    key_lines = [line for line in lines if not line.startswith("-----")]
    cleaned_key = "".join(key_lines)

    if not all([username, name, email, cleaned_key]):
        return jsonify({"success": False, "message": "Missing required fields in sensitive data"}), 400


    conn = sqlite3.connect("subjects.db")
    cursor = conn.execute("""
            SELECT 1 FROM subjects WHERE username = ? OR email = ?
        """, (username, email))
    if cursor.fetchone():
        conn.close()
        return jsonify({"success": False, "message": "Subject already exists"}), 409
    conn.close()


    conn = sqlite3.connect("subjects.db")
    with conn:
        conn.execute("""
        INSERT INTO subjects (organization, username, name, email, credentials_file, status)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (organization, username, name, email, cleaned_key, "active"))
    conn.close()
  
    return jsonify({"success": True, "message": "Subject added successfully."}), 200


def recalculatehmac_not_encrypt(data, session_hmac, mac):

    # Verificar o MAC
    data.pop("mac", None)
    serialized_data = json.dumps(data).encode()
    session_hmac = session_hmac.encode()
    recalculated_hmac = hmac.new(session_hmac, serialized_data, hashlib.sha256).hexdigest()
    print("mac", mac)
    print("recalculated_hmac", recalculated_hmac)
    return True if mac != recalculated_hmac else False
    


@app.route("/subjects/list", methods=['GET'])
def rep_list_subjects():
    data = request.get_json()
    session_id = request.json.get("session_id")  
    username = request.json.get("username") 
    nonce = request.json.get("nonce")
    iv = request.json.get("iv")
    mac = request.json.get("mac")

    if not session_id:
        return jsonify({"success": False, "message": "Missing session ID"}), 400
    

    # Verificar se o sujeito está suspenso
    suspended, message = verify_subject_status(session_id)
    if suspended:
        return jsonify({"success": False, "message": message}), 403


    # Validar a sessão usando o session_id
    conn = sqlite3.connect("sessions.db")
    cursor = conn.execute("""
        SELECT organization, session_key, hmac FROM sessions WHERE session_id = ?
    """, (session_id,))
    session_data = cursor.fetchone()
    conn.close()

    if not session_data:
        return jsonify({"success": False, "message": "Invalid session ID"}), 403
    
    organization, session_key_b64, session_hmac = session_data
    

    print(username)
    if username != None:
        data.pop("username", None)
        

    # Verificar o MAC
    if recalculatehmac_not_encrypt(data, session_hmac, mac):
        return jsonify({"success": False, "message": "Invalid MAC"}), 403
    

    session_key = base64.b64decode(session_key_b64)

    # Desencriptar nonce com a chave simétrica
    nonce = decrypt(base64.b64decode(nonce), session_key, iv)

    if not verify_nonce(nonce):
        return jsonify({"success": False, "message": "Invalid nonce"}), 403


    
    try:
        conn = sqlite3.connect("subjects.db")
        cursor = None
 
        if username:
            cursor = conn.execute("""
                SELECT username, name, email, status FROM subjects
                WHERE organization = ? AND username = ?
            """, (organization, username))
            result = cursor.fetchone()
            if result:
                subjects =  {
                        "username": result[0],
                        "name": result[1],
                        "email": result[2],
                        "status": result[3],    
                }

                iv = os.urandom(16)  # Gerar o vetor de inicialização
                cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
                encryptor = cipher.encryptor()
                sensitive_data_encrypted = encryptor.update(json.dumps(subjects).encode()) + encryptor.finalize()




                return jsonify({
                    "encrypted_data": base64.b64encode(sensitive_data_encrypted).decode(),
                    "iv": base64.b64encode(iv).decode()
                }), 200
            
            else:
                return jsonify({"success": False, "message": "User not found"}), 404
        else:
            cursor = conn.execute("""
                SELECT username, name, email, status
                FROM subjects
                WHERE organization = ?
            """, (organization,))
            subjects = [
                {
                    "username": row[0],
                    "name": row[1],
                    "email": row[2],
                    "status": row[3],
                }
                for row in cursor.fetchall()
            ]
            
                        # Encriptar os dados com a chave simétrica
            iv = os.urandom(16)  # Gerar o vetor de inicialização
            cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
            encryptor = cipher.encryptor()
            sensitive_data_encrypted = encryptor.update(json.dumps(subjects).encode()) + encryptor.finalize()
            
            return jsonify({
                "encrypted_data": base64.b64encode(sensitive_data_encrypted).decode(),
                "iv": base64.b64encode(iv).decode()
            }), 200

    except sqlite3.Error as e:
        return jsonify({"success": False, "message": f"Database error: {str(e)}"}), 500
    finally:
        conn.close()




@app.route("/document/get", methods=['GET'])
def doc_get():
    organization = request.args.get("organization")
    session_id = request.args.get("session_id")
    document_id = request.args.get("document_id")

    
    error = verify_session(organization, session_id)
    if error:
        return jsonify(error[0]), error[1]

    if document_id not in organizations[organization]["documents"]:
        return jsonify({"success": False, "message": "Document does not exist"}), 404

    document = organizations[organization]["documents"][document_id]
    return jsonify({
        "document_id": document_id,
        "title": document["title"],
        "content": document["content"]
    }), 200





DOCUMENTS_DIR = "documents"


def file_exists_with_digest(file_digest, document_dir=DOCUMENTS_DIR):
    """Verifica se um arquivo com o digest já existe no diretório especificado."""
    document_file_path = os.path.join(document_dir, f"{file_digest}.txt")
    return os.path.exists(document_file_path)


def save_document_to_file(document_name, document_content, file_digest, document_dir=DOCUMENTS_DIR):
    document_file_path = os.path.join(document_dir, f"{file_digest}.txt")

    if file_exists_with_digest(file_digest):
        return 0

    os.makedirs(document_dir, exist_ok=True)

    with open(document_file_path, "w") as f:
        f.write(document_content)
    
    return 1



def save_metadata(metadata):
    """Salva os metadados do documento na base de dados."""
    try:
        conn = sqlite3.connect("documents.db")
        with conn:
            conn.execute("""
            INSERT INTO documents (document_handle, name, create_date, creator, file_handle, acl, alg, key, iv, organization)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                metadata["document_handle"],
                metadata["name"],
                metadata["create_date"],
                metadata["creator"],
                metadata["file_handle"],
                json.dumps(metadata["acl"]), 
                metadata["alg"],
                metadata["key"],
                metadata["iv"],
                metadata["organization"]
            ))
        print("Metadata saved successfully.")
    except sqlite3.IntegrityError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        conn.close()



def is_path_safe(file_path, base_dir="documents"):
    """Verifica se o caminho do arquivo é seguro."""
    absolute_base = os.path.abspath(base_dir)
    absolute_path = os.path.abspath(file_path)
    return absolute_path.startswith(absolute_base)



@app.route("/document/add", methods=['POST'])
def rep_add_doc():
    """
    Endpoint para adicionar um documento.
    """

    session_id = request.json.get("session_id")
    encrypted_sensitive_data = base64.b64decode(request.json.get("encrypted_sensitive_data"))
    encrypted_aes_key = request.json.get("encrypted_aes_key")
    iv = request.json.get("iv")
    mac = request.json.get("mac")

    has_perm, error_message = has_permission(session_id, "DOC_NEW")
    if not has_perm:
        return jsonify({"error": error_message}), 403

    if not session_id or not encrypted_sensitive_data or not encrypted_aes_key or not iv:
        return jsonify({"success": False, "message": "Missing required fields"}), 400


    # Verificar se o sujeito está suspenso
    suspended, message = verify_subject_status(session_id)
    if suspended:
        return jsonify({"success": False, "message": message}), 403
    

    # Verificar a sessão
    conn = sqlite3.connect("sessions.db")
    cursor = conn.execute("""
        SELECT username, organization, roles, hmac FROM sessions WHERE session_id = ?
    """, (session_id,))
    session_data = cursor.fetchone()
    conn.close()

    if not session_data:
        return jsonify({"success": False, "message": "Invalid session ID"}), 403

    username, organization, roles, hmac_key = session_data
    roles = roles.split(",") if roles else []

    if roles == []:
        return jsonify({"success": False, "message": "No roles assigned to the user"}), 408
    

    hmac_ecode = hmac_key.encode()
    recalculated_hmac = hmac.new(hmac_ecode, encrypted_sensitive_data, hashlib.sha256).hexdigest()

    # Comparar o hmac recebido com o recalculado
    if mac != recalculated_hmac:
        return jsonify({"success": False, "message": "Invalid MAC"}), 420


    # Descriptografar a chave AES com RSA
    private_key = SERVER_PRIVATE_KEY
    try:
        aes_key = private_key.decrypt(
            base64.b64decode(encrypted_aes_key),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to decrypt AES key: {str(e)}"}), 400

    # Descriptografar os dados sensíveis com AES
    aes_cipher = Cipher(algorithms.AES(aes_key), modes.CFB(bytes.fromhex(iv)), backend=default_backend())
    aes_decryptor = aes_cipher.decryptor()
    sensitive_data = json.loads(aes_decryptor.update(encrypted_sensitive_data) + aes_decryptor.finalize())

    # Extrair os dados sensíveis
    document_name = sensitive_data["document_name"]
    document_content = sensitive_data["document_content"]
    file_digest = sensitive_data["file_digest"]
    alg = sensitive_data["alg"]
    iv = sensitive_data["iv"]
    key = sensitive_data["key"]
    nonce = sensitive_data["nonce"]

    if not nonce or not verify_nonce(nonce):
        return jsonify({"success": False, "message": "Invalid nonce"}), 403
    

    if not all([document_name, document_content, file_digest, alg, iv, key, nonce]):
        return jsonify({"success": False, "message": "Missing required fields in sensitive data"}), 400

    
    acl = { "Manager": ["DOC_READ", "DOC_ACL", "DOC_DELETE"]}
    for role in roles:
        if role not in acl:
            acl[role] = ["DOC_READ", "DOC_DELETE"]


    document_path = os.path.join("documents", f"{file_digest}.txt")

    # Verificar se o caminho do arquivo é seguro
    if not is_path_safe(document_path, DOCUMENTS_DIR):
        return jsonify({"success": False, "message": "Invalid file path. Access to the directory is not allowed."}), 405

    # Salvar o arquivo encriptado
    num = save_document_to_file(document_name, document_content, file_digest)
    if num == 0:
        return jsonify({"success": False, "message": "Document already exists"}), 409
    

    # Criar metadados
    document_handle = str(uuid.uuid4())
    create_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    metadata = {
        "document_handle": document_handle,
        "name": document_name,
        "create_date": create_date,
        "creator": username,
        "file_handle": file_digest,
        "acl": acl,
        "alg": alg,
        "iv": iv,
        "key": key,
        "organization": organization
    }

    save_metadata(metadata)

    return jsonify({"success": True, "message": f"Document '{document_name}' added successfully."}), 200


@app.route("/document/list", methods=['POST'])
def rep_list_docs():
    data = request.get_json()
    session_id = request.json.get("session_id")

    username_filter = data.get("username")
    date_filter = data.get("date_filter")
        

    # Verificar se o sujeito está suspenso
    suspended, message = verify_subject_status(session_id)
    if suspended:
        return jsonify({"success": False, "message": message}), 403
    """
    Endpoint para listar documentos de uma sessão a partir do banco de dados.
    """
    try:


        nonce = request.json.get("nonce")
        iv = request.json.get("iv")
        mac = request.json.get("mac")   
        
        username = data.get("username") 
        date_filter = data.get("date_filter") 

        if not session_id:
            return jsonify({"success": False, "message": "Missing required field: session_id"}), 400
        

        # Verificar o session_id no banco de dados
        conn = sqlite3.connect("sessions.db")
        cursor = conn.execute("""
            SELECT session_key, username, organization, hmac FROM sessions WHERE session_id = ?
        """, (session_id,))
        session_data = cursor.fetchone()
        conn.close()

        if not session_data:
            return jsonify({"success": False, "message": "ID invalid"}), 400
        
        session_key, session_username, organization, session_hmac = session_data
        session_key = base64.b64decode(session_key)

        username_filter = data.get("username")



        # Desencriptar o nonce com a chave 
        nonce = decrypt(base64.b64decode(nonce), session_key, iv)

        if not verify_nonce(nonce):
            return jsonify({"success": False, "message": "Invalid nonce"}), 403
        

        if username:
            data.pop("username", None)
        
        if date_filter:
            data.pop("date_filter", None)

        if username and date_filter:
            data.pop("username", None)
            data.pop("date_filter", None)
        
        # Verificar o MAC
        if recalculatehmac_not_encrypt(data, session_hmac, mac):
            return jsonify({"success": False, "message": "Invalid MAC"}), 403

        if date_filter:
            date_filter_type = date_filter[:2]
            date = date_filter[2:]
        else:
            date_filter_type = None
            date = None
        conn = sqlite3.connect("documents.db")
        cursor = conn.cursor()


        query = """
            SELECT document_handle, name, create_date, creator, file_handle, acl, deleter
            FROM documents
            WHERE organization = ?
        """
        params = [organization]

        # Filtro por criador
        if username:
            query += " AND creator = ?"
            params.append(username_filter)


        '''if date_filter_type and date:
            
            if date_filter_type == "nt":
                query += " AND DATE(create_date) > ?"
            elif date_filter_type == "ot":
                query += " AND DATE(create_date) < ?"
            elif date_filter_type == "et":
                query += " AND DATE(create_date) = ?"
            params.append(date)  '''


        if date_filter:
            try:
                date_filter_type, date_value = date_filter.split()
                date_value = datetime.strptime(date_value, "%d-%m-%Y").strftime("%Y-%m-%d")
            except ValueError:
                return jsonify({"success": False, "message": "Invalid date filter format."}), 400

            if date_filter_type == "nt":
                query += " AND DATE(create_date) > ?"
            elif date_filter_type == "ot":
                query += " AND DATE(create_date) < ?"
            elif date_filter_type == "et":
                query += " AND DATE(create_date) = ?"
            params.append(date_value)

        # Execute a query e retorne os resultados
        try:
            cursor = conn.execute(query, params)
            documents = cursor.fetchall()
        finally:
            conn.close()


    
      

        # Executar a query
        conn = sqlite3.connect("documents.db")
        cursor = conn.execute(query, params)
        documents = cursor.fetchall()
        conn.close()

       
        if not documents:
            return jsonify({"success": True, "message": "No documents found.", "documents": []}), 200

   
        documents_list = [
            {
                "document_handle": doc[0],
                "name": doc[1],
                "create_date": doc[2],
                "creator": doc[3],
                "file_handle": doc[4],
                "acl": doc[5],
                "deleter": doc[6]
            }
            for doc in documents
        ]

       
        return jsonify({
            "success": True,
            "message": "Documents retrieved successfully.",
            "documents": documents_list
        }), 200

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500



@app.route("/document/delete", methods=['POST'])
def rep_delete_doc():
        
    session_id = request.json.get("session_id")
    document_name = request.json.get("document_name")
    encrypted_data = base64.b64decode(request.json.get("encrypted_data"))
    iv = request.json.get("iv")
    mac = request.json.get("mac")


    if not all([session_id, document_name, encrypted_data, iv]):
        return jsonify({"success": False, "message": "Missing required fields"}), 400
        

    # Validar a sessão e buscar a session_key
    conn = sqlite3.connect("sessions.db")
    cursor = conn.execute("""
        SELECT session_key, username, roles, hmac FROM sessions WHERE session_id = ?
    """, (session_id,))
    session_data = cursor.fetchone()
    conn.close()

    if not session_data:
        return jsonify({"success": False, "message": "Invalid session ID"}), 403

    session_key = base64.b64decode(session_data[0])  # Decodifica a chave armazenada em Base64
    deleter = session_data[1]  # Extrai o username diretamente
    roles = session_data[2]  # Extrai o papel diretamente
    hmac_key = session_data[3]  # Extrai a chave HMAC diretamente


    hmac_encode = hmac_key.encode()
    recalculated_hmac = hmac.new(hmac_encode, encrypted_data, hashlib.sha256).hexdigest()

    print(mac)
    print(recalculated_hmac)

    if mac != recalculated_hmac:
        return jsonify({"success": False, "message": "Invalid MAC"}), 403


    if not deleter:
        return jsonify({"success": False, "message": "Unable to identify the user from the session ID"}), 403
    



    conn = sqlite3.connect("documents.db")
    cursor = conn.execute("""
        SELECT document_handle, name, create_date, creator, file_handle, acl, alg, key, iv
        FROM documents
        WHERE name = ?
    """, (document_name,))
    document = cursor.fetchone()
    conn.close()

    if not document:
        return jsonify({"success": False, "message": "Document not found"}), 404


    acl = json.loads(document[5])  # Carregar o ACL
    is_creator = deleter == document[3]

    user_roles = roles.split(",")

    has_doc_read_permission = any(
        role in acl and "DOC_READ" in acl[role]
        for role in user_roles
    )

    if not is_creator and not has_doc_read_permission:
        return jsonify({"success": False, "message": "Access denied: DOC_DELETE required"}), 403


    # Desencriptar os dados sensíveis
    sensitive_data = json.loads(decrypt(encrypted_data, session_key, iv))

    # Extrair informações do sensitive_data
    
    nonce = sensitive_data.get("nonce")

    if not nonce or not verify_nonce(nonce):
        return jsonify({"success": False, "message": "Invalid nonce"}), 403


    connection = sqlite3.connect('documents.db')  
    cursor = connection.cursor()

    cursor.execute("SELECT file_handle, key, alg FROM documents WHERE name = ?", (document_name,))
    row = cursor.fetchone()

    if not row:
        return jsonify({"success": False, "message": f"Document '{document_name}' not found."}), 404
    


    cursor.execute("UPDATE documents SET file_handle = '', deleter = ? WHERE name = ?", (deleter, document_name))
    connection.commit() 
    connection.close()

        
    return jsonify({
        "success": True,
        "message": f"Document '{document_name}' deleted successfully.",
        "deleter": deleter
    }), 200 


def decrypt(encrypt_data,session_key, iv):
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(bytes.fromhex(iv)), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypt_data) + decryptor.finalize()
    return decrypted_data.decode()


@app.route("/subject/suspend", methods=['POST'])
def rep_suspend_subject():
    data = request.get_json()
    session_id = request.json.get("session_id")
    encrypted_username = request.json.get("encrypted_username")
    iv = request.json.get("iv")
    encrypted_nonce = request.json.get("encrypted_nonce")
    mac = request.json.get("mac")

    if not all([session_id, encrypted_username, iv, encrypted_nonce]):
        return jsonify({"error": "Missing required fields."}), 400

    has_perm, error_message = has_permission(session_id, "SUBJECT_DOWN")
    if not has_perm:
        return jsonify({"error": error_message}), 405

    # Validar a sessão usando o session_id
    conn = sqlite3.connect("sessions.db")
    cursor = conn.execute("""
        SELECT session_key, hmac FROM sessions WHERE session_id = ?
    """, (session_id,))
    session_data = cursor.fetchone()
    conn.close()

    if not session_data:
        return jsonify({"error": "Invalid session ID."}), 404

    session_key = base64.b64decode(session_data[0])  # Obter a chave simétrica
    session_hmac = session_data[1]  # Obter a chave HMAC

    # Verificar o MAC
    if recalculatehmac_not_encrypt(data, session_hmac, mac):
        return jsonify({"error": "Invalid MAC."}), 403
    

    # Desencriptar o username
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(bytes.fromhex(iv)), backend=default_backend())
    decryptor = cipher.decryptor()
    username = decryptor.update(base64.b64decode(encrypted_username)) + decryptor.finalize()
    username = username.decode()

    # Desencriptar o nonce
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(bytes.fromhex(iv)), backend=default_backend())
    decryptor = cipher.decryptor()
    nonce = decryptor.update(base64.b64decode(encrypted_nonce)) + decryptor.finalize()
    nonce = nonce.decode()

    # Verificar o nonce
    if not verify_nonce(nonce):
        return jsonify({"error": "Invalid nonce."}), 404

    # Verificar se o utilizador é um Manager
    conn_role = sqlite3.connect("roles.db")
    cursor = conn_role.execute("""
        SELECT 1 FROM role_subjects WHERE role_name = 'Manager' AND subject_username = ?
    """, (username,))
    is_manager = cursor.fetchone() is not None
    conn_role.close()

    if is_manager:
        return jsonify({"error": f"Subject '{username}' is a Manager and cannot be suspended."}), 404


    # Verificar status do utilizador
    conn = sqlite3.connect("subjects.db")
    with conn:
        cursor = conn.execute("SELECT status FROM subjects WHERE username = ?", (username,))
        subject = cursor.fetchone()
        if not subject:
            return jsonify({"error": f"Subject '{username}' not found."}), 404

        current_status = subject[0]
        if current_status == "suspended":
            return jsonify({"error": f"Subject '{username}' is already suspended."}), 400

        # Atualizar o status para 'suspended'
        conn.execute("UPDATE subjects SET status = ? WHERE username = ?", ("suspended", username))
    conn.close()

    return jsonify({"message": f"Subject '{username}' suspended successfully."}), 200


@app.route("/subject/activate", methods=['POST'])
def rep_activate_subject():
    data = request.get_json()
    session_id = request.json.get("session_id")
    encrypted_username = request.json.get("encrypted_username")
    iv = request.json.get("iv")
    encrypted_nonce = request.json.get("encrypted_nonce")
    mac = request.json.get("mac")

    has_perm, error_message = has_permission(session_id, "SUBJECT_UP")
    if not has_perm:
        return jsonify({"error": error_message}), 403

    if not all([session_id, encrypted_username, iv, encrypted_nonce]):
        return jsonify({"error": "Missing required fields."}), 400

    conn = sqlite3.connect("sessions.db")
    cursor = conn.execute("""
        SELECT session_key, hmac FROM sessions WHERE session_id = ?
    """, (session_id,))
    session_data = cursor.fetchone()
    conn.close()

    if not session_data:
        return jsonify({"error": "Invalid session ID."}), 403

    session_key = base64.b64decode(session_data[0])  # Obter a chave simétrica
    session_hmac = session_data[1]  # Obter a chave HMAC

    # Verificar o MAC
    if recalculatehmac_not_encrypt(data, session_hmac, mac):
        return jsonify({"error": "Invalid MAC."}), 403


    # Desencriptar o username
    username = decrypt(base64.b64decode(encrypted_username), session_key, iv)

    # Desencriptar o nonce
    nonce = decrypt(base64.b64decode(encrypted_nonce), session_key, iv)

    # Verificar o nonce
    if not verify_nonce(nonce):
        return jsonify({"error": "Invalid nonce."}), 403

    # Verificar status do utilizador
    conn = sqlite3.connect("subjects.db")
    with conn:
        cursor = conn.execute("SELECT status FROM subjects WHERE username = ?", (username,))
        subject = cursor.fetchone()
        if not subject:
            return jsonify({"error": f"Subject '{username}' not found."}), 404

        current_status = subject[0]
        if current_status == "active":
            return jsonify({"error": f"Subject '{username}' is already active."}), 400

        # Atualizar o status para 'active'
        conn.execute("UPDATE subjects SET status = ? WHERE username = ?", ("active", username))
    conn.close()

    return jsonify({"message": f"Subject '{username}' activated successfully."}), 200


# Verifica o status do sujeito associado a uma sessão
def verify_subject_status(session_id):
    """
    Verifica se o sujeito associado a uma sessão está suspenso.
    """
    try:
        conn = sqlite3.connect("sessions.db")
        cursor = conn.execute("""
            SELECT username FROM sessions WHERE session_id = ?
        """, (session_id,))
        session_data = cursor.fetchone()
        conn.close()

        if not session_data:
            return False, "Invalid session ID"

        username = session_data[0]

        # Verificar o status do sujeito no banco de dados
        conn = sqlite3.connect("subjects.db")
        cursor = conn.execute("""
            SELECT status FROM subjects WHERE username = ?
        """, (username,))
        subject_data = cursor.fetchone()
        conn.close()

        if not subject_data:
            return False, f"Subject '{username}' not found."

        if subject_data[0] == "suspended":
            return True, f"Subject '{username}' is suspended and cannot perform this action."

        return False, None
    except sqlite3.Error as e:
        return False, f"Database error: {str(e)}"


@app.route("/document/metadata", methods=['POST'])
def rep_get_doc_metadata():
    """Retorna os metadados de um documento."""
    data = request.get_json()
    session_id = request.json.get("session_id")
    document_name = request.json.get("document_name")
    encrypted_nonce = request.json.get("nonce")
    iv = request.json.get("iv")
    mac = request.json.get("mac")

    if not session_id or not document_name:
        return jsonify({"success": False, "message": "Missing required fields"}), 400

    
    conn = sqlite3.connect("sessions.db")
    cursor = conn.execute("""
        SELECT username, session_key, roles, hmac FROM sessions WHERE session_id = ?
    """, (session_id,))
    session_data = cursor.fetchone()
    conn.close()

    if not session_data:
        return jsonify({"success": False, "message": "Invalid session ID"}), 403

    username, session_key, roles, hmac = session_data
    session_key = base64.b64decode(session_key)

    if recalculatehmac_not_encrypt(data, hmac, mac):
        return jsonify({"success": False, "message": "Invalid MAC"}), 403

    # Verificar se o usuário tem roles atribuídos
    if not roles:
        return jsonify({"success": False, "message": "User has no assigned roles. Please assign a role before proceeding."}), 403
    
    if iv:
        nonce = decrypt(base64.b64decode(encrypted_nonce),session_key, iv)
    
        if not verify_nonce(nonce):
            return jsonify({"success": False, "message": "Invalid nonce"}), 403

    try:
        conn = sqlite3.connect("documents.db")
        cursor = conn.execute("""
            SELECT document_handle, name, create_date, creator, file_handle, acl, alg, key, iv
            FROM documents
            WHERE name = ?
        """, (document_name,))
        document = cursor.fetchone()
        conn.close()

        if not document:
            return jsonify({"success": False, "message": "Document not found"}), 404


        acl = json.loads(document[5])  # Carregar o ACL
        is_creator = username == document[3]

        user_roles = roles.split(",")

        has_doc_read_permission = any(
            role in acl and "DOC_READ" in acl[role]
            for role in user_roles
        )

        if not is_creator and not has_doc_read_permission:
            return jsonify({"success": False, "message": "Access denied: DOC_READ required"}), 403

        metadata = {
            "document_handle": document[0],
            "name": document[1],
            "create_date": document[2],
            "creator": document[3],
            "file_handle": document[4],
            "acl": acl,  
            "alg": document[6],
            "key": document[7],
            "iv": document[8],
            "username": username
        }

        # Encriptar os metadados com a session_key
        metadata_json = json.dumps(metadata).encode()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_metadata = encryptor.update(metadata_json) + encryptor.finalize()


        return jsonify({
            "encrypted_metadata": base64.b64encode(encrypted_metadata).decode(),
            "iv": iv.hex()
        }), 200
    except sqlite3.Error as e:
        return jsonify({"success": False, "message": f"Database error: {str(e)}"}), 500
    

@app.route("/file/get", methods=["POST"])
def rep_get_file():
    """Endpoint para baixar um arquivo pelo file_handle."""
    file_handle = request.json.get("file_handle")

    if not file_handle:
        return jsonify({"success": False, "message": "Missing required field: file_handle"}), 400
    

   
    document_path = os.path.join(DOCUMENTS_DIR, f"{file_handle}.txt")

    if not os.path.exists(document_path):
        return jsonify({"success": False, "message": f"File with handle '{file_handle}' not found."}), 404

    try:
        with open(document_path, "rb") as f:
            file_content = f.read()
        return file_content, 200, {'Content-Type': 'application/octet-stream'}
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
    

@app.route("/file/decrypt", methods=["POST"])
def rep_decrypt_file():
    """
    Endpoint para descriptografar um arquivo com base nos metadados fornecidos.
    """
   
    encrypted_file = request.json.get("encrypted_file")
    key = bytes.fromhex(request.json.get("key"))
    iv = bytes.fromhex(request.json.get("iv"))
    algorithm = request.json.get("alg")

   
    if not all([encrypted_file, key, iv, algorithm]):
        return jsonify({"success": False, "message": "Missing required fields: encrypted_file, key, iv, alg"}), 400

    
    if not os.path.exists(encrypted_file):
        return jsonify({"success": False, "message": f"Encrypted file '{encrypted_file}' not found."}), 404

    
    with open(encrypted_file, "rb") as f:
        encrypted_content = f.read()

    
    if algorithm != "AES-256-CFB":
        return jsonify({"success": False, "message": f"Unsupported algorithm '{algorithm}'."}), 400

    
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

   
    decrypted_content = decryptor.update(encrypted_content) + decryptor.finalize()

    print("Decrypted content (before returning):", decrypted_content.decode("utf-8", errors="replace"))


    return jsonify({"success": True, "decrypted_content": decrypted_content.decode("utf-8", errors="ignore")}), 200



@app.route("/role/assume", methods=["POST"])
def rep_assume_role():
    """Endpoint para um sujeito assumir um papel em uma sessão."""
    data = request.json
    session_id = request.json.get("session_id")
    role = request.json.get("role")
    encrypted_nonce = request.json.get("nonce")
    iv = request.json.get("iv")
    mac = request.json.get("mac")


    if not session_id or not role:
        return jsonify({"success": False, "message": "Missing required fields: session_id or role"}), 400
    

    # Verificar se o sujeito está suspenso
    suspended, message = verify_subject_status(session_id)
    if suspended:
        return jsonify({"success": False, "message": message}), 403
    


    # Validar a sessão
    conn = sqlite3.connect("sessions.db")
    cursor = conn.execute("""
        SELECT session_key,organization, username, roles, hmac FROM sessions WHERE session_id = ?
    """, (session_id,))
    session_data = cursor.fetchone()
    conn.close()


    if not session_data:
        return jsonify({"success": False, "message": "Invalid session ID"}), 403


    session_key_encoded, organization, username, current_roles, session_hmac = session_data
    session_key = base64.b64decode(session_key_encoded)


    current_roles = current_roles.split(",") if current_roles else []  # Transformar roles assumidos em lista


    # Verificar o MAC
    if recalculatehmac_not_encrypt(data, session_hmac, mac):    
        return jsonify({"success": False, "message": "Invalid MAC"}), 403

    # Desencriptar o nonce
    nonce = decrypt(base64.b64decode(encrypted_nonce),session_key, iv)

    if not verify_nonce(nonce):
        return jsonify({"success": False, "message": "Invalid nonce"}), 403
    


    # Validar se o papel existe e está ativo
    conn = sqlite3.connect("roles.db")
    cursor = conn.execute("""
        SELECT status FROM roles WHERE name = ? AND organization = ?
    """, (role, organization))
    role_data = cursor.fetchone()
    conn.close()

    if not role_data or role_data[0] != "active":
        return jsonify({"success": False, "message": f"Role '{role}' not found or inactive in organization '{organization}'"}), 404
    


    # Verificar se o sujeito está associado ao papel na tabela role_subjects
    conn = sqlite3.connect("roles.db")
    cursor = conn.execute("""
        SELECT 1 FROM role_subjects WHERE role_name = ? AND subject_username = ? AND organization = ?
    """, (role, username, organization))
    is_associated = cursor.fetchone()
    conn.close()

    if not is_associated:
        return jsonify({"success": False, "message": f"You are not associated with the role '{role}'."}), 403
    
    current_roles.append(role)
    updated_roles = ",".join(current_roles)
    conn = sqlite3.connect("sessions.db")
    conn.execute("""
        UPDATE sessions SET roles = ? WHERE session_id = ?
    """, (updated_roles, session_id))
    conn.commit()
    conn.close()

    # Sucesso
    return jsonify({"success": True, "message": f"Role '{role}' assumed successfully."}), 200



@app.route('/role/drop', methods=['POST'])
def rep_drop_role():
    """
    Endpoint para remover um papel atribuído a uma sessão.
    """
    data = request.json
    session_id = data.get("session_id")
    role = data.get("role")
    encrypted_nonce = data.get("nonce")
    iv = data.get("iv")
    mac = data.get("mac")

    if not session_id or not role:
        return jsonify({"success": False, "message": "Missing required fields: session_id or role"}), 400

    # Validar a sessão
    conn = sqlite3.connect("sessions.db")
    cursor = conn.execute("""
        SELECT username, session_key, roles, hmac FROM sessions WHERE session_id = ?
    """, (session_id,))
    session_data = cursor.fetchone()
    conn.close()

    if not session_data:
        return jsonify({"success": False, "message": "Invalid session ID"}), 403

    username, session_key_encode, current_roles, session_hmac = session_data
    print("Current roles:", current_roles)

    session_key = base64.b64decode(session_key_encode)


    # Verificar o MAC
    if recalculatehmac_not_encrypt(data, session_hmac, mac):
        return jsonify({"success": False, "message": "Invalid MAC"}), 403

    # Desencriptar o nonce
    nonce = decrypt(base64.b64decode(encrypted_nonce),session_key, iv)

    if not verify_nonce(nonce):
        return jsonify({"success": False, "message": "Invalid nonce"}), 403
    

    # Atualizar a coluna roles removendo o papel
    roles = current_roles.split(",") if current_roles else []
    if role not in roles:
        return jsonify({"success": False, "message": f"Role '{role}' is not assigned to this session"}), 404

    roles.remove(role)

    # Salvar os papéis atualizados
    conn = sqlite3.connect("sessions.db")
    conn.execute("""
        UPDATE sessions SET roles = ? WHERE session_id = ?
    """, (",".join(roles) if roles else None, session_id))
    conn.commit()
    conn.close()

    # Remover o papel dos roles do utilizador
    conn = sqlite3.connect("roles.db")
    conn.execute("""
        DELETE FROM role_subjects WHERE role_name = ? AND subject_username = ?
    """, (role, username))
    conn.commit()
    conn.close()


    return jsonify({"success": True, "message": f"Role '{role}' dropped successfully."}), 200
def has_permission(session_id, required_permission):
    """
    Verifica se o utilizador da sessão tem a permissão necessária.
    """
    conn = sqlite3.connect("sessions.db")
    cursor = conn.execute("""
        SELECT username, organization, roles FROM sessions WHERE session_id = ?
    """, (session_id,))
    session_data = cursor.fetchone()
    conn.close()

    if not session_data:
        return False, "Invalid session ID."

    username, organization, roles = session_data

    if not roles:
        return False, "Permission Denied"

    # Verificar permissões dos roles do utilizador
    conn = sqlite3.connect("roles.db")
    cursor = conn.execute("""
        SELECT r.permissions
        FROM roles r
        JOIN role_subjects rs ON r.name = rs.role_name
        WHERE rs.subject_username = ? AND rs.organization = ? AND r.status = 'active'
    """, (username, organization))
    roles = cursor.fetchall()
    conn.close()

    if not roles:
        return False, "Permisssion Denied"

    # Verificar se a permissão está em algum dos roles
    for role in roles:
        permissions = role[0].split(",")  # Separar permissões por vírgulas
        print("Permissions:", permissions)
        if required_permission in permissions:
            return True, None

    return False, "Permission denied."



@app.route("/role/add", methods=['POST'])
def rep_add_role():
    """
    Endpoint para adicionar um novo papel (role) à organização com a qual o utilizador tem uma sessão ativa.
    """
    data = request.json
    session_id = request.json.get("session_id")
    role_name = request.json.get("role_name")
    encrypted_nonce = request.json.get("nonce")
    iv = request.json.get("iv")
    mac = data.get("mac")

    if not session_id or not role_name:
        return jsonify({"success": False, "message": "Missing required fields: session_id, role_name"}), 400
    

    #Verificar se a sessão está ativa
    conn = sqlite3.connect("sessions.db")
    cursor = conn.execute("SELECT session_key, hmac FROM sessions WHERE session_id = ?", (session_id,))
    session_data = cursor.fetchone()
    conn.close()

    if not session_data:
        return jsonify({"success": False, "message": "Invalid session ID"}), 403

    session_key = base64.b64decode(session_data[0])
    session_hmac = session_data[1]

    # Verificar o MAC
    if recalculatehmac_not_encrypt(data, session_hmac, mac):
        return jsonify({"success": False, "message": "Invalid MAC"}), 403

    # Desencriptar o nonce
    nonce = decrypt(base64.b64decode(encrypted_nonce),session_key, iv)

    if not verify_nonce(nonce):
        return jsonify({"success": False, "message": "Invalid nonce"}), 403

    #Verificar se o utilizador tem a permissão ROLE_NEW
    has_perm, error_message = has_permission(session_id, "ROLE_NEW")
    if not has_perm:
        return jsonify({"success": False, "message": error_message}), 403


    conn = sqlite3.connect("sessions.db")
    cursor = conn.execute("SELECT organization FROM sessions WHERE session_id = ?", (session_id,))
    organization = cursor.fetchone()[0]
    conn.close()

        #Verificar se o role já existe
    conn = sqlite3.connect("roles.db")
    cursor = conn.execute("""SELECT 1 FROM roles WHERE name = ? and organization = ?""", (role_name, organization))
    role_exists = cursor.fetchone() is not None
    conn.close()

    if role_exists:
        return jsonify({"success": False, "message": f"Role '{role_name}' already exists."}), 409
    
    


    # Adicionar o papel à base de dados
    try:
        conn = sqlite3.connect("roles.db")
        with conn:
            conn.execute("""
                INSERT INTO roles (name, organization, permissions, status)
                VALUES (?, ?, '', 'active')
            """, (role_name, organization))  
        return jsonify({"success": True, "message": f"Role '{role_name}' added successfully."}), 200
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": f"Role '{role_name}' already exists."}), 409
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


    
SERVER_PRIVATE_KEY = None

def load_server_private_key():
    """Carrega a chave privada do servidor a partir de um arquivo PEM."""
    global SERVER_PRIVATE_KEY
    with open("server_private_key.pem","rb") as key_file:
        SERVER_PRIVATE_KEY = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    print("Chave privada carregada com sucesso!")


DB_PATH = "sessions.db"
ROLES_DB_PATH = "roles.db"

@app.route('/role/list', methods=['POST'])
def list_roles():
    """
    Lista os papéis disponíveis para a organização associada à sessão.
    """
    try:
        # Extrair dados da requisição
        data = request.json
        session_id = data.get("session_id")
        role_name = data.get("role", None)  # Role opcional para busca específica
        encrypted_nonce = data.get("nonce")
        mac = data.get("mac")
        iv = data.get("iv")

        if not session_id:
            return jsonify({"error": "Session ID is required"}), 400

        # Conectar ao banco de dados de sessões
        session_conn = sqlite3.connect(DB_PATH)
        session_cursor = session_conn.cursor()

        # Validar a sessão e recuperar a organização
        session_cursor.execute("SELECT session_key, organization, hmac FROM sessions WHERE session_id = ?", (session_id,))
        session_data = session_cursor.fetchone()

        if not session_data:
            return jsonify({"error": "Invalid or expired session"}), 401

        session_key_encode, organization, hmac = session_data  # Organização e session_key associada à sessão

        session_key = base64.b64decode(session_key_encode)  # Decodificar a chave simétrica

        if role_name:
            data.pop("role", None)

        # Verificar o MAC
        if recalculatehmac_not_encrypt(data, hmac, mac):
            return jsonify({"error": "Invalid MAC"}), 403


        # Desencriptar o nonce
        nonce = decrypt(base64.b64decode(encrypted_nonce), session_key, iv)

        if not verify_nonce(nonce):
            return jsonify({"error": "Invalid nonce"}), 403

        # Conectar ao banco de dados de papéis
        roles_conn = sqlite3.connect(ROLES_DB_PATH)
        roles_cursor = roles_conn.cursor()

        if role_name:
            # Listar informações específicas do papel solicitado
            roles_cursor.execute("""
                SELECT name, permissions, status 
                FROM roles 
                WHERE organization = ? AND name = ?
            """, (organization, role_name))
        else:
            # Listar todos os papéis da organização
            roles_cursor.execute("""
                SELECT name, permissions, status 
                FROM roles 
                WHERE organization = ?
            """, (organization,))

        roles = roles_cursor.fetchall()

        # Fechar conexões
        session_conn.close()
        roles_conn.close()

        # Processar a resposta
        if not roles:
            return jsonify({"message": "No roles found for the organization."}), 200

        roles_list = [
            {
                "name": role[0],
                "permissions": role[1].split(",") if role[1] else [],
                "status": role[2]
            } for role in roles
        ]
        return jsonify({"roles": roles_list}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/role/modify', methods=['POST'])
def modify_role():
    """
    Modifica as propriedades de um papel (adicionar/remover permissões ou sujeitos).
    """
    data = request.json
    session_id = data.get("session_id")
    role = data.get("role")
    target = data.get("target")  # Pode ser username ou permission
    action = data.get("action")
    encrypted_nonce = data.get("nonce")
    iv = data.get("iv")
    mac = data.get("mac")

    if not session_id or not role or not target or not action:
        return jsonify({"error": "Missing required fields."}), 400
    

    # Verificar se o utilizador tem a permissão ROLE_MOD
    has_perm, error_message = has_permission(session_id, "ROLE_MOD")
    if not has_perm:
        return jsonify({"error": error_message}), 403

    # Validar sessão
    conn = sqlite3.connect("sessions.db")
    session = conn.execute("SELECT session_key, organization, hmac FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
    conn.close()
    if not session:
        return jsonify({"error": "Invalid session."}), 403

    
    session_key, organization, session_hmac = session
    session_key = base64.b64decode(session_key)


    # Desencriptar o nonce
    nonce = decrypt(base64.b64decode(encrypted_nonce), session_key, iv)

    if not verify_nonce(nonce):
        return jsonify({"error": "Invalid nonce."}), 403

    # Verificar o MAC
    if recalculatehmac_not_encrypt(data, session_hmac, mac):
        return jsonify({"error": "Invalid MAC."}), 403



    # Verificar se o role existe

    conn = sqlite3.connect("roles.db")
    cursor = conn.execute("""
        SELECT 1 FROM roles WHERE name = ? AND organization = ?
    """, (role, organization))
    role_exists = cursor.fetchone() is not None
    conn.close()

    if not role_exists:
        return jsonify({"error": f"Role '{role}' does not exist in organization '{organization}'."}), 404


    # Processar a ação
    conn = sqlite3.connect("roles.db")
    cursor = conn.cursor()
    try:
        if action == "add_permission":

            # Verificar se a permissão já existe
            cursor.execute("SELECT permissions FROM roles WHERE name = ? AND organization = ?", (role, organization))
            current_permissions = cursor.fetchone()[0]

            if not current_permissions:
                new_permissions = target
            else:
                permissions_list = current_permissions.split(',')
                if target in permissions_list:
                    return jsonify({"error": f"Permission '{target}' already exists for role '{role}' in organization '{organization}'."}), 400
                permissions_list.append(target)
                new_permissions = ','.join(permissions_list)    

            cursor.execute("UPDATE roles SET permissions = ? WHERE name = ? AND organization = ?",
                        (new_permissions, role, organization))
            
        elif action == "remove_permission":
            cursor.execute("SELECT permissions FROM roles WHERE name = ? AND organization = ?", (role, organization))
            permissions = cursor.fetchone()[0].split(',')
            if target in permissions:
                permissions.remove(target)
                updated_permissions = ','.join(permissions)
                cursor.execute("UPDATE roles SET permissions = ? WHERE name = ? AND organization = ?",
                               (updated_permissions, role, organization))
                

        elif action == "add_subject":
            # Verificar se já existe o registro na tabela
            cursor.execute("""
                SELECT 1 FROM role_subjects WHERE role_name = ? AND organization = ? AND subject_username = ?
            """, (role, organization, target))
            subject_exists = cursor.fetchone() is not None

            if subject_exists:
                return jsonify({"error": f"Subject '{target}' is already associated with role '{role}' in organization '{organization}'."}), 400

            if verify_username(target, organization):
                    cursor.execute("INSERT INTO role_subjects (role_name, organization, subject_username) VALUES (?, ?, ?)",
                            (role, organization, target))
            else:
                return jsonify({"error": f"Subject '{target}' not found."}), 404
                             
        elif action == "remove_subject":
            if verify_username(target, organization):
                cursor.execute("DELETE FROM role_subjects WHERE role_name = ? AND organization = ? AND subject_username = ?",
                    (role, organization, target))
            else:
                return jsonify({"error": f"Subject '{target}' not found."}), 404
        else:
            return jsonify({"error": "Invalid action."}), 400

        conn.commit()
        return jsonify({"message": f"Action '{action}' completed successfully for role '{role}'."}), 200

    except sqlite3.Error as e:
        conn.rollback()
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    finally:
        conn.close()

def verify_username(username, organization):
    # Buscar todos os usuários da organização
    conn = sqlite3.connect("sessions.db")
    cursor = conn.execute("""
        SELECT username FROM sessions WHERE organization = ?
    """, (organization,))
    all_users = [row[0] for row in cursor.fetchall()]
    conn.close()
    print("All users:", all_users)
    if all_users and username in all_users:
        return True
    return False




@app.route("/roles/<role>/subjects", methods=['GET'])
def rep_list_role_subjects(role):
    # Obter o session_id da query string
    data = request.get_json()
    session_id = request.json.get("session_id")
    nonce = request.json.get("nonce")
    iv = request.json.get("iv")
    mac = request.json.get("mac")

    app.logger.debug(f"Received session_id: {session_id}, role: {role}")

    if not session_id:
        return jsonify({"success": False, "message": "Missing session ID"}), 400
    
    # Verificar se o sujeito está suspenso
    suspended, message = verify_subject_status(session_id)
    if suspended:
        return jsonify({"success": False, "message": message}), 403


    try:
        # Validar a sessão e obter a organização
        conn = sqlite3.connect("sessions.db")
        cursor = conn.execute("""
            SELECT session_key, organization, hmac FROM sessions WHERE session_id = ?
        """, (session_id,))
        session_data = cursor.fetchone()
        conn.close()

        if not session_data:
            return jsonify({"success": False, "message": "Invalid session ID"}), 403

        session_key, organization, hmac = session_data

        session_key = base64.b64decode(session_key)

        # Desencriptar o nonce
        nonce = decrypt(base64.b64decode(nonce), session_key, iv)

        if not verify_nonce(nonce):
            return jsonify({"success": False, "message": "Invalid nonce"}), 403
        
        # Verificar o MAC
        if recalculatehmac_not_encrypt(data, hmac, mac):
            return jsonify({"success": False, "message": "Invalid MAC"}), 403

        # Consultar os sujeitos associados ao papel
        conn = sqlite3.connect("roles.db")
        cursor = conn.execute("""
            SELECT subject_username FROM role_subjects WHERE role_name = ? AND organization = ?
        """, (role, organization))
        subjects = [row[0] for row in cursor.fetchall()]
        conn.close()

        if not subjects:
            return jsonify({"success": True, "message": f"No subjects found for role '{role}'."}), 200

        return jsonify({"success": True, "subjects": subjects}), 200

    except sqlite3.Error as e:
        app.logger.error(f"Database error: {str(e)}")
        return jsonify({"success": False, "message": f"Database error: {str(e)}"}), 500




@app.route("/roles/<role>/permissions", methods=['GET'])
def rep_list_role_permissions(role):
    session_id = request.json.get("session_id")
    nonce = request.json.get("nonce")
    iv = request.json.get("iv")
    data = request.get_json()
    mac = data.get("mac")



    app.logger.debug(f"Received session_id: {session_id}, role: {role}")

    if not session_id:
        return jsonify({"success": False, "message": "Missing session ID"}), 400


    # Verificar se o sujeito está suspenso
    suspended, message = verify_subject_status(session_id)
    if suspended:
        return jsonify({"success": False, "message": message}), 403


    try:
        # Validar a sessão e obter a organização
        conn = sqlite3.connect("sessions.db")
        cursor = conn.execute("""
            SELECT session_key, organization, hmac FROM sessions WHERE session_id = ?
        """, (session_id,))
        session_data = cursor.fetchone()
        conn.close()

        if not session_data:
            return jsonify({"success": False, "message": "Invalid session ID"}), 403

        session_key, organization, hmac = session_data
        session_key = base64.b64decode(session_key)

        # Desencriptar o nonce
        nonce = decrypt(base64.b64decode(nonce), session_key, iv)
        if not verify_nonce(nonce):
            return jsonify({"success": False, "message": "Invalid nonce"}), 403
        
        # Verificar o MAC
        if recalculatehmac_not_encrypt(data, hmac, mac):
            return jsonify({"success": False, "message": "Invalid MAC"}), 403

        # Consultar as permissões associadas ao papel
        conn = sqlite3.connect("roles.db")
        cursor = conn.execute("""
            SELECT permissions FROM roles WHERE name = ? AND organization = ?
        """, (role, organization))
        permissions_row = cursor.fetchone()
        conn.close()

        if not permissions_row or not permissions_row[0]:
            return jsonify({"success": True, "message": f"No permissions found for role '{role}'."}), 200

        # Dividir as permissões em uma lista
        permissions = permissions_row[0].split(',')

        return jsonify({"success": True, "permissions": permissions}), 200

    except sqlite3.Error as e:
        app.logger.error(f"Database error: {str(e)}")
        return jsonify({"success": False, "message": f"Database error: {str(e)}"}), 500



@app.route("/subjects/<username>/roles", methods=['GET'])
def rep_list_subject_roles(username):
    data = request.get_json()
    session_id = request.json.get("session_id")
    nonce = request.json.get("nonce")
    iv = request.json.get("iv")
    mac = request.json.get("mac")

    app.logger.debug(f"Received session_id: {session_id}, username: {username}")

    if not session_id:
        return jsonify({"success": False, "message": "Missing session ID"}), 400


    # Verificar se o sujeito está suspenso
    suspended, message = verify_subject_status(session_id)
    if suspended:
        return jsonify({"success": False, "message": message}), 403


    try:
        # Validar a sessão e obter a organização
        conn = sqlite3.connect("sessions.db")
        cursor = conn.execute("""
            SELECT session_key, organization, hmac FROM sessions WHERE session_id = ?
        """, (session_id,))
        session_data = cursor.fetchone()
        conn.close()

        if not session_data:
            return jsonify({"success": False, "message": "Invalid session ID"}), 403

        session_key, organization, session_hmac = session_data
        session_key = base64.b64decode(session_key)

        # Desencriptar o nonce
        nonce = decrypt(base64.b64decode(nonce), session_key, iv)
        if not verify_nonce(nonce):
            return jsonify({"success": False, "message": "Invalid nonce"}), 403
        
        # Verificar o MAC
        if recalculatehmac_not_encrypt(data, session_hmac, mac):
            return jsonify({"success": False, "message": "Invalid MAC"}), 403

        # Consultar os papéis associados ao sujeito
        conn = sqlite3.connect("roles.db")
        cursor = conn.execute("""
            SELECT role_name FROM role_subjects WHERE subject_username = ? AND organization = ?
        """, (username, organization))
        roles = [row[0] for row in cursor.fetchall()]
        conn.close()

        if not roles:
            return jsonify({"success": True, "message": f"No roles found for subject '{username}'."}), 200

        return jsonify({"success": True, "roles": roles}), 200

    except sqlite3.Error as e:
        app.logger.error(f"Database error: {str(e)}")
        return jsonify({"success": False, "message": f"Database error: {str(e)}"}), 500



@app.route("/permissions/<permission>/roles", methods=['GET'])
def rep_list_permission_roles(permission):
    data = request.get_json()
    session_id = request.json.get("session_id")
    nonce = request.json.get("nonce")
    iv = request.json.get("iv")
    mac = request.json.get("mac")

    app.logger.debug(f"Received session_id: {session_id}, permission: {permission}")

    if not session_id:
        return jsonify({"success": False, "message": "Missing session ID"}), 400


    #session_id = request.args.get("session_id")
    # Verificar se o sujeito está suspenso
    suspended, message = verify_subject_status(session_id)
    if suspended:
        return jsonify({"success": False, "message": message}), 403


    try:
        # Validar a sessão e obter a organização
        conn = sqlite3.connect("sessions.db")
        cursor = conn.execute("""
            SELECT session_key, organization, hmac FROM sessions WHERE session_id = ?
        """, (session_id,))
        session_data = cursor.fetchone()
        conn.close()

        if not session_data:
            return jsonify({"success": False, "message": "Invalid session ID"}), 403

        session_key, organization, session_hmac = session_data
        session_key = base64.b64decode(session_key)

        # Desencriptar o nonce
        nonce = decrypt(base64.b64decode(nonce), session_key, iv)
        if not verify_nonce(nonce):
            return jsonify({"success": False, "message": "Invalid nonce"}), 403

        # Verificar o MAC
        if recalculatehmac_not_encrypt(data, session_hmac, mac):
            return jsonify({"success": False, "message": "Invalid MAC"}), 403

        # Consultar os papéis associados à permissão
        conn = sqlite3.connect("roles.db")
        cursor = conn.execute("""
            SELECT name FROM roles WHERE permissions LIKE ? AND organization = ?
        """, (f"%{permission}%", organization))
        roles = [row[0] for row in cursor.fetchall()]
        conn.close()

        if not roles:
            return jsonify({"success": True, "message": f"No roles found with permission '{permission}'."}), 200

        return jsonify({"success": True, "roles": roles}), 200

    except sqlite3.Error as e:
        app.logger.error(f"Database error: {str(e)}")
        return jsonify({"success": False, "message": f"Database error: {str(e)}"}), 500
    



@app.route('/role/suspend', methods=['POST'])
def suspend_role():
    """
    Suspende um papel (ROLE_DOWN).
    """
    data = request.json
    session_id = data.get("session_id")
    role = data.get("role")
    nonce = data.get("nonce")
    iv = data.get("iv")
    mac = data.get("mac")

    # Verificar se os campos necessários estão presentes
    if not session_id or not role:
        return jsonify({"error": "Role and session_id are required."}), 400
    
    # Verificar se o utilizador tem a permissão ROLE_DOWN
    has_perm, error_message = has_permission(session_id, "ROLE_DOWN")
    if not has_perm:
        return jsonify({"error": error_message}), 403

    # Validar sessão
    conn = sqlite3.connect("sessions.db")
    session = conn.execute("SELECT session_key, organization, hmac FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
    conn.close()
    
    if not session:
        return jsonify({"error": "Invalid session."}), 403

    session_key, organization, session_hmac = session
    print(f"Session valid for organization: {organization}")
    session_key = base64.b64decode(session_key)

    # Desencriptar o nonce
    nonce = decrypt(base64.b64decode(nonce), session_key, iv)
    if not verify_nonce(nonce):
        return jsonify({"error": "Invalid nonce."}), 403
    
    #Verificar MAC
    if recalculatehmac_not_encrypt(data, session_hmac, mac):
        return jsonify({"error": "Invalid MAC."}), 403

    # Verificar se o papel existe na organização
    conn = sqlite3.connect("roles.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM roles WHERE name = ? AND organization = ?", (role, organization))
    role_data = cursor.fetchone()

    if not role_data:
        return jsonify({"error": f"Role '{role}' not found in organization '{organization}'."}), 404

    # Alterar o status do papel para 'suspended'
    try:
        cursor.execute("UPDATE roles SET status = 'suspended' WHERE name = ? AND organization = ?", (role, organization))
        conn.commit()
        return jsonify({"message": f"Role '{role}' has been suspended successfully."}), 200
    except sqlite3.Error as e:
        conn.rollback()
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    finally:
        conn.close()

@app.route('/role/reactivate', methods=['POST'])
def reactivate_role():
    """
    Reativa um papel (ROLE_UP).
    """
    data = request.json
    session_id = data.get("session_id")
    role = data.get("role")
    nonce = data.get("nonce")
    iv = data.get("iv")
    mac = data.get("mac")

    # Verificar se os campos necessários estão presentes
    if not session_id or not role:
        return jsonify({"error": "Role and session_id are required."}), 400
    
    # Verificar se o utilizador tem a permissão ROLE_UP
    has_perm, error_message = has_permission(session_id, "ROLE_UP")
    if not has_perm:
        return jsonify({"error": error_message}), 403

    # Validar sessão
    conn = sqlite3.connect("sessions.db")
    session = conn.execute("SELECT session_key, organization, hmac FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
    conn.close()
    
    if not session:
        return jsonify({"error": "Invalid session."}), 403

    session_key, organization, session_hmac = session
    session_key = base64.b64decode(session_key)
    print(f"Session valid for organization: {organization}")

    # Desencriptar o nonce
    nonce = decrypt(base64.b64decode(nonce), session_key, iv)
    if not verify_nonce(nonce):
        return jsonify({"error": "Invalid nonce."}), 403
    
    #Verificar MAC
    if recalculatehmac_not_encrypt(data, session_hmac, mac):
        return jsonify({"error": "Invalid MAC."}), 403

    # Verificar se o papel existe na organização
    conn = sqlite3.connect("roles.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM roles WHERE name = ? AND organization = ?", (role, organization))
    role_data = cursor.fetchone()

    if not role_data:
        return jsonify({"error": f"Role '{role}' not found in organization '{organization}'."}), 404

    # Alterar o status do papel para 'active'
    try:
        cursor.execute("UPDATE roles SET status = 'active' WHERE name = ? AND organization = ?", (role, organization))
        conn.commit()
        return jsonify({"message": f"Role '{role}' has been reactivated successfully."}), 200
    except sqlite3.Error as e:
        conn.rollback()
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    finally:
        conn.close()

@app.route('/document/acl', methods=['POST'])
def acl_doc():

    data = request.json
    session_id = data.get("session_id")
    document_name = data.get("document_name")
    action = data.get("action")
    role = data.get("role")
    permission = data.get("permission")
    nonce = data.get("nonce")
    iv = data.get("iv")
    mac = data.get("mac")

    
    if not all([session_id, document_name, action, role, permission]):
        return jsonify({"error": "Missing required fields."}), 400
    
    if action not in ["+", "-"]:
        return jsonify({"error": "Invalid action."}), 400


    # Validar a sessão e obter a organização
    conn = sqlite3.connect("sessions.db")
    cursor = conn.execute("""
        SELECT session_key, organization, username, roles, hmac FROM sessions WHERE session_id = ?
    """, (session_id,))
    session_data = cursor.fetchone()
    conn.close()

    if not session_data:
        return jsonify({"success": False, "message": "Invalid session ID"}), 403

    session_key, organization, username, roles, session_hmac = session_data
    session_key = base64.b64decode(session_key)


    # Desencriptar o nonce
    nonce = decrypt(base64.b64decode(nonce), session_key, iv)
    if not verify_nonce(nonce):
        return jsonify({"success": False, "message": "Invalid nonce"}), 403
    
    # Verifica MAC
    if recalculatehmac_not_encrypt(data, session_hmac, mac):
        return jsonify({"success": False, "message": "Invalid MAC"}), 403


    conn = sqlite3.connect("documents.db")
    cursor = conn.execute("""
        SELECT document_handle, name, create_date, creator, file_handle, acl, alg, key, iv
        FROM documents
        WHERE name = ?
    """, (document_name,))
    document = cursor.fetchone()
    conn.close()

    if not document:
        return jsonify({"success": False, "message": "Document not found"}), 404


    acl = json.loads(document[5])  # Carregar o ACL



    user_roles = roles.split(",")


    has_doc_acl_permission = False

    for _role in user_roles:
        if _role in acl and "DOC_ACL" in acl[_role]:
            has_doc_acl_permission = True
            break


    if not has_doc_acl_permission:
        return jsonify({"success": False, "message": "Access denied: DOC_ACL required"}), 403


    conn = sqlite3.connect("documents.db")
    cursor = conn.execute("""
        SELECT acl FROM documents WHERE name = ? AND organization = ?
    """, (document_name, organization))
    document = cursor.fetchone()

    if not document:
        conn.close()
        return jsonify({"success": False, "message": f"Document '{document_name}' not found in organization '{organization}'."}), 404


    acl = json.loads(document[0]) if document[0] else {}

    print(role)
    if action == "+":
        if role not in acl:
            acl[role] = []
        if permission not in acl[role]:
            acl[role].append(permission)
    elif action == "-":
        #Não permitir que remova o ultimo DOC_ACL
        list = acl.values()
        print(list)
        if permission == "DOC_ACL":
            flag = 0
            for lst in list:
                for a in lst:
                    print(a)
                    if a == "DOC_ACL":
                        flag += 1
            if flag <= 1:
                return jsonify({"success": False, "message": "NO ACL LAST"}), 407
              
        if role in acl and permission in acl[role]:
            acl[role].remove(permission)
            if not acl[role]:  # Remove o papel se não tiver permissões restantes
                del acl[role]

    # Atualizar o ACL no metadata
    cursor.execute("""
        UPDATE documents SET acl = ? WHERE name = ? AND organization = ?
    """, (json.dumps(acl), document_name, organization))
    conn.commit()
    conn.close()

    conn = sqlite3.connect("roles.db")
    cursor = conn.execute("""
        SELECT permissions FROM roles WHERE name = ? AND organization = ?
    """, (role, organization))
    role_data = cursor.fetchone()

    if not role_data:
        conn.close()
        return jsonify({"success": False, "message": f"Role '{role}' not found in organization '{organization}'."}), 404

    permissions = role_data[0].split(",") if role_data[0] else []

    if action == "+" and permission not in permissions:
        permissions.append(permission)
    elif action == "-" and permission in permissions:
        permissions.remove(permission)

    cursor.execute("""
        UPDATE roles SET permissions = ? WHERE name = ? AND organization = ?
    """, (",".join(permissions), role, organization))
    conn.commit()
    conn.close()



    return jsonify({"success": True, "message": f"Permission '{permission}' {action}ed for role '{role}' on document '{document_name}'."}), 200



if __name__ == "__main__":
    if not os.path.exists("server_private_key.pem"):
        generate_keys()

   
    load_server_private_key()
    init_db()
    app.run(debug=True, port=5000, host="127.0.0.1")
    