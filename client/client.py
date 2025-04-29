import os
import sys
import argparse
import logging
import json
import requests
from datetime import datetime, timezone
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import hmac

import base64
import uuid
from datetime import timedelta
import random
import time


logging.basicConfig(format='%(levelname)s\t- %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.DEBUG) 
logger.setLevel(logging.INFO)

def load_state():
    state = {}
    state_dir = os.path.join(os.path.expanduser('~'), '.sio')
    state_file = os.path.join(state_dir, 'state.json')

    logger.debug('State folder: ' + state_dir)
    logger.debug('State file: ' + state_file)

    if os.path.exists(state_file):
        logger.debug('Loading state')
        with open(state_file,'r') as f:
            state = json.loads(f.read())

    if state is None:
        state = {}

    return state


def parse_env(state):
    if 'REP_ADDRESS' in os.environ:
        state['REP_ADDRESS'] = os.getenv('REP_ADDRESS')
        logger.debug('Setting REP_ADDRESS from environment: ' + state['REP_ADDRESS'])
    
    if 'REP_PUB_KEY' in os.environ:
        rep_pub_key = os.getenv('REP_PUB_KEY')
        logger.debug('Loading REP_PUB_KEY fron: ' + state['REP_PUB_KEY'])
        if os.path.exists(rep_pub_key):
            with open(rep_pub_key, 'r') as f:
                state['REP_PUB_KEY'] = f.read()
                logger.debug('Loaded REP_PUB_KEY from Environment')
    return state



def parse_args(state):
    parser = argparse.ArgumentParser()

    parser.add_argument("-k", '--key', nargs=1, help="Path to the key file")
    parser.add_argument("-r", '--repo', nargs=1, help="Address:Port of the repository")
    parser.add_argument("-v", '--verbose', help="Increase verbosity", action="store_true")
    parser.add_argument("-c", "--command", help="Command to execute")
    parser.add_argument('-s', '--string', type=str, help='String argument')
    #parser.add_argument('-d', '--date', type=str, help='Date argument')
    parser.add_argument('-d', '--date', nargs=2, help='Date filter type and date (in DD-MM-YYYY)')
    parser.add_argument('arg0', nargs='?', default=None)
    parser.add_argument('arg1', nargs='?', default=None)
    parser.add_argument('arg2', nargs='?', default=None)
    parser.add_argument('arg3', nargs='?', default=None)
    parser.add_argument('arg4', nargs='?', default=None)
    parser.add_argument('arg5', nargs='?', default=None)


    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.info('Setting log level to DEBUG')

    if args.key:
        key_file = args.key[0]
        if not os.path.exists(key_file) or not os.path.isfile(key_file):
            logger.error(f"Key file not found or invalid: {key_file}")
            sys.exit(-1)

        with open(key_file, 'r') as f:
            state['REP_PUB_KEY'] = f.read()
            logger.info('Overriding REP_PUB_KEY from command line')
            

    if args.repo:
        state['REP_ADDRESS'] = args.repo[0]
        logger.info('Overriding REP_ADDRESS from command line')

    
    if args.command:
        logger.info("Command: " + args.command)



    date_filter = None
    if args.date:
        date_filter_type, date_str = args.date
        try:
            datetime.strptime(date_str, "%d-%m-%Y")
        except ValueError:
            logger.error("Invalid date format. Expected DD-MM-YYYY.")
            sys.exit(1)
        date_filter = f"{date_filter_type} {date_str}"

    return state, {'command': args.command,'arg0': args.arg0, 'arg1': args.arg1, 'arg2': args.arg2, 'arg3': args.arg3, 'arg4': args.arg4, 'arg5': args.arg5,'string': args.string,'date': date_filter}



def save(state):
    """Salva o estado no arquivo de configuração."""
    state_dir = os.path.join(os.path.expanduser('~'), '.sio')
    state_file = os.path.join(state_dir, 'state.json')

    if not os.path.exists(state_dir):
        logger.debug('Creating state folder: ' + state_dir)
        os.mkdir(state_dir)

    with open(state_file, 'w') as f:
        json.dump(state, f, indent=4)


state = load_state()
state = parse_env(state)
state, args = parse_args(state)
save(state)

if 'REP_ADDRESS' not in state:
    logger.error("Must define Repository Address")
    sys.exit(-1)


if 'REP_PUB_KEY' not in state:
  logger.error("Must set the Repository Public Key")
  sys.exit(-1)
  
""" Do something """
logger.debug("Arguments: " + str(args))




def rep_subject_credentials(password, credentials_file):
    print(f"Generating RSA credentials and saving to {credentials_file}")
    logger.info(f"Generating RSA credentials and saving to {credentials_file}")

    if not password or not credentials_file:
        logger.error("Missing required arguments for rep_subject_credentials.")
        sys.exit(1)

    try:
        if not credentials_file.endswith(".pem"):
            credentials_file += ".pem"

        credentials_dir = "credentials"
        os.makedirs(credentials_dir, exist_ok=True)
        credentials_path = os.path.join(credentials_dir, credentials_file)

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(credentials_path, "wb") as pem_file:
            pem_file.write(private_key_pem)
            pem_file.write(b"\n")
            pem_file.write(public_key_pem)

        logger.info(f"RSA credentials successfully saved to {credentials_path}")
        print(f"RSA credentials successfully saved to {credentials_path}")
        sys.exit(0)

    except Exception as e:
        logger.error(f"An error occurred while generating credentials: {e}")
        print(f"Error: {e}")
        sys.exit(1)



def rep_create_org(org, username, name, email, credentials_file):
    print(f"rep_create_org: org={org}, username={username}, name={name}, email={email}, credentials_file={credentials_file}")
    logger.info(f"Creating organization: {org}")

    credentials_path = os.path.join("credentials", credentials_file)

    if not os.path.exists(credentials_path):
        logger.error(f"Credentials file '{credentials_path}' not found.")
        sys.exit(1)

    if not org or not username or not name or not email or not credentials_file:
        logger.error("Missing required arguments for rep_create_org.")
        print("Command: rep_create_org <org> <username> <name> <email> <credentials_file>")
        sys.exit(1)

    with open(credentials_path, "rb") as f:
        pem_data = f.read()

    if b"-----BEGIN PUBLIC KEY-----" in pem_data:
        public_key_pem = pem_data.split(b"-----BEGIN PUBLIC KEY-----")[1]
        public_key_pem = b"-----BEGIN PUBLIC KEY-----" + public_key_pem.split(b"-----END PUBLIC KEY-----")[0] + b"-----END PUBLIC KEY-----"
    else:
        raise ValueError("Public key not found in credentials file.")


    url = f"http://{state['REP_ADDRESS']}/organization/create"
    data = {
        "org_name": org,
        "username": username,
        "full_name": name,
        "email": email,
        "public_key": public_key_pem.decode() 
    }


    key = os.urandom(32)  # Chave AES-256 (32 bytes)
    iv = os.urandom(16)   # VI (16 bytes)

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    data_json = json.dumps(data).encode()
    encrypted_data = encryptor.update(data_json) + encryptor.finalize()

    #encriptar a key simetrica com a chave publica do rep
    public_key = serialization.load_pem_public_key(
        state['REP_PUB_KEY'].encode(),
        backend=default_backend()
    )

    encrypted_key = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )



    data = {
        "data": base64.b64encode(encrypted_data).decode(),
        "key": base64.b64encode(encrypted_key).decode(),
        "iv": base64.b64encode(iv).decode()
    }


    response = requests.post(url, json=data)
    if response.status_code == 200:
        logger.info("Organization created successfully!")
        sys.exit(0)
    else:
        logger.error(f"Failed to create organization: {response.status_code} - {response.text}")
        sys.exit(-1)


def rep_list_orgs():

    logger.info("Listing organizations...")
    url = f"http://{state['REP_ADDRESS']}/organization/list"

    response = requests.get(url)
    if response.status_code == 200:
        orgs = response.json()
        print("\n") 
        if orgs:
            print("\nOrganizations List:")
            print("="*30)
            for i, org in enumerate(orgs, start=1):
                print(f"{i}. {org}")
            print("="*30)
            logger.info("Organizations retrieved successfully.")
            sys.exit(0)
        else:
            print("No organizations found.")
            logger.info("No organizations found.")
            sys.exit(-1)

    else:
        logger.error(f"Failed to list organizations: {response.status_code} - {response.text}")
        sys.exit(-1)


def generate_nonce():
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")  # Tempo UTC
    random_bytes = os.urandom(8).hex()  # 8 bytes aleatórios
    unique_id = str(uuid.uuid4())  # UUID único
    return f"{timestamp}/{unique_id}/{random_bytes}"



def rep_create_session(org, username, password, credentials_file, session_file):
    print("rep_create_session: org=%s, username=%s, password=%s, credentials_file=%s, session_file=%s" % (org, username, password, credentials_file, session_file))
  
    logger.info(f"Creating session for organization: {org}, username: {username}, password: {password}, credentials_file: {credentials_file}, session_file: {session_file}")

    if not org or not username or not password or not credentials_file or not session_file:
        logger.error("Missing required arguments for rep_create_session.")
        print("Command: rep_create_session <org> <username> <password> <credentials_file> <session_file>")
        sys.exit(1)

    credentials_dir = "credentials"
    credentials_path = os.path.join(credentials_dir, credentials_file)


    with open(credentials_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
                f.read(),
                password=password.encode(),
                backend=default_backend()
        )

    url = f"http://{state['REP_ADDRESS']}/session/create"
    data = {
        "organization": org,
        "username": username,
        "password": password,
        "credentials_file": credentials_file,
        "session_file": session_file
    }


    response = requests.post(url, json=data)
    if response.status_code == 200:
        logger.info("Session created successfully!")
        session_data = response.json()

        try:
            encrypted_session_key = base64.b64decode(session_data["session_key"])  # decodifica a chave simétrica criptografada
            session_key = private_key.decrypt(
                encrypted_session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except ValueError as e:
            logger.error(f"Decryption failed: {e}")
            sys.exit(-1)


        session_file_data = {
                "session_id": session_data["session_id"],
                "hmac": session_data["hmac"],
                "organization": org,
                "username": username,
                "session_key": base64.b64encode(session_key).decode()  # guarda a chave descriptografada
        }

        session_dir = "sessions"
        os.makedirs(session_dir, exist_ok=True)
        session_file_path = os.path.join(session_dir, session_file)

        with open(session_file_path, "w") as f:
            json.dump(session_file_data, f, indent=4)

        logger.info(f"Session context saved to file: {session_file}")
        sys.exit(0)

    else:
        logger.error(f"Failed to create session: {response.status_code} - {response.text}")
        sys.exit(-1)



def rep_add_subject(session_file, username, name, email, pubkey):
    print("rep_create_session: session_file=%s, username=%s, name=%s, email=%s, pubkey=%s" % (session_file, username, name, email, pubkey))
    logger.info(f"Adding subject: {session_file}, username: {username},name: {name}, email: {email}, pubkey: {pubkey}")

    credentials_path = os.path.join("credentials", pubkey)

    if not os.path.exists(credentials_path):
        logger.error(f"Credentials file '{credentials_path}' not found.")
        sys.exit(1)
        

    if not session_file or not username or not name or not email or not pubkey:
        logger.error("Missing required arguments for rep_add_subject.")
        print("Command: rep_add_subject <session_file> <username> <name> <email> <pubkey>")
        sys.exit(1)



    session_dir = "sessions"
    session_file_path = os.path.join(session_dir, session_file)
    if not os.path.exists(session_file_path):
        logger.error(f"Session file '{session_file}' not found.")
        sys.exit(1)
    with open(session_file_path, "r") as sf:
        session_data = json.load(sf)
        session_id = session_data.get("session_id")
        session_hmac = session_data.get("hmac").encode()
        if not session_id:
            logger.error("session_id not found in session file.")
            sys.exit(1)


    with open(credentials_path, "rb") as f:
        pem_data = f.read()

    if b"-----BEGIN PUBLIC KEY-----" in pem_data:
        public_key_pem = pem_data.split(b"-----BEGIN PUBLIC KEY-----")[1]
        public_key_pem = b"-----BEGIN PUBLIC KEY-----" + public_key_pem.split(b"-----END PUBLIC KEY-----")[0] + b"-----END PUBLIC KEY-----"
    else:
        raise ValueError("Public key not found in credentials file.")
    
    public_key_pem_str = public_key_pem.decode('utf-8')


    url = f"http://{state['REP_ADDRESS']}/subject/add"


    sensitive_data = {
        "username": username,
        "name": name,
        "email": email,
        "credentials_file": public_key_pem_str,
        "nonce" : generate_nonce()
    }

    # Criptografar os dados sensíveis com AES
    key = os.urandom(32)  # Chave AES-256 (32 bytes)
    iv = os.urandom(16)   # Vetor de Inicialização (16 bytes)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    sensitive_data_encrypted = encryptor.update(json.dumps(sensitive_data).encode()) + encryptor.finalize()

    # Criptografar a chave AES com a chave pública do servidor
    server_public_key = serialization.load_pem_public_key(state['REP_PUB_KEY'].encode(), backend=default_backend())
    encrypted_key = server_public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    mac = hmac.new(session_hmac, sensitive_data_encrypted, hashlib.sha256).hexdigest()


    subject_data = {
        "session_id": session_id,
        "encrypted_sensitive_data": base64.b64encode(sensitive_data_encrypted).decode(),
        "encrypted_aes_key": base64.b64encode(encrypted_key).decode(),
        "iv": iv.hex(),
        "mac": mac
    }


    response = requests.post(url, json=subject_data)
    if response.status_code == 200:
        logger.info(f"Subject {username} added successfully.")
        sys.exit(0)
    else:
        logger.error(f"Failed to add subject: {response.status_code} - {response.text}")
        sys.exit(-1)


logging.basicConfig(format='%(levelname)s\t- %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

logging.basicConfig(format='%(levelname)s\t- %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


def generate_mac_not_encrypt(session_hmac, params):
    serialization_params = json.dumps(params).encode()
    return hmac.new(session_hmac, serialization_params, hashlib.sha256).hexdigest()


def rep_list_subjects(session_file, username):
    print("rep_list_subjects: session_file=%s, username=%s" % (session_file, username))
    logger.info("Listing organizations...")

    session_dir = "sessions"
    session_file_path = os.path.join(session_dir, session_file)
    if not os.path.exists(session_file_path):
        logger.error(f"Session file '{session_file}' not found.")
        sys.exit(1)
    with open(session_file_path, "r") as sf:
        session_data = json.load(sf)
        session_id = session_data.get("session_id")
        session_key = base64.b64decode(session_data.get("session_key"))
        session_hmac = session_data.get("hmac").encode()
        if not session_id or not session_key:
            logger.error("session_id not found in session file.")
            sys.exit(1)

    
    # Encryptar nonce 
    iv = os.urandom(16)  # Gerar um vetor de inicialização
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_nonce = encryptor.update(generate_nonce().encode()) + encryptor.finalize()
    
    params = {"session_id": session_id,
              "nonce": base64.b64encode(encrypted_nonce).decode(),
              "iv": iv.hex()
              }
    
   
    mac = generate_mac_not_encrypt(session_hmac, params)
    params["mac"] = mac
    
    if username:
        params["username"] = username

    url = f"http://{state['REP_ADDRESS']}/subjects/list"
    response = requests.get(url, json=params)

    if response.status_code == 200:
        response_data = response.json()

        encrypted_data = base64.b64decode(response_data["encrypted_data"])
        iv = base64.b64decode(response_data["iv"])

        # Desencriptar os dados retornados com a chave simétrica e o IV
        cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        subjects = json.loads(decrypted_data)

        if username:
            if subjects:  #se existir
                logger.info(f"User: {subjects['username']}, Status: {subjects['status']}")   
                sys.exit(0)                                                     
            else:                                                                                                                                     
                logger.info(f"User {username} not found.")
                sys.exit(-1)
        else:
            if subjects:
                logger.info("\nSubjects retrieved successfully:\n")
                logger.info(f"{'Username':<20} {'Status':<10}")
                logger.info(f"{'-'*20} {'-'*10}")
                
                for subject in subjects:
                    logger.info(f"{subject['username']:<20} {subject['status']:<10}")
                sys.exit(0)
        
            else:
                logger.info("No subjects found.")
                sys.exit(-1)
    else:
        logger.error(f"Failed to list subjects: {response.status_code} - {response.text}")
        sys.exit(-1)
    

def rep_suspend_subject(session_file, username):
    print(f"Suspending subject: {username} using session: {session_file}")
    logger.info(f"Suspending subject: {username} with session: {session_file}")

    # Obter session_key a partir do session_file
    session_dir = "sessions"
    session_file_path = os.path.join(session_dir, session_file)
    if not os.path.exists(session_file_path):
        logger.error(f"Session file '{session_file}' not found.")
        sys.exit(1)
    with open(session_file_path, "r") as sf:
        session_data = json.load(sf)
        session_key = base64.b64decode(session_data.get("session_key")) 
        session_hmac = session_data.get("hmac").encode()
        if not session_key:
            logger.error("Session key not found in session file.")
            sys.exit(1)

    iv = os.urandom(16)  # Gerar um vetor de inicialização
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_username = encryptor.update(username.encode()) + encryptor.finalize()

    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_nonce = encryptor.update(generate_nonce().encode()) + encryptor.finalize()

    url = f"http://{state['REP_ADDRESS']}/subject/suspend"
    data = {
        "session_id": session_data.get("session_id"),
        "encrypted_username": base64.b64encode(encrypted_username).decode(),
        "encrypted_nonce": base64.b64encode(encrypted_nonce).decode(),
        "iv": iv.hex()
    }


    mac = generate_mac_not_encrypt(session_hmac, data)
    data["mac"] = mac

    response = requests.post(url, json=data)
    
    # Tratamento da resposta
    if response.status_code == 200:
        logger.info(f"Subject '{username}' suspended successfully.")
        print(response.json().get("message"))
        sys.exit(0)
    elif response.status_code == 400 and "already suspended" in response.text.lower():
        logger.warning(f"Subject '{username}' is already suspended.")
        print(f"Subject '{username}' is already suspended.")
        sys.exit(-1)
    elif response.status_code == 403:
        logger.error("Invalid MAC")
        sys.exit(-1)
    elif response.status_code == 404:
        logger.error("Subject not found")
        sys.exit(-1)
    elif response.status_code == 405:
        logger.error("Permission Denied")
        sys.exit(-1)
    else:
        logger.error(f"Failed to suspend subject: {response.status_code} - {response.text}")
        print(f"Error: {response.json().get('error', 'Unknown error occurred')}")
        sys.exit(-1)




# status = activate
def rep_activate_subject(session_file, username):
    print(f"Activating subject: {username} using session: {session_file}")
    logger.info(f"Activating subject: {username} with session: {session_file}")

    # Obter session_key a partir do session_file
    session_dir = "sessions"
    session_file_path = os.path.join(session_dir, session_file)
    with open(session_file_path, "r") as sf:
        session_data = json.load(sf)
        session_key = base64.b64decode(session_data.get("session_key"))
        session_hmac = session_data.get("hmac").encode() 
        if not session_key:
            logger.error("Session key not found in session file.")
            sys.exit(1)

    iv = os.urandom(16)  # Gerar um vetor de inicialização
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_username = encryptor.update(username.encode()) + encryptor.finalize()

    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_nonce = encryptor.update(generate_nonce().encode()) + encryptor.finalize()

    url = f"http://{state['REP_ADDRESS']}/subject/activate"
    data = {
        "session_id": session_data.get("session_id"),
        "encrypted_username": base64.b64encode(encrypted_username).decode(),
        "iv": iv.hex(),
        "encrypted_nonce": base64.b64encode(encrypted_nonce).decode()
    }

    mac = generate_mac_not_encrypt(session_hmac, data)
    data["mac"] = mac

    response = requests.post(url, json=data)

    # Tratamento da resposta
    if response.status_code == 200:
        logger.info(f"Subject '{username}' activated successfully.")
        print(response.json().get("message"))
        sys.exit(0)
    elif response.status_code == 400 and "already active" in response.text.lower():
        logger.warning(f"Subject '{username}' is already active.")
        print(f"Subject '{username}' is already active.")
        sys.exit(-1)
    else:
        logger.error(f"Failed to activate subject: {response.status_code} - {response.text}")
        print(f"Error: {response.json().get('error', 'Unknown error occurred')}")
        sys.exit(-1)



def encrypt_document(content, key, iv):
    """Encripta o conteúdo com AES-256-CFB."""
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_content = content.encode()  
    return encryptor.update(padded_content) + encryptor.finalize()



def rep_add_doc(session_file, document_name, file_path):
    logger.info(f"Adding document: session_file={session_file}, document_name={document_name}, file_path={file_path}")


    # Carregar o session_id a partir do session_file
    session_dir = "sessions"
    session_file_path = os.path.join(session_dir, session_file)
    if not os.path.exists(session_file_path):
        logger.error(f"Session file '{session_file}' not found.")
        sys.exit(1)
    with open(session_file_path, "r") as sf:
        session_data = json.load(sf)
        session_id = session_data.get("session_id")
        session_hmac = session_data.get("hmac").encode()
        if not session_id:
            logger.error("session_id not found in session file.")
            sys.exit(1)


    if not os.path.exists(file_path):
        logger.error(f"File {file_path} not found.")
        sys.exit(1)
 

    

    with open(file_path, "r") as f:
        document_content = f.read()

    # Calcular o hash do conteúdo
    file_handle = hashlib.md5(document_content.encode()).hexdigest()

    # Criptografar o conteúdo do documento com AES
    key = os.urandom(32)  # Chave AES-256 (32 bytes)
    iv = os.urandom(16)   # Vetor de Inicialização (16 bytes)
    encrypted_content = encrypt_document(document_content, key, iv)

    # Criar sensitive_data com todos os dados sensíveis
    sensitive_data = {
        "document_name": document_name,
        "document_content": encrypted_content.hex(),
        "file_digest": file_handle,
        "acl": "permissões",
        "alg": "AES-256-CFB",
        "iv": iv.hex(),
        "key": key.hex(),
        "nonce": generate_nonce()
    }

    # Criptografar os dados sensíveis com AES
    aes_key = os.urandom(32)
    aes_cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    aes_encryptor = aes_cipher.encryptor()
    sensitive_data_encrypted = aes_encryptor.update(json.dumps(sensitive_data).encode()) + aes_encryptor.finalize()

    # Carregar a chave pública do servidor
    server_public_key = serialization.load_pem_public_key(
        state['REP_PUB_KEY'].encode(),
        backend=default_backend()
    )

    # Criptografar a chave AES com RSA
    encrypted_aes_key = server_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )   


    mac = hmac.new(session_hmac, sensitive_data_encrypted, hashlib.sha256).hexdigest()

    # Preparar os dados para envio
    data = {
        "session_id": session_id,
        "encrypted_sensitive_data": base64.b64encode(sensitive_data_encrypted).decode(),
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode(),
        "iv": iv.hex(),
        "mac": mac
    }

    url = f"http://127.0.0.1:5000/document/add"
    response = requests.post(url, json=data)

    # Verificar a resposta do servidor
    if response.status_code == 200:
        logger.info(f"Document {document_name} added successfully.")
        sys.exit(0)
    elif response.status_code == 403:
        logger.error("Permission denied: DOC_NEW required")
        sys.exit(-1)
    elif response.status_code == 408:
        logger.error("No roles assigned to user")
        sys.exit(-1)
    elif response.status_code == 420:
        logger.error("Invalid HMAC")
        sys.exit(-1)
    elif response.status_code == 405:
        logger.error("Invalid file path. Access to the directory is not allowed")
        sys.exit(-1)
    else:
        logger.error(f"Failed to add document: {response.status_code} - {response.text}")
        sys.exit(-1)



def rep_list_docs(session_file, username=None, date_filter = None):
    """Lista os documentos disponíveis na organização para o usuário da sessão."""

    logger.info(f"Listing documents: session_file={session_file}, username={username}, date_filter={date_filter}")

    session_dir = "sessions"
    session_file_path = os.path.join(session_dir, session_file)
    with open(session_file_path, "r") as sf:
        session_data = json.load(sf)
        session_id = session_data.get("session_id")
        session_key = base64.b64decode(session_data.get("session_key"))
        session_hmac = session_data.get("hmac").encode()
        if not session_id:
            logger.error("session_id not found in session file.")
            sys.exit(1)

    # Encrypt nonce
    iv = os.urandom(16)  # Gerar um vetor de inicialização
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_nonce = encryptor.update(generate_nonce().encode()) + encryptor.finalize()

    url = f"http://127.0.0.1:5000/document/list"
    params = {"session_id": session_id,
              "nonce": base64.b64encode(encrypted_nonce).decode(),
              "iv": iv.hex()
            }
    
    mac = hmac.new(session_hmac, json.dumps(params).encode(), hashlib.sha256).hexdigest()
    params["mac"] = mac

    
    if username:
        params["username"] = username  
    if date_filter:
        params["date_filter"] = date_filter
    

    response = requests.post(url, json=params)
    if response.status_code == 200:
        response_data = response.json()
        if response_data["success"]:
            documents = response_data.get("documents", [])
            if documents:
                logger.info("\nDocuments retrieved successfully:\n")
                for idx, doc in enumerate(documents, start=1):
                    logger.info(f"Document {idx}:")
                    logger.info(f"{'-'*20}")
                    logger.info(f"Document Handle : {doc['document_handle']}")
                    logger.info(f"Name            : {doc['name']}")
                    logger.info(f"Create Date     : {doc['create_date']}")
                    logger.info(f"Creator         : {doc['creator']}")
                    logger.info(f"File Handle     : {doc['file_handle']}")
                    logger.info(f"ACL             : {doc['acl']}")
                    logger.info(f"Deleter         : {doc['deleter']}")
                    logger.info(f"{'-'*20}\n")
                sys.exit(0)

            else:
                logger.info("No documents found.")
                sys.exit(0)
        else:
            logger.error(f"Failed to retrieve documents: {response_data.get('message', 'Unknown error')}")
            sys.exit(-1)
    else:
        logger.error(f"Failed to list documents: {response.status_code} - {response.text}")
        sys.exit(-1)



def rep_delete_doc(session_file, document_name):
    """Apaga o documento de uma organização via comando rep_delete_doc."""
    logger.info(f"Deleting document: session_file={session_file}, document_name={document_name}")

    # Carregar o session_id do session_file
    session_dir = "sessions"
    session_file_path = os.path.join(session_dir, session_file)
    if not os.path.exists(session_file_path):
        logger.error(f"Session file '{session_file}' not found.")
        sys.exit(1)
    with open(session_file_path, "r") as sf:
        session_data = json.load(sf)
        session_id = session_data.get("session_id")
        session_key = base64.b64decode(session_data.get("session_key"))
        session_hmac = session_data.get("hmac").encode()
        if not session_id or not session_key:
            logger.error("Session ID not found in session file.")
            sys.exit(1)


    sensitive_data = {
        "document":document_name,
        "nonce": generate_nonce()
    }

    iv = os.urandom(16)  # Gerar um novo IV
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(json.dumps(sensitive_data).encode()) + encryptor.finalize()


    mac = hmac.new(session_hmac, encrypted_data, hashlib.sha256).hexdigest()



    url = f"http://127.0.0.1:5000/document/delete"
    data = {
        "session_id": session_id,
        "document_name": document_name, 
        "encrypted_data": base64.b64encode(encrypted_data).decode(),
        "iv": iv.hex(),
        "mac": mac
    }

    response = requests.post(url, json=data)
    if response.status_code == 200:
        file_handle = response.json().get("file_handle")
        key = response.json().get("key")
        alg = response.json().get("alg")
        logger.info(f"Document '{document_name}' deleted successfully.")
        logger.info(f"Details - File Handle: {file_handle}, Key: {key}, Algorithm: {alg}")
        return file_handle
    elif response.status_code == 403:
        logger.error("Permission denied: DOC_DELETE required.")
        sys.exit(-1)
    elif response.status_code == 404:
        logger.error(f"Document '{document_name}' not found.")
        sys.exit(1)
    else:
        logger.error(f"Failed to delete document: {response.status_code} - {response.text}")
        sys.exit(-1)




def rep_get_doc_metadata(session_file, document_name):
    """Obtém os metadados de um documento."""
    logger.info(f"Fetching metadata for document: session_file={session_file}, document_name={document_name}")

        # Carregar o session_id do session_file
    session_dir = "sessions"
    session_file_path = os.path.join(session_dir, session_file)
    if not os.path.exists(session_file_path):
        logger.error(f"Session file '{session_file}' not found.")
        sys.exit(1)
        
    with open(session_file_path, "r") as sf:
        session_data = json.load(sf)
        session_id = session_data.get("session_id")
        session_key = base64.b64decode(session_data.get("session_key"))
        session_hmac = session_data.get("hmac").encode()
        if not session_id or not session_key:
            logger.error("Session ID not found in session file.")
            sys.exit(1)

    iv = os.urandom(16) 
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    nonce = generate_nonce()
    encrypted_nonce = encryptor.update(nonce.encode()) + encryptor.finalize()

    url = f"http://127.0.0.1:5000/document/metadata"
    data = {
        "session_id": session_id,
        "document_name": document_name,
        "nonce": base64.b64encode(encrypted_nonce).decode(),
        "iv": iv.hex()
    }

    mac = hmac.new(session_hmac, json.dumps(data).encode(), hashlib.sha256).hexdigest()
    data["mac"] = mac

    response = requests.post(url, json=data)
    if response.status_code == 200:
        encrypt_metadata = response.json()
        encrypted_metadata_bytes = base64.b64decode(encrypt_metadata["encrypted_metadata"])

        iv = bytes.fromhex(encrypt_metadata["iv"])
        cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_metadata_bytes = decryptor.update(encrypted_metadata_bytes) + decryptor.finalize()

        metadata = json.loads(decrypted_metadata_bytes)
        logger.info(f"Metadata retrieved successfully: {json.dumps(metadata, indent=4)}")

        # Atualizar o estado com os metadados mais recentes
        if "documents" not in state:
            state["documents"] = {}
        state["documents"][document_name] = metadata
        state["last_metadata"] = metadata
        logger.debug("State updated with the latest metadata.")
        save(state)
        logger.info(f"Metadata for document '{document_name}' saved to state.")
        return metadata
        
    else:
        logger.error(f"Failed to fetch metadata: {response.status_code} - {response.text}")
        sys.exit(-1)
        return None


def rep_get_file(file_handle, output_file=None):
    """Baixa um arquivo pelo file_handle e grava no arquivo ou exibe no stdout."""
    logger.info(f"Downloading file: file_handle={file_handle}, output_file={output_file}")

  
    url = f"http://{state['REP_ADDRESS']}/file/get"
    data = {"file_handle": file_handle}

    response = requests.post(url, json=data)

    if response.status_code == 200:
        file_content = response.content

        if output_file:

            with open(output_file, "wb") as f:
                f.write(file_content)
            logger.info(f"File downloaded and saved to {output_file}")
            sys.exit(0)
        else:

            sys.stdout.buffer.write(file_content)
            print("\n")
    elif response.status_code == 404:
        logger.error(f"File with handle '{file_handle}' not found.")
        sys.exit(-1)
    else:
        logger.error(f"Failed to download file: {response.status_code} - {response.text}")
        sys.exit(-1)
        





def rep_decrypt_file(encrypted_file):
    """Descriptografa um arquivo usando os metadados no state e imprime no terminal."""
    logger.info(f"Decrypting file: encrypted_file={encrypted_file}")

 
    metadata = state.get("last_metadata")
    if not metadata:
        logger.error("No metadata available in state. Please fetch the metadata first.")
        sys.exit(1)

    key = bytes.fromhex(metadata["key"])  # Certifique-se de que está em formato bytes
    iv = bytes.fromhex(metadata["iv"])    # Certifique-se de que está em formato bytes
    algorithm = metadata["alg"]


    if algorithm != "AES-256-CFB":
        logger.error(f"Unsupported algorithm '{algorithm}'.")
        sys.exit(1)

    if not os.path.exists(encrypted_file):
        logger.error(f"Encrypted file '{encrypted_file}' not found.")
        sys.exit(1)

    with open(encrypted_file, "r") as f:
        encrypted_content_hex = f.read().strip() 


    encrypted_content = bytes.fromhex(encrypted_content_hex)


    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_content = decryptor.update(encrypted_content) + decryptor.finalize()


    try:
        decoded_content = decrypted_content.decode('utf-8')
        logger.info("File decrypted successfully.\n")
        print("\nDecrypted Content (UTF-8):\n")
        print(decoded_content)
        return decoded_content
    except UnicodeDecodeError:
        logger.warning("Failed to decode decrypted content as UTF-8 text.")
        
        return None




def rep_get_doc_file(session_file, document_name, output_file=None):
    """
    Combina os comandos rep_get_doc_metadata, rep_get_file e rep_decrypt_file.
    Faz download e descriptografa o arquivo, escrevendo o conteúdo no terminal ou em um arquivo.
    """
    logger.info(f"Executing rep_get_doc_file: session_file={session_file}, document_name={document_name}, output_file={output_file}")


    metadata = rep_get_doc_metadata(session_file, document_name)
    if metadata is None:
        logger.error(f"Failed to fetch metadata for document '{document_name}'.")
        sys.exit(1)

    logger.debug(f"Metadata retrieved: {metadata}")


    file_handle = metadata["file_handle"]
    encrypted_file = output_file or "temp_encrypted_file.txt"
    rep_get_file(file_handle, encrypted_file)

    if not os.path.exists(encrypted_file):
        logger.error(f"Failed to download the encrypted file {encrypted_file}. Exiting.")
        sys.exit(1)

    if output_file:
        content_str = rep_decrypt_file(encrypted_file)
        with open(output_file, "w", encoding="utf-8") as f:
                f.write(content_str)
        logger.info(f"Decrypted content saved to {output_file}.")

    else:
        logger.info(f"Decrypting file: {encrypted_file}")
        rep_decrypt_file(encrypted_file)


    logger.info(f"rep_get_doc_file executed successfully for document '{document_name}'.")
    sys.exit(0)



def rep_assume_role(session_file, role):
    """
    Assumes a role within the session of the given organization.
    This command requires that the role exists and is allowed for the subject in the session.
    """
    logger.info(f"Assuming role: session_file={session_file}, role={role}")

    # Diretório de sessões
    session_dir = "sessions"
    session_file_path = os.path.join(session_dir, session_file)

    # Verificar se o arquivo da sessão existe
    if not os.path.exists(session_file_path):
        logger.error(f"Session file '{session_file}' not found.")
        sys.exit(1)

    # Carregar dados da sessão
    with open(session_file_path, "r") as sf:
        session_data = json.load(sf)
        session_id = session_data.get("session_id")
        session_key = base64.b64decode(session_data.get("session_key"))
        organization = session_data.get("organization")
        session_hmac = session_data.get("hmac").encode()
        if not session_id or not organization:
            logger.error("Invalid session data: Missing session_id or organization.")
            sys.exit(1)

    # Criptografar o nonce com a chave simetrica
    iv = os.urandom(16)  # Gerar um vetor de inicialização
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_nonce = encryptor.update(generate_nonce().encode()) + encryptor.finalize()

    # Endpoint para assumir o papel
    url = f"http://{state['REP_ADDRESS']}/role/assume"

    # Dados para o request
    data = {
        "session_id": session_id,
        "role": role,
        "nonce": base64.b64encode(encrypted_nonce).decode(),
        "iv": iv.hex()
    }

    mac = hmac.new(session_hmac, json.dumps(data).encode(), hashlib.sha256).hexdigest()
    data["mac"] = mac

    # Enviar requisição para o servidor
    response = requests.post(url, json=data)

    if response.status_code == 200:
        logger.info(f"Role '{role}' successfully assumed in session {session_id}.")
        session_data['roles'] = session_data.get('roles', []) + [role]  # Atualizar papéis no estado
        with open(session_file_path, "w") as sf:
            json.dump(session_data, sf, indent=4)
        sys.exit(0)
    else:
        logger.error(f"Failed to assume role '{role}': {response.status_code} - {response.text}")
        sys.exit(-1)


def rep_drop_role(session_file, role):
    """
    Remove um papel atribuído a uma sessão.
    """
    logger.info(f"Dropping role: session_file={session_file}, role={role}")

    # Verificar se o arquivo de sessão existe
    session_dir = "sessions"
    session_file_path = os.path.join(session_dir, session_file)
    if not os.path.exists(session_file_path):
        logger.error(f"Session file '{session_file}' not found.")
        sys.exit(1)

    # Carregar dados da sessão
    with open(session_file_path, "r") as sf:
        session_data = json.load(sf)
        session_id = session_data.get("session_id")
        session_key = base64.b64decode(session_data.get("session_key"))
        session_hmac = session_data.get("hmac").encode()
        if not session_id:
            logger.error("Invalid session file: Missing session_id.")
            sys.exit(1)

    
    # Criptografar o nonce com a chave simetrica
    iv = os.urandom(16)  # Gerar um vetor de inicialização
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_nonce = encryptor.update(generate_nonce().encode()) + encryptor.finalize()

    # Dados para o request
    data = {
        "session_id": session_id,
        "role": role,
        "nonce": base64.b64encode(encrypted_nonce).decode(),
        "iv": iv.hex()
    }

    mac = hmac.new(session_hmac, json.dumps(data).encode(), hashlib.sha256).hexdigest()
    data["mac"] = mac

    # Fazer a requisição ao servidor
    url = f"http://{state['REP_ADDRESS']}/role/drop"
    response = requests.post(url, json=data)

    if response.status_code == 200:
        logger.info(f"Role '{role}' successfully dropped from session {session_id}.")
        print(response.json().get("message"))
        sys.exit(0)
    else:
        logger.error(f"Failed to drop role '{role}': {response.status_code} - {response.text}")
        sys.exit(-1)





def rep_add_role(session_file, role_name):
    """
    Adiciona um novo papel (role) à organização com a qual o utilizador tem atualmente uma sessão ativa.
    """
    logger.info(f"Adding role: session_file={session_file}, role_name={role_name}")

    # Verificar se o ficheiro de sessão existe
    session_dir = "sessions"
    session_file_path = os.path.join(session_dir, session_file)
    if not os.path.exists(session_file_path):
        logger.error(f"Session file '{session_file}' not found.")
        sys.exit(1)

    # Carregar os dados da sessão
    with open(session_file_path, "r") as sf:
        session_data = json.load(sf)
        session_id = session_data.get("session_id")
        session_key = base64.b64decode(session_data.get("session_key"))
        session_hmac = session_data.get("hmac").encode()
        if not session_id:
            logger.error("Session ID not found in session file.")
            sys.exit(1)
    
    # Criptografar o nonce com a chave simétrica
    iv = os.urandom(16)  # Gerar um vetor de inicialização
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_nonce = encryptor.update(generate_nonce().encode()) + encryptor.finalize()

    # Dados a enviar ao servidor
    data = {
        "session_id": session_id,
        "role_name": role_name,
        "nonce": base64.b64encode(encrypted_nonce).decode(),
        "iv": iv.hex()
    }

    mac = hmac.new(session_hmac, json.dumps(data).encode(), hashlib.sha256).hexdigest()
    data["mac"] = mac

    # Fazer a requisição ao servidor
    url = f"http://127.0.0.1:5000/role/add"
    response = requests.post(url, json=data)

    # Processar a resposta do servidor
    if response.status_code == 200:
        logger.info(f"Role '{role_name}' added successfully.")
        print(response.json().get("message"))
        sys.exit(0)
    else:
        logger.error(f"Failed to add role: {response.status_code} - {response.text}")
        sys.exit(-1)

def rep_list_roles(session_file, role=None):
    """
    Lista os papéis associados à organização da sessão ativa.
    Se 'role' for fornecido, lista detalhes apenas desse papel específico.
    """
    logger.info(f"Listing roles: session_file={session_file}, role={role if role else 'All'}")

    # Diretório de sessões
    session_dir = "sessions"
    session_file_path = os.path.join(session_dir, session_file)

    # Verificar se o arquivo de sessão existe
    if not os.path.exists(session_file_path):
        logger.error(f"Session file '{session_file}' not found.")
        sys.exit(1)
    # Carregar os dados da sessão
    with open(session_file_path, "r") as sf:
        session_data = json.load(sf)
        session_id = session_data.get("session_id")
        session_key = base64.b64decode(session_data.get("session_key"))
        session_hmac = session_data.get("hmac").encode()
        if not session_id:
            logger.error("Invalid session file: session_id missing.")
            sys.exit(1)


    # Criptografar o nonce com a chave simétrica
    iv = os.urandom(16)  # Gerar um vetor de inicialização
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_nonce = encryptor.update(generate_nonce().encode()) + encryptor.finalize()


    # Preparar dados para envio
    data = {"session_id": session_id,
            "nonce": base64.b64encode(encrypted_nonce).decode(),
            "iv": iv.hex()
            }
    
    mac = hmac.new(session_hmac, json.dumps(data).encode(), hashlib.sha256).hexdigest()
    data["mac"] = mac
    
    if role:
        data["role"] = role

    # Fazer a requisição ao servidor
    url = f"http://127.0.0.1:5000/role/list"
    try:
        response = requests.post(url, json=data)

        if response.status_code == 200:
            roles = response.json().get("roles", [])
            if not roles:
                print("\nNo roles found for the organization.")
                logger.info("No roles found for the organization.")
                return
            
            print("\nRoles List:")
            print("=" * 40)
            for idx, r in enumerate(roles, start=1):
                print(f"{idx}. Role Name: {r['name']}")
                print(f"   Status     : {r['status']}")
                permissions = ", ".join(r['permissions']) if r['permissions'] else "No permissions assigned"
                print(f"   Permissions: {permissions}")
                print("-" * 40)
            print("=" * 40)
            logger.info("Roles retrieved successfully.")
            sys.exit(0)
        else:
            error_message = response.json().get("error", "Unknown error")
            logger.error(f"Failed to list roles: {error_message}")
            print(f"Error: {error_message}")
            sys.exit(-1)

    except requests.RequestException as e:
        logger.error(f"Failed to connect to the server: {str(e)}")
        print(f"Error: Failed to connect to the server: {str(e)}")
        sys.exit(-1)

def rep_add_permission(session_file, role, target):
    """
    Adiciona uma permissão ou um sujeito (username) a um papel.
    - Se o 'target' for um nome de usuário, adiciona o sujeito ao papel.
    - Se o 'target' for uma permissão, adiciona a permissão ao papel.
    """
    logger.info(f"Adding permission or subject: session_file={session_file}, role={role}, target={target}")
    if is_permission(target):
        _modify_permission(session_file, role, target, action="add_permission")
    else:
        _modify_permission(session_file, role, target, action="add_subject")


def rep_remove_permission(session_file, role, target):
    """
    Remove uma permissão ou um sujeito (username) de um papel.
    - Se o 'target' for um nome de usuário, remove o sujeito do papel.
    - Se o 'target' for uma permissão, remove a permissão do papel.
    """
    logger.info(f"Removing permission or subject: session_file={session_file}, role={role}, target={target}")
    if is_permission(target):
        _modify_permission(session_file, role, target, action="remove_permission")
    else:
        _modify_permission(session_file, role, target, action="remove_subject")


def _modify_permission(session_file, role, target, action):
    """
    Função auxiliar para modificar propriedades de um papel (sujeitos ou permissões).
    """
    # Diretório de sessões
    session_dir = "sessions"
    session_file_path = os.path.join(session_dir, session_file)

    # Verificar se o arquivo de sessão existe
    if not os.path.exists(session_file_path):
        logger.error(f"Session file '{session_file}' not found.")
        sys.exit(1)

    # Carregar os dados da sessão
    with open(session_file_path, "r") as sf:
        session_data = json.load(sf)
        session_id = session_data.get("session_id")
        session_key = base64.b64decode(session_data.get("session_key"))
        session_hmac = session_data.get("hmac").encode()
        if not session_id:
            logger.error("Invalid session file: session_id missing.")
            sys.exit(1)
        
    iv = os.urandom(16)  # Gerar um vetor de inicialização
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    nonce = generate_nonce()
    encrypted_nonce = encryptor.update(nonce.encode()) + encryptor.finalize()

    data = {
        "session_id": session_id,
        "role": role,
        "target": target,  # Pode ser 'username' ou 'permission', dependendo da ação
        "action": action,   # Indica a ação: 'add_permission', 'remove_permission', etc.
        "nonce": base64.b64encode(encrypted_nonce).decode(),
        "iv": iv.hex()
    }

    mac = hmac.new(session_hmac, json.dumps(data).encode(), hashlib.sha256).hexdigest()
    data["mac"] = mac

    # Fazer a requisição ao servidor
    url = f"http://127.0.0.1:5000/role/modify"
    try:
        response = requests.post(url, json=data)

        if response.status_code == 200:
            print(f"Action '{action}' completed successfully for role '{role}'.")
            logger.info(f"Action '{action}' completed successfully for role '{role}'.")
            sys.exit(0)
        else:
            error_message = response.json().get("error", "Unknown error")
            logger.error(f"Failed to perform action '{action}' on role '{role}': {error_message}")
            print(f"Error: {error_message}")
            sys.exit(-1)

    except requests.RequestException as e:
        logger.error(f"Failed to connect to the server: {str(e)}")
        print(f"Error: Failed to connect to the server: {str(e)}")
        sys.exit(-1)

def is_permission(target):
    """
    Determina se o 'target' é uma permissão ou um nome de usuário.
    - Considera permissões como strings padrão ('read', 'write', 'delete', etc.).
    """
    valid_permissions = {"ROLE_ACL","SUBJECT_NEW","SUBJECT_DOWN","SUBJECT_UP","DOC_NEW","ROLE_NEW","ROLE_MOD","ROLE_UP","ROLE_DOWN"}  # Liste aqui as permissões válidas
    return target in valid_permissions
     


def rep_list_role_subjects(session_file, role):
    logger.info(f"Listing subjects for role '{role}' using session '{session_file}'.")

    # Carregar os dados da sessão
    session_dir = "sessions"
    session_file_path = os.path.join(session_dir, session_file)

    if not os.path.exists(session_file_path):
        logger.error(f"Session file '{session_file}' not found.")
        sys.exit(1)

    with open(session_file_path, "r") as sf:
        session_data = json.load(sf)
        session_id = session_data.get("session_id")
        session_key = base64.b64decode(session_data.get("session_key"))
        session_hmac = session_data.get("hmac").encode()
        if not session_id:
            logger.error("session_id not found in session file.")
            sys.exit(1)


    # Criar nonce 
    iv = os.urandom(16)  # Gerar um vetor de inicialização
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_nonce = encryptor.update(generate_nonce().encode()) + encryptor.finalize()

    # Configurar URL e parâmetros
    url = f"http://127.0.0.1:5000/roles/{role}/subjects"
    data = {
            "session_id": session_id,
            "nonce": base64.b64encode(encrypted_nonce).decode(),
            "iv": iv.hex()
        }
    
    mac = hmac.new(session_hmac, json.dumps(data).encode(), hashlib.sha256).hexdigest()
    data["mac"] = mac

    # Log para depuração
    logger.debug(f"Sending request to: {url} with params: {data}")

    # Fazer a requisição
    response = requests.get(url, json=data)
    if response.status_code == 200:
        response_data = response.json()
        if response_data["success"]:
            subjects = response_data.get("subjects", [])
            if subjects:
                print(f"\nSubjects for role '{role}':")
                print("=" * 30)
                for i, subject in enumerate(subjects, 1):
                    print(f"{i}. {subject}")
                print("=" * 30)
                sys.exit(0)
            else:
                print(f"No subjects found for role '{role}'.")
                sys.exit(1)
        else:
            logger.info(response_data["message"])
            sys.exit(-1)
    else:
        logger.error(f"Failed to list role subjects: {response.status_code} - {response.text}")
        sys.exit(-1)


def rep_list_role_permissions(session_file, role):
    logger.info(f"Listing permissions for role '{role}' using session '{session_file}'.")

    # Carregar os dados da sessão
    session_dir = "sessions"
    session_file_path = os.path.join(session_dir, session_file)

    if not os.path.exists(session_file_path):
        logger.error(f"Session file '{session_file}' not found.")
        sys.exit(1)

    with open(session_file_path, "r") as sf:
        session_data = json.load(sf)
        session_id = session_data.get("session_id")
        session_key = base64.b64decode(session_data.get("session_key"))
        session_hmac = session_data.get("hmac").encode()
        if not session_id:
            logger.error("session_id not found in session file.")
            sys.exit(1)


    # Criar nonce
    iv = os.urandom(16)  # Gerar um vetor de inicialização
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_nonce = encryptor.update(generate_nonce().encode()) + encryptor.finalize()

    # Configurar URL e parâmetros
    url = f"http://127.0.0.1:5000/roles/{role}/permissions"
    data = {"session_id": session_id,
              "nonce": base64.b64encode(encrypted_nonce).decode(),
              "iv": iv.hex()
              }
    
    mac = hmac.new(session_hmac, json.dumps(data).encode(), hashlib.sha256).hexdigest()
    data["mac"] = mac


    # Log para depuração
    logger.debug(f"Sending request to: {url} with params: {data}")

    # Fazer a requisição
    response = requests.get(url, json=data)
    if response.status_code == 200:
        response_data = response.json()
        if response_data["success"]:
            permissions = response_data.get("permissions", [])
            if permissions:
                print(f"\nPermissions for role '{role}':")
                print("=" * 30)
                for i, permission in enumerate(permissions, 1):
                    print(f"{i}. {permission}")
                print("=" * 30)
                sys.exit(0)
            else:
                print(f"No permissions found for role '{role}'.")
                sys.exit(0)
        else:
            logger.info(response_data["message"])
            sys.exit(-1)
    else:
        logger.error(f"Failed to list role permissions: {response.status_code} - {response.text}")
        sys.exit(-1)





def rep_list_subject_roles(session_file, username):
    logger.info(f"Listing roles for subject '{username}' using session '{session_file}'.")

    # Carregar os dados da sessão
    session_dir = "sessions"
    session_file_path = os.path.join(session_dir, session_file)

    if not os.path.exists(session_file_path):
        logger.error(f"Session file '{session_file}' not found.")
        sys.exit(1)

    with open(session_file_path, "r") as sf:
        session_data = json.load(sf)
        session_id = session_data.get("session_id")
        session_key = base64.b64decode(session_data.get("session_key"))
        session_hmac = session_data.get("hmac").encode()
        if not session_id:
            logger.error("session_id not found in session file.")
            sys.exit(1)

    # Criar nonce
    iv = os.urandom(16)  # Gerar um novo IV
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    nonce = generate_nonce()
    encrypted_nonce = encryptor.update(nonce.encode()) + encryptor.finalize()

    # Configurar URL e parâmetros
    url = f"http://127.0.0.1:5000/subjects/{username}/roles"
    data = {"session_id": session_id,
              "nonce": base64.b64encode(encrypted_nonce).decode(),
              "iv": iv.hex()
              }
        
    mac = hmac.new(session_hmac, json.dumps(data).encode(), hashlib.sha256).hexdigest()
    data["mac"] = mac

    # Log para depuração
    logger.debug(f"Sending request to: {url} with params: {data}")

    # Fazer a requisição
    response = requests.get(url, json=data)
    if response.status_code == 200:
        response_data = response.json()
        if response_data["success"]:
            roles = response_data.get("roles", [])
            if roles:
                print(f"\nRoles for subject '{username}':")
                print("=" * 30)
                for i, role in enumerate(roles, 1):
                    print(f"{i}. {role}")
                print("=" * 30)
                sys.exit(0)
            else:
                print(f"No roles found for subject '{username}'.")
                sys.exit(0)
        else:
            logger.info(response_data["message"])
            sys.exit(-1)
    else:
        logger.error(f"Failed to list roles for subject: {response.status_code} - {response.text}")
        sys.exit(-1)






def rep_list_permission_roles(session_file, permission):
    logger.info(f"Listing roles with permission '{permission}' using session '{session_file}'.")

    # Carregar os dados da sessão
    session_dir = "sessions"
    session_file_path = os.path.join(session_dir, session_file)

    if not os.path.exists(session_file_path):
        logger.error(f"Session file '{session_file}' not found.")
        sys.exit(1)


    with open(session_file_path, "r") as sf:
        session_data = json.load(sf)
        session_id = session_data.get("session_id")
        session_key = base64.b64decode(session_data.get("session_key"))
        session_hmac = session_data.get("hmac").encode()
        if not session_id:
            logger.error("session_id not found in session file.")
            sys.exit(1)


    # Criar nonce
    iv = os.urandom(16)  # Gerar um novo IV
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    nonce = generate_nonce()
    encrypted_nonce = encryptor.update(nonce.encode()) + encryptor.finalize()

    # Configurar URL e parâmetros
    url = f"http://127.0.0.1:5000/permissions/{permission}/roles"
    data = {"session_id": session_id,
              "nonce": base64.b64encode(encrypted_nonce).decode(),
              "iv": iv.hex()
              }
    
    mac = hmac.new(session_hmac, json.dumps(data).encode(), hashlib.sha256).hexdigest()
    data["mac"] = mac

    # Log para depuração
    logger.debug(f"Sending request to: {url} with params: {data}")

    # Fazer a requisição
    response = requests.get(url, json=data)
    if response.status_code == 200:
        response_data = response.json()
        if response_data["success"]:
            roles = response_data.get("roles", [])
            if roles:
                print(f"\nRoles with permission '{permission}':")
                print("=" * 40)
                for i, role in enumerate(roles, 1):
                    print(f"{i}. {role}")
                print("=" * 40)
                sys.exit(0)
            else:
                print(f"No roles found with permission '{permission}'.")
                sys.exit(0)
        else:
            logger.info(response_data["message"])
            sys.exit(-1)
    else:
        logger.error(f"Failed to list roles with permission: {response.status_code} - {response.text}")
        sys.exit(-1)



def rep_suspend_role(session_file, role):
    logger.info(f"Suspending role: session_file={session_file}, role={role}")

    # Carregar os dados da sessão
    session_dir = "sessions"  # Diretório onde os arquivos de sessão estão localizados
    session_file_path = os.path.join(session_dir, session_file)
    if not os.path.exists(session_file_path):
        logger.error(f"Session file '{session_file}' not found.")
        sys.exit(1)


    with open(session_file_path, "r") as sf:
        session_data = json.load(sf)
        session_id = session_data.get("session_id")
        session_key = base64.b64decode(session_data.get("session_key"))
        session_hmac = session_data.get("hmac").encode()
        if not session_id:
            logger.error("session_id not found in session file.")
            sys.exit(1)


    # Encriptar nonce com a chave simétrica
    iv = os.urandom(16)  # Gerar um novo IV
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    nonce = generate_nonce()
    encrypted_nonce = encryptor.update(nonce.encode()) + encryptor.finalize()

    # Configurar URL e parâmetros para a solicitação
    url = "http://127.0.0.1:5000/role/suspend"
    data = {
        "session_id": session_id,
        "role": role,
        "nonce": base64.b64encode(encrypted_nonce).decode(),
        "iv": iv.hex()
    }

    mac = hmac.new(session_hmac, json.dumps(data).encode(), hashlib.sha256).hexdigest()
    data["mac"] = mac

    # Log para depuração
    logger.debug(f"Sending request to: {url} with data: {data}logger.")

    try:
        # Enviar a solicitação POST
        response = requests.post(url, json=data)
        
        # Verificar o status da resposta
        if response.status_code == 200:
            logger.info(response.json()["message"])
        else:
            error_message = response.json().get("error", "Unknown error")
            logger.error(f"Failed to suspend role '{role}': {error_message}")
            print(f"Error: {error_message}")
            sys.exit(-1)
    
    except requests.RequestException as e:
        logger.error(f"Failed to connect to the server: {str(e)}")
        print(f"Error: Failed to connect to the server: {str(e)}")
        sys.exit(-1)


def rep_reactivate_role(session_file, role):
    logger.info(f"Reactivating role: session_file={session_file}, role={role}")


    # Carregar os dados da sessão
    session_dir = "sessions"  # Diretório onde os arquivos de sessão estão localizados
    session_file_path = os.path.join(session_dir, session_file)
    if not os.path.exists(session_file_path):
        logger.error(f"Session file '{session_file}' not found.")
        sys.exit(1)


    with open(session_file_path, "r") as sf:
        session_data = json.load(sf)
        session_id = session_data.get("session_id")
        session_key = base64.b64decode(session_data.get("session_key"))
        session_hmac = session_data.get("hmac").encode()
        if not session_id:
            logger.error("session_id not found in session file.")
            sys.exit(1)


        # Encriptar nonce com a chave simétrica
    iv = os.urandom(16)  # Gerar um novo IV
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    nonce = generate_nonce()
    encrypted_nonce = encryptor.update(nonce.encode()) + encryptor.finalize()


    # Configurar URL e parâmetros para a solicitação
    url = "http://127.0.0.1:5000/role/reactivate"
    data = {
        "session_id": session_id,
        "role": role,
        "nonce" : base64.b64encode(encrypted_nonce).decode(),
        "iv": iv.hex()
    }

    mac = hmac.new(session_hmac, json.dumps(data).encode(), hashlib.sha256).hexdigest()
    data["mac"] = mac

    # Log para depuração
    logger.debug(f"Sending request to: {url} with data: {data}")

    try:
        # Enviar a solicitação POST
        response = requests.post(url, json=data)
        
        # Verificar o status da resposta
        if response.status_code == 200:
            logger.info(response.json()["message"])
        else:
            error_message = response.json().get("error", "Unknown error")
            logger.error(f"Failed to reactivate role '{role}': {error_message}")
            print(f"Error: {error_message}")
            sys.exit(-1)
    
    except requests.RequestException as e:
        logger.error(f"Failed to connect to the server: {str(e)}")
        print(f"Error: Failed to connect to the server: {str(e)}")
        sys.exit(-1)


def rep_acl_doc(session_file, document_name, action, role, permission):

    logger.info(f"Modifying ACL for document '{document_name}': session_file={session_file}, action={action}, role={role}, permission={permission}")

    if not all([session_file, document_name, action, role, permission]):
        print("ERROR - Missing required arguments.")
        sys.exit(1)
        return

    try:
        with open(f"sessions/{session_file}", "r") as f:
            session_data = json.load(f)
            session_hmac = session_data.get("hmac").encode()
    except FileNotFoundError:
        print(f"ERROR - Session file '{session_file}' not found.")
        sys.exit(1)
        return
    except json.JSONDecodeError:
        print(f"ERROR - Failed to parse session file '{session_file}'.")
        sys.exit(1)
        return



    session_id = session_data.get("session_id")
    if not session_id:
        print("ERROR - Invalid session file: missing session_id.")
        sys.exit(1)
        return


    session_key = session_data.get("session_key")
    session_key = base64.b64decode(session_key) if session_key else None

            # Encriptar nonce com a chave simétrica
    iv = os.urandom(16)  # Gerar um novo IV
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    nonce = generate_nonce()
    encrypted_nonce = encryptor.update(nonce.encode()) + encryptor.finalize()


    # Preparar os dados para a requisição
    data = {
        "session_id": session_id,
        "document_name": document_name,
        "action": action,
        "role": role,
        "permission": permission,
        "nonce": base64.b64encode(encrypted_nonce).decode(),
        "iv": iv.hex()
    }

    mac = hmac.new(session_hmac, json.dumps(data).encode(), hashlib.sha256).hexdigest()
    data["mac"] = mac


    response = requests.post("http://127.0.0.1:5000/document/acl", json=data)
    if response.status_code == 200:
        print(f"INFO - Permission '{permission}' {action}ed for role '{role}' on document '{document_name}'.")
        sys.exit(0)
    elif response.status_code == 403:
        logger.error("Permission denied: DOC_ACL required.")

        sys.exit(-1)

    elif response.status_code == 407:
        logger.error("Permission denied: Last ACL cannot be removed.")
        sys.exit(-1)

    else:
        response_data = response.json()
        print(f"ERROR - {response_data.get('message', 'Unknown error occurred')}")
        #logger.error(f"Failed to {action} permission for role '{role}' on document '{document_name}': {response_data.get('message', 'Unknown error')}")
        sys.exit(-1)


def test_directories():
    """
    Testa se a navegação em diretórios sensíveis está desativada no servidor.
    """
    # Lista de diretórios para testar
    directories = ["sessions", "roles.db", "documents", "nonexistent_directory"]
    base_url = "http://127.0.0.1:5000"  # URL base do servidor

    print("\nTesting directory access...\n")

    for directory in directories:
        url = f"{base_url}/{directory}/"
        print("url:", url)
        try:
            response = requests.get(url)
            status_code = response.status_code

            if status_code == 403:
                print(f"[PASS] Directory '{directory}' is not accessible (403).")
            elif status_code == 404:
                print(f"[PASS] Directory '{directory}' does not exist (404).")
            elif status_code == 200:
                print(f"[FAIL] Directory '{directory}' is accessible (200).")
            else:
                print(f"[WARN] Directory '{directory}' returned unexpected status code: {status_code}")
        
        except requests.RequestException as e:
            print(f"[ERROR] Could not connect to the server for directory '{directory}': {e}")

    print("\nDirectory access test completed.\n")


command = args["command"]
if command == "rep_create_org":
    rep_create_org(args["arg0"], args["arg1"], args["arg2"], args["arg3"], args["arg4"])
elif command == "rep_list_orgs":
    rep_list_orgs()
elif command == "rep_create_session":
    rep_create_session(args["arg0"], args["arg1"], args["arg2"], args["arg3"], args["arg4"])
elif command == "rep_add_subject":      
    rep_add_subject(args["arg0"], args["arg1"], args["arg2"], args["arg3"], args["arg4"])
elif command == "rep_list_subjects":
    rep_list_subjects(args["arg0"], args["arg1"])
elif command == "rep_suspend_subject":
    rep_suspend_subject(args["arg0"], args["arg1"])
elif command == "rep_activate_subject":
    rep_activate_subject(args["arg0"], args["arg1"])
elif command == "rep_add_doc":
    rep_add_doc(args["arg0"], args["arg1"], args["arg2"])
elif command == "rep_delete_doc":
    rep_delete_doc(args["arg0"], args["arg1"])
elif command == "rep_subject_credentials":
    rep_subject_credentials(args["arg0"], args["arg1"])
elif command == "rep_get_doc_metadata":
    rep_get_doc_metadata(args["arg0"], args["arg1"])
elif command == "rep_list_docs":
    rep_list_docs(args["arg0"], args["string"], args["date"])
elif command == "rep_get_file":
    rep_get_file(args["arg0"], args["arg1"])
elif command == "rep_decrypt_file":
    rep_decrypt_file(args["arg0"])
elif command == "rep_get_doc_file":
    rep_get_doc_file(args["arg0"], args["arg1"], args["arg2"])
elif command == "rep_assume_role":
    rep_assume_role(args["arg0"], args["arg1"])
elif command == "rep_add_role":
    rep_add_role(args["arg0"], args["arg1"])
elif command == "rep_list_roles":
    rep_list_roles(args["arg0"], args["arg1"])
elif command == "rep_add_permission":
    rep_add_permission(args["arg0"], args["arg1"], args["arg2"])
elif command == "rep_remove_permission":
    rep_remove_permission(args["arg0"], args["arg1"], args["arg2"])
elif command == "rep_drop_role":
    rep_drop_role(args["arg0"], args["arg1"])
elif command == "rep_list_role_subjects":
    rep_list_role_subjects(args["arg0"], args["arg1"])
elif command == "rep_list_role_permissions":
    rep_list_role_permissions(args["arg0"], args["arg1"])
elif command == "rep_list_subject_roles":
    rep_list_subject_roles(args["arg0"], args["arg1"])  
elif command == "rep_list_permission_roles":
    rep_list_permission_roles(args["arg0"], args["arg1"])
elif command == "rep_suspend_role":
    rep_suspend_role(args["arg0"], args["arg1"])
elif command == "rep_reactivate_role":
    rep_reactivate_role(args["arg0"], args["arg1"])
elif command == "rep_acl_doc":
    rep_acl_doc(args["arg0"], args["arg1"], args["arg2"], args["arg3"], args["arg4"] )
elif command == "test_directories":
    test_directories()
else:
    logger.error("Invalid command specified.")
    sys.exit(1)

   