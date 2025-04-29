import glob
import os
import subprocess
import time

def terminate_process_on_port(port):
    try:
        result = subprocess.run(
            ['lsof', '-t', f'-i:{port}'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.returncode == 0 and result.stdout.strip():
            pids = result.stdout.strip().split('\n')
            for pid in pids:
                subprocess.run(['kill', '-9', pid], check=True)
                print(f"Processo {pid} encerrado na porta {port}.")
        else:
            print(f"Nenhum processo encontrado na porta {port}.")
    except Exception as e:
        print(f"Erro ao encerrar o processo na porta {port}: {e}")



def execute_command(command):
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            text=True
        )
        print(result.stdout)
        return result.returncode
    except subprocess.CalledProcessError as e:
        print(f"Erro ao executar o comando: {e.stderr}")
        return e.returncode


def clean_environment(state):
    # Elimina base de dados
    
    for db_file in glob.glob('*.db'):
        try:
            os.remove(db_file)
            print(f"Arquivo removido: {db_file}")
        except OSError as e:
            print(f"Erro ao remover {db_file}: {e}")

    # Elimina "documents"
    documents_path = "documents"
    if os.path.exists(documents_path):
        files_in_documents = glob.glob(os.path.join(documents_path, '*'))
        if files_in_documents:
            for doc_file in files_in_documents:
                os.remove(doc_file)
                print(f"Documento removido: {doc_file}")
            print(f"Pasta '{documents_path}' limpa.")
        else:
            print(f"Pasta '{documents_path}' está vazia. Nenhuma ação necessária.")
    else:
        print(f"Pasta '{documents_path}' não encontrada. Nenhuma ação necessária.")

    # Elimina "sessions"
    sessions_path = "sessions"
    if os.path.exists(sessions_path):
        files_in_sessions = glob.glob(os.path.join(sessions_path, '*'))
        if files_in_sessions:
            for session_file in files_in_sessions:
                os.remove(session_file)
                print(f"Sessão removida: {session_file}")
            print(f"Pasta '{sessions_path}' limpa.")
        else:
            print(f"Pasta '{sessions_path}' está vazia. Nenhuma ação necessária.")
    else:
        print(f"Pasta '{sessions_path}' não encontrada. Nenhuma ação necessária.")

    # Elimina "credentials"
    credentials_path = "credentials"
    if os.path.exists(credentials_path):
        files_in_credentials = glob.glob(os.path.join(credentials_path, '*'))
        if files_in_credentials:
            for cred_file in files_in_credentials:
                os.remove(cred_file)
                print(f"Credencial removida: {cred_file}")
            print(f"Pasta '{credentials_path}' limpa.")
        else:
            print(f"Pasta '{credentials_path}' está vazia. Nenhuma ação necessária.")
    else:
        print(f"Pasta '{credentials_path}' não encontrada. Nenhuma ação necessária.")


    terminate_process_on_port(5000)

    # restart repositório
    if state == 'init':
        try:
            subprocess.Popen(
                ['python3', 'repository.py'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(0.5)
            print("Repositório reiniciado.")
        except Exception as e:
            print(f"Erro ao reiniciar o repositório: {e}")

    return True



def test_initialization():
    assert clean_environment("init") is True
    

def test_1():

#CRIAR CREDENCIAIS (rep_subject_credentials)
    assert execute_command(['./rep_subject_credentials', 'pass1']) == 1  #input incorreto 

    assert execute_command(['./rep_subject_credentials', 'passA', 'credA.pem']) == 0
    assert execute_command(['./rep_subject_credentials', 'passB', 'credB.pem']) == 0
    assert execute_command(['./rep_subject_credentials', 'pass1', 'cred1.pem']) == 0    
    assert execute_command(['./rep_subject_credentials', 'pass2', 'cred2.pem']) == 0
    assert execute_command(['./rep_subject_credentials', 'pass3', 'cred3.pem']) == 0
    assert execute_command(['./rep_subject_credentials', 'pass4', 'cred4.pem']) == 0
    assert execute_command(['./rep_subject_credentials', 'pass5', 'cred5.pem']) == 0

    


#CRIAR ORGANIZAÇAO (rep_create_org)
    assert execute_command(['./rep_create_org', 'org1', 'user1', 'Name', 'email@domain.com', 'InvalidCredentials']) == 1    #input incorreto
    assert execute_command(['./rep_create_org', 'InvalidOrg', 'user1']) == 1                                                

    assert execute_command(['./rep_create_org', 'orgA', 'userA', 'NameA', 'emailA@domain.com', 'credA.pem']) == 0   #Cria orgA
    assert execute_command(['./rep_create_org', 'orgB', 'userB', 'NameB', 'emailB@domain.com', 'credB.pem']) == 0   #Cria orgB

    assert execute_command(['./rep_create_org', 'orgA', 'userA', 'NameA', 'emailA@domain.com', 'credA.pem']) == 255  #organizaçao ja existente     
 



#LISTAR ORGANIZAÇOES (rep_list_orgs)
    assert execute_command(['./rep_list_orgs']) == 0   




#CRIAR SESSAO (rep_create_session) -> manager
    assert execute_command(['./rep_create_session', 'orgA', 'userA', 'pass2', 'credA.pem', 'sessaoA']) == 1         # input incorreto (pass incorreta)

    assert execute_command(['./rep_create_session', 'orgA', 'userA', 'passA', 'credA.pem', 'sessaoA']) == 0         # Sessao A
    assert execute_command(['./rep_create_session', 'orgB', 'userB', 'passB', 'credB.pem', 'sessaoB']) == 0         # Sessao B

    assert execute_command(['./rep_create_session', 'orgA', 'userB', 'passA', 'credA.pem', 'sessaoA']) == 255       # sessao ja existente


    assert execute_command(['./rep_assume_role','sessaoA', 'Manager']) == 0 
    assert execute_command(['./rep_assume_role','sessaoB', 'Manager']) == 0 
    

#CRIAR NOVO SUJEITO (rep_add_subject)
    assert execute_command(['./rep_add_subject', 'sessao', 'user2', 'Name2', 'email2', 'invalid_cred1.pem']) == 1       #   input incorreto
    assert execute_command(['./rep_add_subject', 'sessao']) == 1

    assert execute_command(['./rep_add_subject', 'sessaoA', 'user1', 'name1', 'email1@domain.com', 'cred1.pem']) == 0   # user1 (Sessao A)
    assert execute_command(['./rep_add_subject', 'sessaoA', 'user2', 'name2', 'email2@domain.com', 'cred2.pem']) == 0   # user2 (Sessao A)
    assert execute_command(['./rep_add_subject', 'sessaoB', 'user3', 'name3', 'email3@domain.com', 'cred3.pem']) == 0   # user3 (Sessao B)
    assert execute_command(['./rep_add_subject', 'sessaoB', 'user4', 'name4', 'email4@domain.com', 'cred4.pem']) == 0   # user4 (Sessao B)

    assert execute_command(['./rep_add_subject', 'sessaoA', 'user1', 'name1', 'email1@domain.com', 'cred1.pem']) == 255 # user ja existente


 
#CRIAR SESSAO PARA NOVOS SUJEITOS (rep_create_session) -> user
    assert execute_command(['./rep_create_session', 'orgA', 'user1', 'pass1', 'cred1.pem']) == 1  # input incorreto

    assert execute_command(['./rep_create_session', 'orgA', 'user1', 'pass1', 'cred1.pem', 'sessao1']) == 0  # Sessao 1 -> user1
    assert execute_command(['./rep_create_session', 'orgA', 'user2', 'pass2', 'cred2.pem', 'sessao2']) == 0  # Sessao 2 -> user2
    assert execute_command(['./rep_create_session', 'orgB', 'user3', 'pass3', 'cred3.pem', 'sessao3']) == 0  # Sessao 3 -> user3
    assert execute_command(['./rep_create_session', 'orgB', 'user4', 'pass4', 'cred4.pem', 'sessao4']) == 0  # Sessao 4 -> user4     



#LISTAR SUJEITOS (rep_list_subjects)
    assert execute_command(['./rep_list_subjects', 'sessao', 'user1']) == 1

    assert execute_command(['./rep_list_subjects', 'sessaoA']) == 0
    assert execute_command(['./rep_list_subjects', 'sessaoB']) == 0

    # Filtro por nome de Utilizador
    assert execute_command(['./rep_list_subjects', 'sessao', 'user1']) == 1 # input incorreto 

    assert execute_command(['./rep_list_subjects', 'sessaoA', 'user1']) == 0
    assert execute_command(['./rep_list_subjects', 'sessaoA', 'user2']) == 0
    assert execute_command(['./rep_list_subjects', 'sessaoB', 'user3']) == 0
    assert execute_command(['./rep_list_subjects', 'sessaoB', 'user4']) == 0
    
    # Utilizador não encontrado na sessão   
    assert execute_command(['./rep_list_subjects', 'sessaoA', 'user3']) == 255
    assert execute_command(['./rep_list_subjects', 'sessaoB', 'invalidUser']) == 255


        
#SUSPENDER SUJEITO (rep_suspend_subject)
    assert execute_command(['./rep_suspend_subject', 'sessao']) == 1    # input errado
    assert execute_command(['./rep_suspend_subject', 'sessaoB', 'user4']) == 0
    assert execute_command(['./rep_suspend_subject', 'sessaoB', 'user4']) == 255        # is already suspended

    # Se o sujeito estiver suspenso, nao consegue operar 
    assert execute_command(['./rep_list_subjects', 'sessaoB','user4']) == 0

#ATIVAR SUJEITO (rep_activate_subject)
    assert execute_command(['./rep_activate_subject', 'sessaoB','user4']) == 0  
    assert execute_command(['./rep_activate_subject', 'sessaoB','user4']) == 255        # is already active    

    # Se o sujeito estiver ativo, consegue operar normalmente
    assert execute_command(['./rep_list_subjects', 'sessaoB','user4']) == 0  
    

    
    

    
def test_2():   #focado em atribuir permissões

#REP_ADD_ROLE
    assert execute_command(['./rep_add_role', 'sessao', 'Editor']) == 1
    assert execute_command(['./rep_add_role', 'sessao2', 'Editor']) == 255
    
    #sessão com permissão
    assert execute_command(['./rep_add_role', 'sessaoA', 'Editor']) == 0
    assert execute_command(['./rep_add_role', 'sessaoB', 'Gestor']) == 0
    assert execute_command(['./rep_add_role', 'sessaoA', 'Empresario']) == 0  
    assert execute_command(['./rep_add_role', 'sessaoA', 'Editor']) == 255 
    #role já foi adicionado a esta sessao
    assert execute_command(['./rep_add_role', 'sessaoA', 'Editor']) == 255


    assert execute_command(['./rep_list_roles', 'sessaoA']) == 0
    assert execute_command(['./rep_list_roles', 'sessaoB']) == 0
    assert execute_command(['./rep_list_roles', 'invalid_session']) == 1

#REP_ADD_PERMISSION(subjects)
    assert execute_command(['./rep_add_permission', 'sessaoA', 'Editor', 'user1']) == 0
    assert execute_command(['./rep_add_permission', 'sessaoB', 'Gestor', 'user3']) == 0
    assert execute_command(['./rep_add_permission', 'sessaoA', 'Empresario', 'user2']) == 0
    #permissao ja foi adicionada
    assert execute_command(['./rep_add_permission', 'sessaoA', 'Empresario', 'user2']) == 255

    

#REP_ADD_PERMISSION(permissoes) -->  DOC_NEW,ROLE_ACL,ROLE_NEW,ROLE_MOD,ROLE_UP,ROLE_DOWN,SUBJECT_NEW,SUBJECT_DOWN,SUBJECT_UP)

    #sessaoA
    assert execute_command(['./rep_add_permission', 'sessaoA', 'Editor', 'DOC_NEW']) == 0       
    assert execute_command(['./rep_add_permission', 'sessaoA', 'Editor', 'ROLE_UP']) == 0       
    assert execute_command(['./rep_add_permission', 'sessaoA', 'Editor', 'SUBJECT_NEW']) == 0   
    #sessaoB
    assert execute_command(['./rep_add_permission', 'sessaoB', 'Gestor', 'SUBJECT_NEW']) == 0   
    assert execute_command(['./rep_add_permission', 'sessaoB', 'Gestor', 'SUBJECT_DOWN']) == 0  
    assert execute_command(['./rep_add_permission', 'sessaoB', 'Gestor', 'SUBJECT_UP']) == 0   
    assert execute_command(['./rep_add_permission', 'sessaoB', 'Gestor', 'ROLE_ACL']) == 0          
    assert execute_command(['./rep_add_permission', 'sessaoB', 'Gestor', 'ROLE_MOD']) == 0     
    assert execute_command(['./rep_add_permission', 'sessaoB', 'Gestor', 'ROLE_NEW']) == 0      
    assert execute_command(['./rep_add_permission', 'sessaoB', 'Gestor', 'ROLE_DOWN']) == 0     
    assert execute_command(['./rep_add_permission', 'sessaoB', 'Gestor', 'ROLE_UP']) == 0       

    assert execute_command(['./rep_add_permission', 'sessaoA', 'Editor', 'DOC_NEW']) == 255 #ja tem permissao
    assert execute_command(['./rep_add_permission', 'sessaoB', 'Gestor', 'ROLE_ACL']) == 255    # ja tem permissao
    assert execute_command(['./rep_add_permission', 'sessao', 'Editor', 'DOC_NEW']) == 1    #sessao n/existe
    assert execute_command(['./rep_add_permission', 'sessao2', 'Editor', 'DOC_NEW']) == 255 #sessao n/tem permissão DOC_NEW


#REP_REMOVE_PERMISSION
    assert execute_command(['./rep_remove_permission', 'sessaoA', 'Editor', 'DOC_NEW']) == 0   
    assert execute_command(['./rep_add_permission', 'sessaoA', 'Editor', 'DOC_NEW']) == 0

#REP_ASSUME_ROLE
    assert execute_command(['./rep_assume_role', 'sessao1', 'Editor']) == 0 
    assert execute_command(['./rep_assume_role', 'sessao3', 'Gestor']) == 0
    assert execute_command(['./rep_assume_role', 'sessao2', 'Editor']) == 255   # n/tem permissao
    assert execute_command(['./rep_assume_role', 'sessao2', 'Gestor']) == 255   # n/tem permissao
    assert execute_command(['./rep_assume_role', 'sessao2', 'Empresario']) == 0

#REP_LIST_ROLES
    assert execute_command(['./rep_list_roles', 'sessao1']) == 0
    assert execute_command(['./rep_list_roles', 'invalid_session']) == 1

#REP_LIST_ROLES_PERMISSION
    assert execute_command(['./rep_list_role_permissions', 'sessaoA', 'Editor']) == 0
    assert execute_command(['./rep_list_role_permissions', 'sessaoB', 'Gestor']) == 0
    assert execute_command(['./rep_list_role_permissions', 'sessaoB', 'Editor']) == 0
    assert execute_command(['./rep_list_role_permissions', 'sessaoA', 'Gestor']) == 0

#REP_LIST_PERMISSION_ROLES
    assert execute_command(['./rep_list_permission_roles', 'sessao', 'DOC_NEW']) == 1
    assert execute_command(['./rep_list_permission_roles', 'sessaoA', 'DOC_NEW']) == 0
    assert execute_command(['./rep_list_permission_roles', 'sessaoB', 'ROLE_NEW']) == 0
    assert execute_command(['./rep_list_permission_roles', 'sessaoB', 'ROLE_MOD']) == 0
    assert execute_command(['./rep_list_permission_roles', 'sessaoB', 'DOC_NEW']) == 0 


def test_3():   #focado nos documentos e permissões DOC_ACL,DOC_READ,DOC_DELETE

#REP_ADD_DOC
    assert execute_command(['./rep_add_doc', 'sessao', 'Document1', 'file1.txt']) == 1          #input incorreto
    assert execute_command(['./rep_add_doc', 'sessao3', 'Document1', 'file1.txt']) == 255       #without permission

    assert execute_command(['./rep_add_doc', 'sessao1', 'Doc1', 'file1.txt']) == 0
    assert execute_command(['./rep_add_doc', 'sessao1', 'Doc2', 'file2.txt']) == 0
    assert execute_command(['./rep_add_doc', 'sessaoA', 'Doc3', 'file3.txt']) == 0           
    assert execute_command(['./rep_add_doc', 'sessao1', 'Document1', 'file1.txt']) == 255     # file1.txt ja existe logo nao pode ser adicionado novamente
    assert execute_command(['./rep_add_doc', 'sessao2', 'Document1', 'file4.txt']) == 255     # sem permissao
    assert execute_command(['./rep_add_doc', 'sessao1', 'Doc1', 'file1.txt']) == 255
# LISTA OS DADOS
    assert execute_command(['./rep_list_docs', 'sessao']) == 1
    assert execute_command(['./rep_list_docs', 'sessao1']) == 0
    assert execute_command(['./rep_list_docs', 'sessao2']) == 0
    assert execute_command(['./rep_list_docs', 'sessaoA']) == 0

    assert execute_command(['./rep_list_docs', 'sessaoA', '-s user1']) == 0
    assert execute_command(['./rep_list_docs', 'sessaoA', '-s user2']) == 0 
    assert execute_command(['./rep_list_docs', 'sessaoA','-s user2','-d nt 01-01-2024']) == 0     
    assert execute_command(['./rep_list_docs', 'sessaoA', '-d et 01-01-2024']) == 0
    assert execute_command(['./rep_list_docs', 'sessaoA', '-d ot 01-01-2024']) == 0

#REP_GET_ACL_METADATA
    #sem permissao
    assert execute_command(['./rep_get_doc_metadata', 'sessao2', 'Doc1']) == 255    
    assert execute_command(['./rep_get_doc_metadata', 'sessao1', 'Doc1']) == 0
    assert execute_command(['./rep_get_doc_metadata', 'sessao1', 'Doc2']) == 0
    assert execute_command(['./rep_get_doc_metadata', 'sessao1', 'Doc3']) == 255    
    assert execute_command(['./rep_get_doc_metadata', 'sessaoA', 'Doc1']) == 0
    assert execute_command(['./rep_get_doc_metadata', 'sessaoA', 'Doc2']) == 0
    assert execute_command(['./rep_get_doc_metadata', 'sessaoA', 'Doc3']) == 0




#REP_ACL_DOC 
    #session_file, document_name, action, role, permission
    assert execute_command(['./rep_acl_doc', 'sessaoA', 'Docs','+','Editor', 'DOC_ACL']) == 255
    assert execute_command(['./rep_acl_doc', 'sessaoA', 'Doc2','+','Editor', 'DOC_ACL']) == 0
    assert execute_command(['./rep_acl_doc', 'sessaoA', 'Doc1','+','Editor', 'DOC_ACL']) == 0
    

#REP_GET_DOC_FILE  (session_file, document_name, output_file=None)
    assert execute_command(['./rep_get_doc_file', 'sessao', 'Doc_Inexistente']) == 1
    assert execute_command(['./rep_get_doc_file', 'sessao']) == 1
    assert execute_command(['./rep_get_doc_file', 'sessao1', 'Doc2', 'output1.txt']) == 0



#REP_DELETE_DOC

    assert execute_command(['./rep_delete_doc', 'sessao']) == 1

    assert execute_command(['./rep_delete_doc', 'sessao1', 'novo_document_name']) == 1


    assert execute_command(['./rep_delete_doc', 'sessao2', 'Doc1']) == 255
    assert execute_command(['./rep_delete_doc', 'sessao1', 'Doc2']) == 0  


#REP_DECRYPT_FILE
    assert execute_command(['./rep_decrypt_file', 'file.txt']) == 1
    assert execute_command(['./rep_decrypt_file', 'output.txt']) == 0
    assert execute_command(['./rep_decrypt_file', 'get_doc_file']) == 1  

#REP_GET_FILE
    assert execute_command(['./rep_get_file', '27397cebad9d6bba418795d11876ff3e']) == 0
    assert execute_command(['./rep_get_file', '27397cebad9d6bba418795d11876ff3e', 'output.txt']) == 0
    assert execute_command(['./rep_get_file', 'invalid_file_handle']) == 255

def test_4():   #focado em usar permissões ROLE_UP,ROLE_DOWN,ROLE_MOD

    #tem permissão ROLE_NEW
    assert execute_command(['./rep_add_role', 'sessao3', 'CEO']) == 0   
    assert execute_command(['./rep_add_role', 'sessao3', 'Funcionario']) == 0  

#REP_ROLE_MOD
    assert execute_command(['./rep_add_permission', 'sessao3', 'Funcionario', 'user4']) == 0
    assert execute_command(['./rep_add_permission', 'sessao3', 'Funcionario', 'ROLE_UP']) == 0
    #sessão nao tem permissao ADD_ROLE
    assert execute_command(['./rep_add_role', 'sessao2', 'CEO']) == 255 
    # sessão já está a ser assumida pelo Gestor
    assert execute_command(['./rep_assume_role', 'sessao3', 'CEO']) == 255 
    
#REP_ROLE_DOWN
    #sessao não tem permissão ROLE_DOWN
    assert execute_command(['./rep_suspend_role', 'sessao2', 'Editor']) == 255 
    #role invalida
    assert execute_command(['./rep_suspend_role', 'sessao3', 'NonExistentRole']) == 255
    #sessao tem permissão ROLE_DOWN
    assert execute_command(['./rep_suspend_role', 'sessao3', 'CEO']) == 0   

#REP_ROLE_UP    
    #sessão tem permissão ROLE_UP mas sao de organizacoes diferentes
    assert execute_command(['./rep_reactivate_role', 'sessao1', 'CEO']) == 255 
    #reativa role 
    assert execute_command(['./rep_reactivate_role', 'sessao3', 'CEO']) == 0  
     
#REP_ROLE_MOD
    # tem permissao ROLE_MOD mas ROLE nao pertence a organizaçao
    assert execute_command(['./rep_remove_permission', 'sessao3', 'Editor', 'DOC_NEW']) == 255
    #nao tem permissao ROLE_MOD
    assert execute_command(['./rep_remove_permission', 'sessao1', 'Editor', 'DOC_NEW']) == 255
    # tem permissao ROLE_MOD
    assert execute_command(['./rep_remove_permission', 'sessaoA', 'Editor', 'DOC_NEW']) == 0
    #tem permissao ROLE_MOD
    assert execute_command(['./rep_remove_permission', 'sessao3', 'Gestor', 'DOC_NEW']) == 0

#REP_LIST_ROLE_SUBJECTS   
    assert execute_command(['./rep_list_role_subjects', 'sessao1', 'Editor']) == 0
    #role inválido
    assert execute_command(['./rep_list_role_subjects', 'sessao1', 'invalid_role']) == 1

def test_5():   #focado em usar permissões SUBJECT_NEW,SUBJECT_UP,SUBJECT_DOWN

#REP_ADD_SUBJECT
    #subject ja existe
    assert execute_command(['./rep_add_subject', 'sessao3', 'user4', 'name4', 'email4', 'cred4.pem']) == 255
    #sessao nao tem permissao SUBJECT_NEW
    assert execute_command(['./rep_add_subject', 'sessao2', 'user5', 'name5', 'email5', 'cred5.pem']) == 255
    #sessao tem permissão SUBJECT_NEW
    assert execute_command(['./rep_add_subject', 'sessao1', 'user5', 'name5', 'email5', 'cred5.pem']) == 0
    #tentativa duplicada
    assert execute_command(['./rep_add_subject', 'sessao1', 'user5', 'name5', 'email5', 'cred5.pem']) == 255

#REP_SUSPEND_SUBJECT    
    #com permissao SUBJECT_DOWN
    assert execute_command(['./rep_suspend_subject', 'sessao3', 'user4']) == 0
    #tentativa duplicada
    assert execute_command(['./rep_suspend_subject', 'sessao3', 'user4']) == 255
    #sem permissao SUBJECT_DOWN
    assert execute_command(['./rep_suspend_subject', 'sessao1', 'user2']) == 255     
    #username invalido
    assert execute_command(['./rep_suspend_subject', 'sessao2', 'user']) == 255

#REP_LIST_SUBJECTS
    # Se o sujeito estiver suspenso, nao consegue operar 
    assert execute_command(['./rep_list_subjects', 'sessao3','user2']) == 255

#REP_ACTIVATE_SUBJECT
    # Ativar sujeito
    assert execute_command(['./rep_activate_subject', 'sessao3','user4']) == 0
    #tentativa duplicada
    assert execute_command(['./rep_activate_subject', 'sessao3','user4']) == 255
    #sem permissao SUBJECT_UP
    assert execute_command(['./rep_activate_subject', 'sessao1','user2']) == 255
    #com permissao SUBLECT_UP mas user pertence a outra org
    assert execute_command(['./rep_activate_subject', 'sessao3','user1']) == 255

    # Se o sujeito estiver ativo, consegue operar normalmente
    assert execute_command(['./rep_list_subjects', 'sessao3','user4']) == 0  


def test_6():
    
#REP_DROP_ROLE
    assert execute_command(['./rep_drop_role', 'sessao1', 'Editor']) == 0
    assert execute_command(['./rep_drop_role', 'sessao1', 'NonExistentRole']) == 255
    assert execute_command(['./rep_list_roles', 'sessao1']) == 0


def test_cleanup_finalization():
    """Testa a finalização do ambiente de limpeza."""
    assert clean_environment("end") is True

