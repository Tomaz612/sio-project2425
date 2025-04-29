# **SIO_2425_Projeto** - Entrega 2

## **Membros do Grupo**
- **Martina Duque** (113261)
- **Sofia Marrafa** (114591)
- **Tomás Oliveira** (113939)

---

## **Requisitos de Instalação**

Para simplificar a instalação, as dependências do projeto estão listadas no ficheiro `requirements.txt`. Utilize o seguinte comando para instalar todos os pacotes necessários:

```bash
pip install -r requirements.txt
```

**Conteúdo do `requirements.txt`:**
```txt
# Dependências do Cliente
requests
cryptography

# Dependências do Repositório
flask
cryptography
```



#### **Novas Funções Implementadas:**
- **`rep_assume_role`**: Assume o papel especificado para a sessão.
- **`rep_drop_role`**: Deixa o papel associado à sessão.
- **`rep_list_roles`**: Lista os papéis atualmente assumidos pela sessão.
- **`rep_list_role_subjects`**: Lista os sujeitos associados a um papel.
- **`rep_list_subject_roles`**: Lista os papéis associados a um sujeito específico.
- **`rep_list_role_permissions`**: Lista as permissões atribuídas a um papel.
- **`rep_add_role`**: Adiciona um novo papel à organização.
- **`rep_suspend_role`**: Suspende um papel, impedindo que seja assumido por sujeitos.
- **`rep_reactivate_role`**: Reativa um papel previamente suspenso.
- **`rep_add_permission`**: Adiciona uma permissão a um papel.
- **`rep_remove_permission`**: Remove uma permissão de um papel.
- **`rep_acl_doc`**: Modifica a ACL de um documento, adicionando/removendo permissões para papéis.

#### **Melhorias nas Funcionalidades Anteriores:**
- Revisão das funções previamente implementadas e melhoria dos mecanismos de validação.


## **Testes e Validação**

Para a Entrega 2, todas as funcionalidades implementadas foram testadas através de:
- **Testes unitários** para validar a correção de cada função.
- **Testes manuais** para cenários limite, como entradas inválidas e restrições de papéis/permissões.

Foi criado um ficheiro de testes (tests.py), que é possível correr através do comando "pytest tests.py".
---

## **Atalhos Rápidos**
- **[Prazo de Entrega](https://classroom.github.com/a/n4Xu0y1X)**
- **[Abrir no Visual Studio Code](https://classroom.github.com/online_ide?assignment_repo_id=16951336&assignment_repo_type=AssignmentRepo)**




