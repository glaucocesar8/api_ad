from datetime import datetime, timedelta
from flask import Flask, jsonify, request
from ldap3 import Server, ALL_ATTRIBUTES, MODIFY_REPLACE, SUBTREE, MODIFY_ADD, MODIFY_DELETE
from pytz import utc
import credenciais
import random
import string


app = Flask(__name__)

### Verifica o Token para autenticar as APIs ###
fixed_access_token = credenciais.token_api

@app.before_request
def verificar_token_fixo():
    # Obtém o token de autorização do cabeçalho da solicitação
    token = request.headers.get('Authorization')

    # Verifica se o token fornecido é igual ao token de acesso fixo
    if token != f"Bearer {fixed_access_token}":
        return jsonify({'error': 'Token de acesso inválido'}), 401


### Conexão com o LDAP ###
server = Server("ldaps://contoso.com.br", use_ssl=True)
con = credenciais.conexao
base_dn = "DC=contoso,DC=com,DC=br"


### Verifica se a API está online ###
@app.route('/', methods=['POST'])
def index():
	return 'Sua API está Online!'


### Verifica se o usuário existe ###
@app.route('/api/consultar-existencia-usuario', methods=['POST'])
def consultar_existencia_usuario():
    login = request.json.get('login')
    filter_str = f"(sAMAccountName={login})"
    attributes = ['mail', 'displayName']

    con.search(base_dn, filter_str, attributes=attributes)

    if len(con.entries) == 0:
        return jsonify({'mensagem': 'Usuário não encontrado'}), 404
    else:
        user_entry = con.entries[0]
        response = {'mensagem': 'Usuário encontrado'}

        if 'mail' in user_entry:
            email = user_entry['mail'].value
            nome = user_entry['displayName'].value
            response['email'] = email
            response['nome'] = nome
        
        return jsonify(response)


### Verifica os grupos em que o usuário é membro ###
@app.route('/api/consultar-grupos-usuario', methods=['POST'])
def consultar_grupos_usuario():
    login = request.json.get('login')
    filter_str = f"(sAMAccountName={login})"
    attributes = ['memberOf']

    con.search(base_dn, filter_str, attributes=attributes)

    if len(con.entries) == 0:
        return jsonify({'mensagem': 'Usuário não encontrado'}), 404
    else:
        user_entry = con.entries[0]
        response = {'grupos': []}

        if 'memberOf' in user_entry:
            groups = user_entry['memberOf'].values
            response['grupos'] = groups
        
        return jsonify(response)


### Virifica se o usuário está bloqueado ###
@app.route('/api/verificar-usuario-bloqueado', methods=['POST'])
def verificar_bloqueio_usuario():
    login = request.json.get('login')
    filter_str = f"(sAMAccountName={login})"
    attributes = [ALL_ATTRIBUTES]

    con.search(base_dn, filter_str, attributes=attributes)

    if len(con.entries) == 0:
        return jsonify({'mensagem': 'Usuário não encontrado'}), 404
    else:
        user_entry = con.entries[0]
        if "lockoutTime" in user_entry:
            lockout_time = user_entry["lockoutTime"]
            if lockout_time is not None:
                lockout_time_str = str(lockout_time)
                Valor_Lockout = "00:00:00+00:00"
                if Valor_Lockout in lockout_time_str:
                    return jsonify({'mensagem': 'Usuário não está bloqueado'})
                else:
                    return jsonify({'mensagem': 'Usuário está bloqueado'})
        else:
            return jsonify({'mensagem': 'Atributo "lockoutTime" não encontrado'}), 500


### Desbloqueia o usuário ###
@app.route('/api/desbloquear-usuario', methods=['POST'])
def desbloquear_usuario():
    login = request.json.get('login')
    filter_str = f"(sAMAccountName={login})"
    con.search(base_dn, filter_str, attributes='sAMAccountName')

    if len(con.entries) > 0:
        user_entry = con.entries[0]
        user_dn = user_entry.entry_dn
        change = {
            'lockoutTime': [(MODIFY_REPLACE, [0])]
        }
        if con.modify(user_dn, change):
            print("Usuário desbloqueado com sucesso")
            return jsonify({'mensagem': 'Usuário desbloqueado com sucesso'})
        else:
            print("Erro ao desbloquear o usuário")
            return jsonify({'mensagem': 'Erro ao desbloquear o usuário'}), 500
    else:
        return jsonify({'mensagem': 'Usuário não encontrado'}), 404


# Função para gerar uma senha aleatória
def gerar_senha_aleatoria(tamanho=15):
    caracteres = string.digits
    senha = 'Novasenha' + ''.join(random.choice(caracteres) for _ in range(tamanho - len('Novasenha')))
    return senha


### Realiza o reset de senha do usuário ###
@app.route('/api/resetar-senha', methods=['POST'])
def resetar_senha():
    login_user = request.json.get('login_user')
    filter_str = f"(sAMAccountName={login_user})"
    con.search(base_dn, filter_str, attributes='sAMAccountName')
    if con.bind():
        try:
            con.search(search_base='DC=contoso,DC=com,DC=br', search_filter=f'(sAMAccountName={login_user})', search_scope=SUBTREE, attributes=['sAMAccountName'])
            if con.entries:
                user_dn = con.entries[0].entry_dn
                nova_senha = gerar_senha_aleatoria()  # Gerar a senha aleatória
                con.extend.microsoft.modify_password(user_dn, nova_senha, old_password=None)
                con.modify(user_dn, {'pwdLastSet': [(MODIFY_REPLACE, [0])]})
                return jsonify({'mensagem': 'Senha redefinida com sucesso', 'Senha provisória': nova_senha})
            else:
                return jsonify({'mensagem': 'Usuário não encontrado'}), 404
        except Exception as e:
            return jsonify({'mensagem': str(e)}), 500        
    else:
        return jsonify({'mensagem': 'Falha na conexão com o LDAP'}), 500


### Define uma data e hora para o usuário expirar ###
@app.route('/api/definir-expiracao-usuario', methods=['POST'])
def definir_expiracao_usuario():
    login = request.json.get('login')
    expiration_date = request.json.get('expiration_date')
    solicitante = request.json.get('mail_solicitante')  # Obtenha o nome do solicitante a partir do corpo da solicitação
    filter = "OU=Users,OU=TI,OU=Grupo Plaenge,DC=intra,DC=epgnet,DC=com,DC=br"

    # Filtro de pesquisa de permissão
    filter_permission = f'(mail={solicitante})'  # Filtro para todos os usuários

    # Realizar a pesquisa de permissão
    if con.bind():
        con.search(search_base=filter, search_filter=filter_permission, search_scope=SUBTREE, attributes=['mail'])
        user_found = False
        for entry in con.entries:
            mail = entry['mail'].value
            if mail == solicitante:
                print(f"Usuário {solicitante} com permissão")
                # Find the user's DN based on their 'mail'.
                filter_str = f'(sAMAccountName={login})'

                # Search for the user's DN.
                con.search(base_dn, filter_str)

                if con.entries:
                    user_dn = con.entries[0].entry_dn

                    try:
                        expiration_datetime = datetime.strptime(expiration_date, "%Y-%m-%d %H:%M:%S")
                        expiration_datetime = utc.localize(expiration_datetime)
                        # Adicione um dia à data para garantir que a data de expiração seja exatamente o que você deseja
                        expiration_datetime += timedelta(days=1)
                        expiration_timestamp = (expiration_datetime - datetime(1601, 1, 1,
                                                                               tzinfo=utc)).total_seconds() * 10 ** 7

                        # Set the account expiration attribute
                        change = {
                            'accountExpires': [(MODIFY_REPLACE, [int(expiration_timestamp)])]
                        }

                        if con.modify(user_dn, change):
                            return jsonify({'mensagem': f'Data de expiração definida com sucesso: {expiration_datetime}'})
                        else:
                            return jsonify({'mensagem': 'Erro ao definir data de expiração'}, 500)
                    except ValueError:
                        return jsonify({'mensagem': 'Erro: Data fornecida em formato incorreto. Use o formato AAAA-MM-DD HH:MM:SS.'})
                else:
                    return jsonify({'mensagem': 'Usuário não encontrado'}, 404)
                user_found = True
        if not user_found:
            print(f"Usuário {solicitante} sem permissão!")
            return jsonify({'mensagem': 'Usuário sem permissão.'})

        con.unbind()

"""
# Adiciona usuário ao grupo (Somente CN passado como parametro)
@app.route('/api/adicionar-usuario-grupo', methods=['POST'])
def adicionar_usuario_grupo():
    data = request.get_json()  # Captura o JSON da requisição
    if not data:
        return jsonify({'mensagem': 'Requisição inválida, JSON esperado'}), 400

    login = data.get('login')
    grupo_cn = data.get('grupo_cn')

    if not login or not grupo_cn:
        return jsonify({'mensagem': 'Login ou CN do grupo não fornecido'}), 400

    # Buscar DN do usuário
    filter_str = f"(sAMAccountName={login})"
    attributes = ['distinguishedName']
    con.search(base_dn, filter_str, attributes=attributes)

    if len(con.entries) == 0:
        return jsonify({'mensagem': 'Usuário não encontrado'}), 404
    else:
        user_entry = con.entries[0]
        if 'distinguishedName' not in user_entry:
            return jsonify({'mensagem': 'DN do usuário não encontrado'}), 404

        user_dn = user_entry['distinguishedName'].value

    # Buscar DN do grupo usando o CN
    group_filter_str = f"(cn={grupo_cn})"
    group_attributes = ['distinguishedName']
    con.search(base_dn, group_filter_str, attributes=group_attributes)

    if len(con.entries) == 0:
        return jsonify({'mensagem': 'Grupo não encontrado'}), 404
    else:
        group_entry = con.entries[0]
        if 'distinguishedName' not in group_entry:
            return jsonify({'mensagem': 'DN do grupo não encontrado'}), 404

        grupo_dn = group_entry['distinguishedName'].value

    # Adicionar usuário ao grupo
    con.modify(grupo_dn, {'member': [(MODIFY_ADD, [user_dn])]})

    if con.result['result'] == 0:
        return jsonify({'mensagem': 'Usuário adicionado ao grupo com sucesso'}), 200
    else:
        return jsonify({'mensagem': 'Falha ao adicionar usuário ao grupo', 'detalhes': con.result}), 500
"""


### Pesquisa se um grupo existe ###
@app.route('/api/pesquisar-grupo', methods=['POST'])
def pesquisar_grupo():
    data = request.get_json()  # Captura o JSON da requisição
    if not data:
        return jsonify({'mensagem': 'Requisição inválida, JSON esperado'}), 400

    grupo = data.get('grupo')

    if not grupo:
        return jsonify({'mensagem': 'Parâmetro grupo não fornecido'}), 400

    # Determina se o parâmetro é um email ou um CN
    if "@" in grupo:
        group_filter_str = f"(mail={grupo})"
    else:
        group_filter_str = f"(cn={grupo})"

    group_attributes = ['cn']
    con.search(base_dn, group_filter_str, attributes=group_attributes)

    if len(con.entries) == 0:
        return jsonify({'mensagem': 'Grupo não encontrado'}), 404
    else:
        group_entry = con.entries[0]
        if 'cn' not in group_entry:
            return jsonify({'mensagem': 'DN do grupo não encontrado'}), 404

    return jsonify({'mensagem': 'Grupo encontrado', 'cn': group_entry.cn.value}), 200


### Adiciona usuário em um grupo (Email ou CN passado como parametro) ###
@app.route('/api/adicionar-usuario-grupo', methods=['POST'])
def adicionar_usuario_grupo():
    data = request.get_json()  # Captura o JSON da requisição
    if not data:
        return jsonify({'mensagem': 'Requisição inválida, JSON esperado'}), 400

    login = data.get('login')
    grupo = data.get('grupo')

    if not login or not grupo:
        return jsonify({'mensagem': 'Login ou parâmetro do grupo não fornecido'}), 400

    # Buscar DN do usuário
    user_filter_str = f"(sAMAccountName={login})"
    user_attributes = ['distinguishedName']
    con.search(base_dn, user_filter_str, attributes=user_attributes)

    if len(con.entries) == 0:
        return jsonify({'mensagem': 'Usuário não encontrado'}), 404
    else:
        user_entry = con.entries[0]
        if 'distinguishedName' not in user_entry:
            return jsonify({'mensagem': 'DN do usuário não encontrado'}), 404

        user_dn = user_entry['distinguishedName'].value

    # Determina se o parâmetro é um email ou um CN
    if "@" in grupo:
        group_filter_str = f"(mail={grupo})"
    else:
        group_filter_str = f"(cn={grupo})"

    # Buscar DN do grupo
    group_attributes = ['distinguishedName']
    con.search(base_dn, group_filter_str, attributes=group_attributes)

    if len(con.entries) == 0:
        return jsonify({'mensagem': 'Grupo não encontrado'}), 404
    else:
        group_entry = con.entries[0]
        if 'distinguishedName' not in group_entry:
            return jsonify({'mensagem': 'DN do grupo não encontrado'}), 404

        grupo = group_entry['distinguishedName'].value

    # Adicionar usuário ao grupo
    con.modify(grupo, {'member': [(MODIFY_ADD, [user_dn])]})

    if con.result['result'] == 0:
        return jsonify({'mensagem': 'Usuário adicionado ao grupo com sucesso'}), 200
    else:
        return jsonify({'mensagem': 'Falha ao adicionar usuário ao grupo', 'detalhes': con.result})


### Adiciona o usuário em um ou mais grupos ###
@app.route('/api/adicionar-usuario-grupos', methods=['POST'])
def adicionar_usuario_grupos():
    data = request.get_json()  # Captura o JSON da requisição
    if not data:
        return jsonify({'mensagem': 'Requisição inválida, JSON esperado'}), 400

    login = data.get('login')
    grupos = data.get('grupos')  # Espera uma lista de grupos

    if not login or not grupos or not isinstance(grupos, list):
        return jsonify({'mensagem': 'Login ou parâmetro dos grupos não fornecido ou inválido'}), 400

    # Buscar DN do usuário
    user_filter_str = f"(sAMAccountName={login})"
    user_attributes = ['distinguishedName']
    con.search(base_dn, user_filter_str, attributes=user_attributes)

    if len(con.entries) == 0:
        return jsonify({'mensagem': 'Usuário não encontrado'}), 404
    else:
        user_entry = con.entries[0]
        if 'distinguishedName' not in user_entry:
            return jsonify({'mensagem': 'DN do usuário não encontrado'}), 404

        user_dn = user_entry['distinguishedName'].value

    # Loop para adicionar usuário a cada grupo
    resultados = []
    for grupo in grupos:
        # Determina se o parâmetro é um email ou um CN
        if "@" in grupo:
            group_filter_str = f"(mail={grupo})"
        else:
            group_filter_str = f"(cn={grupo})"

        # Buscar DN do grupo
        group_attributes = ['distinguishedName']
        con.search(base_dn, group_filter_str, attributes=group_attributes)

        if len(con.entries) == 0:
            resultados.append({'grupo': grupo, 'mensagem': 'Grupo não encontrado'})
            continue
        else:
            group_entry = con.entries[0]
            if 'distinguishedName' not in group_entry:
                resultados.append({'grupo': grupo, 'mensagem': 'DN do grupo não encontrado'})
                continue

            grupo_dn = group_entry['distinguishedName'].value

        # Adicionar usuário ao grupo
        con.modify(grupo_dn, {'member': [(MODIFY_ADD, [user_dn])]})

        if con.result['result'] == 0:
            resultados.append({'grupo': grupo, 'mensagem': 'Usuário adicionado ao grupo com sucesso'})
        else:
            resultados.append({'grupo': grupo, 'mensagem': 'Falha ao adicionar usuário ao grupo', 'detalhes': con.result})

    return jsonify(resultados), 200



### Remove usuário de um grupo ###
@app.route('/api/remove-usuario-grupo', methods=['POST'])
def remove_usuario_grupo():
    data = request.get_json()  # Captura o JSON da requisição
    if not data:
        return jsonify({'mensagem': 'Requisição inválida, JSON esperado'}), 400

    login = data.get('login')
    grupo = data.get('grupo')

    if not login or not grupo:
        return jsonify({'mensagem': 'Login ou parâmetro do grupo não fornecido'}), 400

    # Buscar DN do usuário
    user_filter_str = f"(sAMAccountName={login})"
    user_attributes = ['distinguishedName']
    con.search(base_dn, user_filter_str, attributes=user_attributes)

    if len(con.entries) == 0:
        return jsonify({'mensagem': 'Usuário não encontrado'}), 404
    else:
        user_entry = con.entries[0]
        if 'distinguishedName' not in user_entry:
            return jsonify({'mensagem': 'DN do usuário não encontrado'}), 404

        user_dn = user_entry['distinguishedName'].value

    # Determina se o parâmetro é um email ou um CN
    if "@" in grupo:
        group_filter_str = f"(mail={grupo})"
    else:
        group_filter_str = f"(cn={grupo})"

    # Buscar DN do grupo
    group_attributes = ['distinguishedName']
    con.search(base_dn, group_filter_str, attributes=group_attributes)

    if len(con.entries) == 0:
        return jsonify({'mensagem': 'Grupo não encontrado'}), 404
    else:
        group_entry = con.entries[0]
        if 'distinguishedName' not in group_entry:
            return jsonify({'mensagem': 'DN do grupo não encontrado'}), 404

        grupo = group_entry['distinguishedName'].value

    # Adicionar usuário ao grupo
    con.modify(grupo, {'member': [(MODIFY_DELETE, [user_dn])]})

    if con.result['result'] == 0:
        return jsonify({'mensagem': 'Usuário removido com sucesso'}), 200
    else:
        return jsonify({'mensagem': 'Falha ao remover usuário do grupo', 'detalhes': con.result})


### Remove um ou mais grupos ###
@app.route('/api/remove-usuario-grupos', methods=['POST'])
def remove_usuario_grupos():
    data = request.get_json()  # Captura o JSON da requisição
    if not data:
        return jsonify({'mensagem': 'Requisição inválida, JSON esperado'}), 400

    login = data.get('login')
    grupos = data.get('grupos')

    if not login or not grupos:
        return jsonify({'mensagem': 'Login ou parâmetros dos grupos não fornecidos'}), 400

    if not isinstance(grupos, list):
        return jsonify({'mensagem': 'O parâmetro grupos deve ser uma lista'}), 400

    # Buscar DN do usuário
    user_filter_str = f"(sAMAccountName={login})"
    user_attributes = ['distinguishedName']
    con.search(base_dn, user_filter_str, attributes=user_attributes)

    if len(con.entries) == 0:
        return jsonify({'mensagem': 'Usuário não encontrado'}), 404
    else:
        user_entry = con.entries[0]
        if 'distinguishedName' not in user_entry:
            return jsonify({'mensagem': 'DN do usuário não encontrado'}), 404

        user_dn = user_entry['distinguishedName'].value

    # Loop through each group and attempt to remove the user
    resultados = []
    for grupo in grupos:
        # Determina se o parâmetro é um email ou um CN
        if "@" in grupo:
            group_filter_str = f"(mail={grupo})"
        else:
            group_filter_str = f"(cn={grupo})"

        # Buscar DN do grupo
        group_attributes = ['distinguishedName']
        con.search(base_dn, group_filter_str, attributes=group_attributes)

        if len(con.entries) == 0:
            resultados.append({'grupo': grupo, 'mensagem': 'Grupo não encontrado', 'status': 'falha'})
            continue

        group_entry = con.entries[0]
        if 'distinguishedName' not in group_entry:
            resultados.append({'grupo': grupo, 'mensagem': 'DN do grupo não encontrado', 'status': 'falha'})
            continue

        grupo_dn = group_entry['distinguishedName'].value

        # Remover usuário do grupo
        con.modify(grupo_dn, {'member': [(MODIFY_DELETE, [user_dn])]})

        if con.result['result'] == 0:
            resultados.append({'grupo': grupo, 'mensagem': 'Usuário removido com sucesso', 'status': 'sucesso'})
        else:
            resultados.append({'grupo': grupo, 'mensagem': 'Falha ao remover usuário do grupo', 'detalhes': con.result, 'status': 'falha'})

    return jsonify(resultados), 200



if __name__ == '__main__':
    app.run(debug=True)
