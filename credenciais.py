from ldap3 import Connection, Server

##### CONEXÃO COM O AD ######

server = Server("ldaps://contoso.com.br", use_ssl=True)

### Troque "user" por um usuário com privilégios, e coloque a senha em "senha_user"  ###
conexao = Connection(server, "CONTOSO\user", "senha_user", auto_bind=True)

##### AUTENTICAÇÃO API #####

### Crie seu token e coloque aqui ###
token_api = "seu_token"
