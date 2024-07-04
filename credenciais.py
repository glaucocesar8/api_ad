from ldap3 import Connection, Server

##### CONEXÃO COM O AD ######

server = Server("ldaps://intra.epgnet.com.br", use_ssl=True)
conexao = Connection(server, "EPGNET\\nia", "uV<9>Ft7LK0t8", auto_bind=True)

##### AUTENTICAÇÃO API #####

token_api = "nwpaqnw7SvSY45Dry8i6520498495b49"
