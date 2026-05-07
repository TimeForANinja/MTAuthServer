from ldap3 import Server, ServerPool, Connection, ALL, Tls, RESTARTABLE, FIRST
from flask import g, current_app


def get_ldap_connection() -> Connection:
    """
    Get or create an LDAP connection stored in Flask's 'g' object.

    :return: The LDAP connection
    """
    if 'ldap_conn' not in g:
        conn = Connection(
            get_ldap_pool(),
            user=current_app.config['BINDDN'],
            password=current_app.config['BINDPASSWORD'],
            auto_bind=True,
            client_strategy=RESTARTABLE
        )

        if not conn.bind():
             raise Exception("Failed to bind to any LDAP server in the pool")

        g.ldap_conn = conn
    return g.ldap_conn

def get_ldap_pool() -> ServerPool:
    """
    Get or create an LDAP server pool stored in Flask's 'g' object.

    :return: The LDAP server pool
    """
    if 'ldap_pool' not in g:
        servers = []
        for server in current_app.config['LDAP_SERVERS']:
            servers.append(Server(
                server,
                use_ssl=current_app.config['LDAP_TLS_VERIFY'],
                get_info=ALL,
                tls=Tls(validate=0)
            ))

        if not servers:
            raise Exception("No LDAP servers configured")

        g.ldap_pool = ServerPool(servers, FIRST, active=True, exhaust=True)

    return g.ldap_pool