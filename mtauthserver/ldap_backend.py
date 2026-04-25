from ldap3 import Server, Connection, ALL, Tls, SUBTREE
import ssl
from .config import load_config
import logging
from typing import List, Optional, Set

logger = logging.getLogger(__name__)

def connect_ldap() -> Optional[Connection]:
    cnf = load_config()
    
    servers: List[Optional[str]] = [cnf.ldap_server, cnf.ldap_server2]
    
    for server_url in servers:
        if not server_url:
            continue
        try:
            # Handle TLS if needed
            tls: Optional[Tls] = None
            if server_url.startswith('ldaps://'):
                # InsecureSkipVerify is equivalent to CERT_NONE in python ssl
                tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
            
            server: Server = Server(server_url, get_info=ALL, tls=tls)
            # We don't bind here yet, just check if we can connect
            conn: Connection = Connection(server, raise_exceptions=True)
            logger.info(f"Successfully configured LDAP server: {server_url}")
            return conn
        except Exception as e:
            logger.error(f"Failed to connect to LDAP server {server_url}: {e}")
            
    return None

def check_authentication(conn: Connection, username: str, password: str) -> bool:
    cnf = load_config()
    try:
        # 1. Bind with admin user
        conn.user = cnf.bind_dn
        conn.password = cnf.bind_password
        if not conn.bind():
            logger.error("LDAP admin bind failed")
            return False
            
        # 2. Search for the user DN
        search_filter: str = cnf.user_filter % username
        conn.search(cnf.search_base, search_filter, attributes=['dn'])
        
        if len(conn.entries) != 1:
            logger.error(f"User {username} not found or multiple entries found")
            return False
            
        user_dn: str = conn.entries[0].entry_dn
        
        # 3. Bind with user DN and provided password
        user_conn: Connection = Connection(conn.server, user=user_dn, password=password, raise_exceptions=True)
        if user_conn.bind():
            return True
        else:
            return False
    except Exception as e:
        logger.error(f"Error during LDAP authentication: {e}")
        return False

def find_inherited_groups(conn: Connection, user_dn: str, all_groups: Set[str]) -> None:
    try:
        conn.search(user_dn, '(objectClass=*)', search_scope=SUBTREE, attributes=['memberOf'])
        if len(conn.entries) > 0:
            for entry in conn.entries:
                if 'memberOf' in entry:
                    for group_dn in entry.memberOf:
                        if group_dn not in all_groups:
                            all_groups.add(group_dn)
                            find_inherited_groups(conn, group_dn, all_groups)
    except Exception as e:
        logger.error(f"Error finding inherited groups for {user_dn}: {e}")

def get_group_cns(conn: Connection, group_dns: List[str]) -> List[str]:
    group_cns: List[str] = []
    for dn in group_dns:
        try:
            conn.search(dn, '(objectClass=*)', attributes=['cn'])
            if len(conn.entries) > 0:
                group_cns.append(str(conn.entries[0].cn))
        except Exception as e:
            logger.error(f"Error getting CN for {dn}: {e}")
    return group_cns

def get_groups_of_user(conn: Connection, username: str) -> List[str]:
    cnf = load_config()
    all_groups: Set[str] = set()
    
    try:
        # Bind as admin if not already
        if not conn.bound:
            conn.user = cnf.bind_dn
            conn.password = cnf.bind_password
            conn.bind()
            
        search_filter: str = cnf.user_filter % username
        conn.search(cnf.search_base, search_filter, attributes=['dn'])
        
        if len(conn.entries) != 1:
            return []
            
        user_dn: str = conn.entries[0].entry_dn
        find_inherited_groups(conn, user_dn, all_groups)
        
        return get_group_cns(conn, list(all_groups))
    except Exception as e:
        logger.error(f"Error getting groups for {username}: {e}")
        return []
