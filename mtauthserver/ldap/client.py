from typing import Set, List, Dict, Optional
from ldap3 import Connection, SUBTREE, BASE
from flask import current_app

def get_user_dn(conn: Connection, username: str) -> Optional[str]:
    """
    Search for a user and return their Distinguished Name (DN).
    """
    search_filter = current_app.config['USERFILTER'].format(username)
    conn.search(
        current_app.config['SEARCHBASE'],
        search_filter, 
        search_scope=SUBTREE, 
        attributes=['distinguishedName']
    )
    if len(conn.entries) == 1:
        return conn.entries[0].entry_dn
    return None

def find_inherited_groups(conn: Connection, entry_dn: str, all_groups: Set[str]) -> None:
    """
    Recursively finds all inherited groups for a given DN.
    """
    conn.search(entry_dn, '(objectClass=*)', search_scope=BASE, attributes=['memberOf'])
    if conn.entries:
        for group_dn in conn.entries[0].memberOf:
            if group_dn not in all_groups:
                all_groups.add(group_dn)
                find_inherited_groups(conn, group_dn, all_groups)

def get_group_cns(conn: Connection, group_dns: List[str]) -> List[str]:
    """
    Retrieve the common names (CNs) of the groups.
    """
    group_cns = []
    for group_dn in group_dns:
        conn.search(group_dn, '(objectClass=*)', search_scope=BASE, attributes=['cn'])
        if conn.entries:
            group_cns.append(str(conn.entries[0].cn))
    return group_cns

def get_groups_of_user(conn: Connection, username: str) -> List[str]:
    """
    Get all groups (including inherited) for a given user.
    """
    user_dn = get_user_dn(conn, username)
    if not user_dn:
        return []

    all_group_dns: Set[str] = set()
    find_inherited_groups(conn, user_dn, all_group_dns)
    return get_group_cns(conn, list(all_group_dns))

def get_user_attributes(conn: Connection, username: str) -> Dict[str, str]:
    """
    Retrieve additional user attributes from LDAP.
    """
    search_filter = current_app.config['USERFILTER'].format(username)
    conn.search(
        current_app.config['SEARCHBASE'],
        search_filter, 
        search_scope=SUBTREE, 
        attributes=['cn', 'mail', 'displayName']
    )

    if len(conn.entries) != 1:
        return {}

    entry = conn.entries[0]
    return {
        "cn": str(entry.cn) if 'cn' in entry else "",
        "mail": str(entry.mail) if 'mail' in entry else "",
        "displayName": str(entry.displayName) if 'displayName' in entry else ""
    }
