from .connection import get_ldap_connection
from .client import get_groups_of_user, get_user_attributes


def fetch_user_data(username: str):
    conn = get_ldap_connection()
    groups = get_groups_of_user(conn, username)
    attributes = get_user_attributes(conn, username)
    return groups, attributes
