from typing import List, Tuple, Dict

from shared_util import MTAuthUser
from .connection import get_ldap_connection
from .client import get_groups_of_user, get_user_attributes


def _fetch_user_data(username: str) -> Tuple[List[str], Dict[str, str]]:
    conn = get_ldap_connection()
    groups = get_groups_of_user(conn, username)
    attributes = get_user_attributes(conn, username)
    return groups, attributes

def fetch_user(username: str) -> MTAuthUser:
    groups, attributes = _fetch_user_data(username)
    return MTAuthUser(username, groups, attributes)
