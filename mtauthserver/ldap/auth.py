from ldap3 import Connection, RESTARTABLE
import logging

from .client import get_user_dn
from .connection import get_ldap_pool, get_ldap_connection


def _check_credentials(conn: Connection, username: str, password: str) -> bool:
    """
    Check if the user can authenticate with the provided password.
    Creates a temporary connection for the user to avoid rebinding the main connection.

    :param conn: The main LDAP connection object
    :param username: The username to authenticate
    :param password: The password to authenticate with
    :return: True if authentication succeeds, False otherwise
    """
    user_dn = get_user_dn(conn, username)
    if not user_dn:
        return False

    try:
        # Create a temporary connection to verify credentials
        temp_conn = Connection(
            get_ldap_pool(),
            user=user_dn,
            password=password,
            auto_bind=True,
            client_strategy=RESTARTABLE
        )
        # If auto_bind=True, and it didn't raise, then authentication succeeded
        temp_conn.unbind()
        return True
    except Exception as e:
        logging.error(f"LDAP authentication failed for DN {user_dn}: {e}")
        return False

def check_credentials(username: str, password: str) -> bool:
    conn = get_ldap_connection()
    return _check_credentials(conn, username, password)
