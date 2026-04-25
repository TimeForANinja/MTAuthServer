from typing import Optional, Any
import yaml
import os
from dotenv import load_dotenv

class Config:
    """
    Configuration class for MTAuthServer.
    Loads settings from a YAML file and allows overrides via environment variables.
    """
    ldap_server: Optional[str]  # Primary LDAP server URL (e.g., ldaps://server:636)
    ldap_server2: Optional[str] # Secondary LDAP server URL (optional)
    ldap_tls_verify: bool       # Whether to verify TLS certificate for primary LDAP server
    ldap_tls_verify2: bool      # Whether to verify TLS certificate for secondary LDAP server
    bind_dn: Optional[str]      # Distinguished Name for LDAP bind (admin user)
    bind_password: Optional[str] # Password for LDAP bind
    search_base: Optional[str]   # Base DN for user and group searches
    user_filter: str            # Filter for finding users (default: (sAMAccountName=%s))
    group_filter: str           # Filter for finding groups (default: (&(objectClass=group)(member=%s)))
    secret_key: str             # Secret key for signing JWT tokens
    log_to_file: bool           # Whether to enable logging to a file
    log_file: str               # Path to the log file
    debug: bool                 # Whether to enable debug mode

    def __init__(self, config_path: str = "config.yaml") -> None:
        """
        Initializes the Config object by loading data from the specified YAML file
        and environment variables.
        
        Args:
            config_path: The path to the configuration YAML file. Defaults to "config.yaml".
        """
        load_dotenv()
        data: dict[str, Any] = {}
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                data = yaml.safe_load(f) or {}
            
        self.ldap_server = os.environ.get('LDAP_SERVER') or data.get('LdapServer')
        self.ldap_server2 = os.environ.get('LDAP_SERVER2') or data.get('LdapServer2')
        self.ldap_tls_verify = self._get_bool('LDAP_TLS_VERIFY', data.get('LdapTLSVerify', False))
        self.ldap_tls_verify2 = self._get_bool('LDAP_TLS_VERIFY2', data.get('LdapTLSVerify2', False))
        self.bind_dn = os.environ.get('BIND_DN') or data.get('BindDN')
        self.bind_password = os.environ.get('BIND_PASSWORD') or data.get('BindPassword')
        self.search_base = os.environ.get('SEARCH_BASE') or data.get('SearchBase')
        self.user_filter = os.environ.get('USER_FILTER') or data.get('UserFilter', '(sAMAccountName=%s)')
        self.group_filter = os.environ.get('GROUP_FILTER') or data.get('GroupFilter', '(&(objectClass=group)(member=%s))')
        self.secret_key = os.environ.get('SECRET_KEY') or data.get('SecretKey', 'supersecretkey')
        self.log_to_file = self._get_bool('LOG_TO_FILE', data.get('LogtoFile', False))
        self.log_file = os.environ.get('LOG_FILE') or data.get('LogFile', 'logs/mtauthserver.log')
        self.debug = self._get_bool('DEBUG', data.get('Debug', False))

    def _get_bool(self, env_name: str, default: bool) -> bool:
        val = os.environ.get(env_name)
        if val is None:
            return default
        return val.lower() in ('true', '1', 't', 'y', 'yes')

_config: Optional[Config] = None

def load_config() -> Config:
    """
    Singleton function to load and return the application configuration.
    
    Returns:
        The Config instance.
    """
    global _config
    if _config is None:
        _config = Config()
    return _config
