from apiflask import APIFlask


# type-checks and conversions
def validate_and_convert(app: APIFlask):
    bool_keys = [
        'LDAP_TLS_VERIFY',
        'DEBUG', 'PROXY_FIX'
    ]
    int_keys = ['TOKEN_LIFETIME', 'PORT', 'REKEY_MAX_COUNT', 'REKEY_MAX_TIME_DIFF']
    str_keys = [
        'BINDDN', 'BINDPASSWORD',
        'SEARCHBASE', 'USERFILTER', 'GROUPFILTER',
        'JWT_PRIVATE_KEY', 'JWT_PUBLIC_KEY'
    ]
    str_list_keys = ['LDAP_SERVERS']

    for key in bool_keys:
        val = app.config.get(key)
        if isinstance(val, str):
            app.config[key] = val.lower() in ('true', '1', 't', 'y', 'yes')

    for key in int_keys:
        val = app.config.get(key)
        if val is not None:
            try:
                app.config[key] = int(val)
            except ValueError:
                raise Exception(f"Invalid value for {key}. Must be an integer.")

    for key in str_keys:
        val = app.config.get(key)
        if not val:
            raise Exception(f"Missing required config: {key}")

    for key in str_list_keys:
        val = app.config.get(key)
        if val:
            app.config[key] = val.split(',')
            if len(app.config[key]) == 0:
                raise Exception(f"Invalid value for {key}. Must be a comma-separated list with at least one element.")


def load_config(app: APIFlask):
    # default config
    app.config.from_mapping(
        PORT=8080,
        PROXY_FIX=True,

        # ldap servers
        LDAP_SERVERS=None,
        LDAP_TLS_VERIFY=False,

        # bind user
        BINDDN=None,
        BINDPASSWORD=None,

        # ldap queries
        SEARCHBASE=None,
        USERFILTER='(sAMAccountName={})',
        GROUPFILTER='(&(objectClass=group)(member={}))',

        # jwt
        TOKEN_LIFETIME=3600,
        JWT_PRIVATE_KEY=None,
        JWT_PUBLIC_KEY=None,

        # rekeying
        REKEY_MAX_COUNT=5,
        REKEY_MAX_TIME_DIFF=86400,  # 24 hours

        DEBUG=False,
    )

    # load config from env variables with prefix MAS_AUTH_
    # overwrite the default loads, to keep properties as strings instead of doing a JSON parse
    app.config.from_prefixed_env(prefix='MAS_AUTH', loads=lambda x: x)

    validate_and_convert(app)
