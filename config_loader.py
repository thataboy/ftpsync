from configobj import ConfigObj
from crypty import encrypt


def cascade_values(config):
    """Cascade values from parent sections to all child sections recursively."""
    parent = config.parent
    for sect in parent.sections:
        section = parent[sect]
        for key in parent.scalars:
            if key not in section:
                section[key] = parent[key]
        for subsect in section.sections:
            cascade_values(section[subsect])


def encrypt_passwords(config, dirty_in):
    """walk through tree and encrypt plain passwords"""
    dirty = False or dirty_in
    if 'password' in config:
        config['pwd'] = encrypt(config['password'])
        del config['password']
        dirty = True
    for sect in config.sections:
        section = config[sect]
        if 'password' in section:
            section['pwd'] = encrypt(section['password'])
            del section['password']
            dirty = True
        for subsect in section.sections:
            dirty = dirty or encrypt_passwords(section[subsect], dirty)
    return dirty


def gather_profiles(config, profiles):
    """gather all sections and subsections into a flat unnested dict"""
    parent = config.parent
    for sect in parent.sections:
        section = parent[sect]
        profiles[sect] = {key:section[key] for key in section.scalars}
        for subsect in section.sections:
            gather_profiles(section[subsect], profiles)


def load_config(file_path, encrypt_password=False):
    """Loads config ini
    Args:
        file_path: The path to the INI file.
        encrypt_password: if True,
        change password=<value> to pwd=<encrypted value>
        and rewrite the ini file
    Returns: ConfigObj object
    """
    config = ConfigObj(file_path, interpolation=False)

    if encrypt_password:
        dirty = encrypt_passwords(config, False)
        if dirty:
            config.write()

    cascade_values(config)
    profiles = {}
    gather_profiles(config, profiles)

    return profiles
