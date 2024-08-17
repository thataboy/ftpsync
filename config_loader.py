from configobj import ConfigObj
from crypty import encrypt
import re
from constants import ENCRYPT_PASSWORD, REQUIRED_VALUES, ROOT_PROFILE
import os


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


def gather_profiles(config, profiles, is_root=False):
    """gather all sections and subsections into a flat unnested dict"""
    if is_root:
        scalars = config.scalars
        # if the root settings have all the required values,
        # create a profile for it named ROOT_PROFILE
        if len(REQUIRED_VALUES.difference(scalars)) == 0:
            profiles[ROOT_PROFILE] = {key:config[key] for key in scalars}
    parent = config.parent
    for sect in parent.sections:
        section = parent[sect]
        scalars = section.scalars
        profiles[sect] = {key:section[key] for key in scalars}
        for subsect in section.sections:
            gather_profiles(section[subsect], profiles)


def lint_profile(name, profile):
    if profile.get('ignore_regex'):
        try:
            profile['ignore_regex'] = re.compile(profile['ignore_regex'])
        except Exception as e:
            print(f"Warning: {name} has bad regex:\n     {profile['ignore_regex']}\n{e}. Ignoring")
            profile['ignore_regex'] = None

    missing = REQUIRED_VALUES.difference(profile.keys())
    if len(missing) > 0:
        print(f'Warning: {name} is missing {missing}. Skipping.')
        return False

    local = profile.get('local')
    if local is not None:
        if local.startswith('~'):
            local = os.path.expanduser(local)
            profile['local'] = local
        if not os.path.isdir(local):
            print(f'Warning: {name} has invalid local folder {local}. Skipping.')
            return False
    return True


def load_config(file_path, argv):
    """Loads and processes config ini
    Args:
        file_path: The path to the INI file.
        argv: command line arguments
    Returns: ConfigObj object
    Note: if ENCRYPT_PASSWORD: if True,
        change password=<value> to pwd=<encrypted value>
        and rewrite the ini file
    """
    config = ConfigObj(file_path, interpolation=False)

    if ENCRYPT_PASSWORD:
        dirty = encrypt_passwords(config, False)
        if dirty:
            config.write()

    cascade_values(config)

    profiles = {}
    gather_profiles(config, profiles, is_root=True)

    # get names of profiles from command line and filter out profiles not asked for
    names = ([ROOT_PROFILE] + list(profiles.keys())) if argv[1] == 'all' else argv[1:]
    profiles = {name: profiles[name] for name in names if profiles.get(name)}

    profiles = {name: profile for name, profile in profiles.items() if lint_profile(name, profile)}

    return profiles
