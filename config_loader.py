from configobj import ConfigObj
from crypty import encrypt
import re
import os


ENCRYPT_PASSWORD = True
REQUIRED_VALUES = {
    "host",
    "user",
    "pwd" if ENCRYPT_PASSWORD else "password",
    "local", "remote"
}


def mark_wanted(config, wanted, found):
    """mark sections given on command line"""
    parent = config.parent
    for sect in parent.sections:
        section = parent[sect]
        if sect in wanted:
            section['wanted'] = 1
            found.add(sect)
        for subsect in section.sections:
            mark_wanted(section[subsect], wanted, found)


def cascade_values(config):
    """Cascade values from parent sections to all child sections recursively.
       if the corresponding values are missing in child section
    """
    parent = config.parent
    for sect in parent.sections:
        section = parent[sect]
        for key in parent.scalars:
            if key not in section:
                section[key] = parent[key]
        for subsect in section.sections:
            cascade_values(section[subsect])


def encrypt_passwords(config, dirty_in):
    """walk through tree and encrypt plain passwords
       returns True if changes were made
    """
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


def gather_profiles(config, take, profiles):
    """gather all sections and subsections into a flat unnested dict profiles
       take = all was specified on command line
    """
    parent = config.parent
    for sect in parent.sections:
        section = parent[sect]
        if take == 'ALL' \
           or section.get('wanted') \
           or take == 'all' and not section.get('disabled'):
            scalars = section.scalars
            profiles[sect] = {key: section[key] for key in scalars}
        for subsect in section.sections:
            gather_profiles(section[subsect], take, profiles)


def lint_profile(name, profile, bad_regexes):
    """does some basic validation
       returns True if profile is valid
       bad_regexes keep tracks of bad regexes to avoid duplicative warnings
    """
    if profile.get('ignore_regex'):
        try:
            profile['ignore_regex'] = re.compile(profile['ignore_regex'])
        except Exception as e:
            if profile['ignore_regex'] not in bad_regexes:
                bad_regexes.add(profile['ignore_regex'])
                print(f"Warning: {name} has bad regex:\n     {profile['ignore_regex']}\n{e}. Ignoring")
            profile['ignore_regex'] = None

    missing = REQUIRED_VALUES.difference(profile.keys())
    if len(missing) > 0:
        print(f'Warning: {name} is missing {missing}. Skipping.')
        return False

    local = profile['local']
    if local.startswith('~'):
        local = os.path.expanduser(local)
        profile['local'] = local
    if not os.path.isdir(local):
        print(f'Error: {name} has invalid local folder {local}. Skipping.')
        return False

    return True


def load_config(file_path, argv):
    """Loads and processes config ini
    Args:
        file_path: The path to the INI file.
        argv: command line arguments
    Returns: dict of valid, wqnted profiles
    Note: if ENCRYPT_PASSWORD: if True,
        change password=<value> to pwd=<encrypted value>
        and rewrite the ini file
    """
    config = ConfigObj(file_path, interpolation=False)

    if ENCRYPT_PASSWORD:
        dirty = encrypt_passwords(config, dirty_in=False)
        if dirty:
            config.write()

    take = argv[1] if (argv[1] in ['ALL', 'all'] and len(argv) == 2) else None
    if not take:
        wanted = set(argv[1:])
        found = set()
        mark_wanted(config, wanted, found)
        wanted -= found
        if len(wanted) > 0:
            print(f'Warning: Unknown profile(s) {wanted}')

    cascade_values(config)

    profiles = {}
    gather_profiles(config, take, profiles)

    bad_regexes = set()
    profiles = {name: profile for name, profile in profiles.items()
                if lint_profile(name, profile, bad_regexes)}

    # print(profiles.keys())
    # exit()

    return profiles
