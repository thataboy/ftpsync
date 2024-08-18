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
ROOT_NAME = '[default]'


def encrypt_passwords(section, key, flag):
    """Encrypts passwords in a section."""
    if key == 'password' and section['password']:
        section['pwd'] = encrypt(section['password'])
        # walk does not like it when you delete a value in the root section
        if section.parent is section:
            section['password'] = None
        else:
            del section['password']
        flag['dirty'] = True


def mark_wanted(section, _, wanted, found):
    """mark sections given on command line"""
    if section.name in wanted:
        section['wanted'] = 1
        found.add(section.name)


def cascade_values(section, _):
    """Cascade values from parent sections to all child sections recursively.
       if the corresponding values are missing in child section
    """
    parent = section.parent
    if parent is section:
        return
    for key in parent.scalars:
        if key not in section and key != 'password':
            section[key] = parent[key]


def gather_profiles(section, _, take, profiles):
    """gather all sections and subsections into a flat unnested dict profiles
       take = all or ALL was specified on command line
    """
    if take == 'ALL' \
       or section.get('wanted') \
       or take == 'all' and not section.get('disabled'):
        if section.name not in profiles:
            profiles[section.name or ROOT_NAME] = \
                     {key: section[key] for key in section.scalars}


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
        # root section is expected to have missing values, that's normal
        if name != ROOT_NAME:
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
        flag = {'dirty': False}
        config.walk(encrypt_passwords, flag=flag)
        if flag['dirty']:
            # special handling for password appearing at the root
            if 'password' in config:
                del config['password']
            config.write()

    take = argv[1] if (argv[1] in ['ALL', 'all'] and len(argv) == 2) else None
    if not take:
        wanted = set(argv[1:])
        found = set()
        config.walk(mark_wanted, wanted=wanted, found=found)
        wanted -= found
        if len(wanted) > 0:
            print(f'Warning: Unknown profile(s) {wanted}')

    config.walk(cascade_values)

    profiles = {}
    config.walk(gather_profiles, take=take, profiles=profiles)

    bad_regexes = set()
    profiles = {name: profile for name, profile in profiles.items()
                if lint_profile(name, profile, bad_regexes)}

    return profiles
