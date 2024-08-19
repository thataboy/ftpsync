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

# root section.name is None by default, use this name instead for friendliness
ROOT_NAME = '[default]'
# using this key for internal purpose, use [] to not clash with user's keys
WANTED_KEY = '[wanted]'


def encrypt_passwords(section, key, flag):
    """Encrypts passwords in a section."""
    if key == 'password':
        section['pwd'] = encrypt(section['password'])
        print(f'Password for {section.name or ROOT_NAME} encrypted.')
        # walk does not like it when you delete a value in the root section
        if section.parent is section:
            section['password'] = None
        else:
            del section['password']
        flag['dirty'] = True


def mark_wanted(parent, key, wanted, found):
    """mark sections given on command line"""

    section = parent[key]
    # walk with call_on_sections=True
    # ignore scalars, only checking for sections, i.e. dicts
    if isinstance(section, dict):
        if section.name in wanted:
            section[WANTED_KEY] = 1
            found.add(section.name)


def cascade_values(parent, key):
    """Cascade values from parent sections to all child sections recursively.
       if the corresponding values are missing in child section
    """
    section = parent[key]
    if isinstance(section, dict):
        for key in parent.scalars:
            if key not in section and key != 'password':
                section[key] = parent[key]


def gather_profiles(parent, key, take, profiles):
    """gather all sections and subsections into a flat unnested dict profiles
       take == {all|ALL|None}
    """
    section = parent[key]
    if isinstance(section, dict):
        if take == 'ALL' \
           or section.get(WANTED_KEY) \
           or take == 'all' and not section.get('disabled'):
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
                print(f"Error: {name} has bad regex:\n     {profile['ignore_regex']}\n{e}. Skipping")
            # profile['ignore_regex'] = None
            return False

    missing = REQUIRED_VALUES.difference(profile.keys())
    if len(missing) > 0:
        # root section is expected to have missing values, that's normal
        # if name != ROOT_NAME:
        #     print(f'Warning: {name} is missing {missing}. Skipping.')
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
    try:
        config = ConfigObj(file_path, interpolation=False)
    except Exception as e:
        print(f'Cannot load {file_path}:\n{e}')
        exit()

    if ENCRYPT_PASSWORD:
        flag = {'dirty': False}
        config.walk(encrypt_passwords, flag=flag)
        if flag['dirty']:
            # special handling for password appearing at the root
            if 'password' in config:
                del config['password']
            config.write()
            print(f'Changes written to {file_path}.')

    take = argv[1] if (argv[1] in ['ALL', 'all'] and len(argv) == 2) else None
    if not take:
        wanted = set(argv[1:])
        found = set()
        config.walk(mark_wanted, call_on_sections=True, wanted=wanted, found=found)
        wanted -= found
        if len(wanted) > 0:
            print(f'Warning: Unknown profile(s) {wanted}')

    config.walk(cascade_values, call_on_sections=True)

    profiles = {}
    config.walk(gather_profiles, call_on_sections=True, take=take, profiles=profiles)

    bad_regexes = set()
    profiles = {name: profile for name, profile in profiles.items()
                if lint_profile(name, profile, bad_regexes)}

    # print(profiles)
    # exit()
    return profiles
