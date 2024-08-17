ENCRYPT_PASSWORD = True

REQUIRED_VALUES = {
    "host",
    "user",
    "pwd" if ENCRYPT_PASSWORD else "password",
    "local", "remote"
}

ROOT_PROFILE = '<top>'
