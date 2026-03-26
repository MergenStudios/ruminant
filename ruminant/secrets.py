secrets = {}


def get(name):
    return secrets.get(name)


def set(name, value):
    secrets[name] = value
