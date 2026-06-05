from . import types

secrets: dict[str, types.JSON] = {}


def get(name: str) -> types.JSON:
    return secrets.get(name)


def set(name: str, value: types.JSON) -> None:
    secrets[name] = value
