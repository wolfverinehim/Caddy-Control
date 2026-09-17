from __future__ import annotations

import getpass

from .core import password_digest


def main() -> None:
    first = getpass.getpass("Contraseña: ")
    second = getpass.getpass("Repite la contraseña: ")
    if not first or first != second:
        raise SystemExit("Las contraseñas no coinciden o están vacías.")
    print(password_digest(first))


if __name__ == "__main__":
    main()
