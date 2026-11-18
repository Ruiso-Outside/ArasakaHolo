"""
ARASAKA HOLO // ponto de entrada.

  arasaka-holo                         abre o chat
  arasaka-holo --server=wss://host     abre usando outro servidor
  arasaka-holo --nick                  mostra seu nick eterno e sai
  python -m arasaka_holo.server        roda so o servidor (relay cego)
"""
import sys


def main() -> int:
    if "--nick" in sys.argv:
        from .identity import load_identity
        i = load_identity()
        print(f"{i.nick}   chave {i.fp}   ({i.source})")
        return 0
    from .app import main as gui
    return gui(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
