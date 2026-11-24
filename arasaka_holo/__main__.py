"""
ARASAKA HOLO // ponto de entrada.

  arasaka-holo                         abre o chat
  arasaka-holo --server=wss://host     abre usando outro servidor
  arasaka-holo --nick                  mostra seu nick eterno e sai
  arasaka-holo --diag                  testa a conexao com o servidor e sai
  python -m arasaka_holo.server        roda so o servidor (relay cego)
"""
import sys


def main() -> int:
    if "--nick" in sys.argv:
        from .identity import load_identity
        i = load_identity()
        print(f"{i.nick}   chave {i.fp}   ({i.source})")
        return 0
    if "--diag" in sys.argv:
        from .diag import run
        url = next((a.split("=", 1)[1] for a in sys.argv if a.startswith("--server=")), "https://piphin.online/")
        print(run(url))
        return 0
    try:
        from .app import main as gui
        return gui(sys.argv)
    except Exception as e:  # noqa: BLE001      sem terminal (pythonw), um erro ao abrir sumiria sem aviso
        if sys.platform == "win32":
            import ctypes
            ctypes.windll.user32.MessageBoxW(None, f"O HOLO nao conseguiu abrir:\n\n{type(e).__name__}: {e}\n\n"
                                             "Rode o install.bat de novo.", "ARASAKA HOLO", 0x10)
        raise


if __name__ == "__main__":
    sys.exit(main())
