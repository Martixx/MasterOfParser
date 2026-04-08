import os
from datetime import datetime
import sys
import glob

HIST_DIR = "chat_history"

os.makedirs(HIST_DIR, exist_ok=True)

def save_chat_entry(entry: str):
    now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"{now}_chat.txt"
    path = os.path.join(HIST_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(entry)
    print(f"Conversación guardada en: {path}")

def show_last_chat():
    files = sorted(glob.glob(os.path.join(HIST_DIR, '*_chat.txt')))
    if not files:
        print('No hay chats guardados.')
        return
    last = files[-1]
    print(f'Último chat guardado: {last}\n')
    with open(last, 'r', encoding='utf-8') as f:
        print(f.read())

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Permite guardar todo el chat pasado por argumento
        save_chat_entry(" ".join(sys.argv[1:]))
    else:
        show_last_chat()
        print("\nIntroduce el texto de la conversación. Finaliza con una línea vacía:")
        lines = []
        while True:
            line = input()
            if not line:
                break
            lines.append(line)
        save_chat_entry("\n".join(lines))
