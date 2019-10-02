import os
import shutil
import sys
KEY_PATH = os.getenv("APPDATA") + "\\IDAHub\\key.pub"
KEY_DIR = os.getenv("APPDATA") + "\\IDAHub"

def main():
    if not os.path.exists(KEY_DIR):
        os.makedirs(KEY_DIR)
    shutil.move("key.pub", KEY_PATH)
    os.remove(sys.argv[0])

if __name__ == "__main__":
    main()