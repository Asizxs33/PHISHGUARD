import sys
import os

sys.path.append(os.path.dirname(__file__))

from database import init_db

if __name__ == '__main__':
    print("Running init_db...")
    init_db()
    print("Done.")
