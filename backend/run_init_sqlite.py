import os
import sys

# Force local sqlite by clearing DATABASE_URL
if 'DATABASE_URL' in os.environ:
    del os.environ['DATABASE_URL']

sys.path.append(os.path.dirname(__file__))

from database import init_db
print("Running init_db for local sqlite...")
init_db()
print("Done.")
