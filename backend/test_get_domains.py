import os
import sys

# bypass PostgreSQL locally
if 'DATABASE_URL' in os.environ:
    del os.environ['DATABASE_URL']

sys.path.append(os.path.dirname(__file__))

from database import SessionLocal, get_dangerous_domains

if __name__ == '__main__':
    db = SessionLocal()
    try:
        domains = get_dangerous_domains(db, 10)
        print("Success!", len(domains), "domains found.")
    except Exception as e:
        print("Error:", e)
    finally:
        db.close()
