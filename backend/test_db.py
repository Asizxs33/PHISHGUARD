import sys
import os

# add backend to path
sys.path.append(os.path.dirname(__file__))

from database import SessionLocal, get_dangerous_domains

def test():
    db = SessionLocal()
    try:
        domains = get_dangerous_domains(db, 10)
        print("Success!", len(domains), "domains found.")
        print(domains)
    except Exception as e:
        print("Error:", e)
    finally:
        db.close()

if __name__ == '__main__':
    test()
