import os
import sys

db_url = os.environ.get('DATABASE_URL')
print("DATABASE_URL is:", db_url)

if not db_url:
    print("No DATABASE_URL found.")
    sys.exit(0)

# Also try a quick connection test with a timeout
try:
    import sqlalchemy
    from sqlalchemy import create_engine
    
    if db_url.startswith('postgres://'):
        db_url = db_url.replace('postgres://', 'postgresql://', 1)
        
    if 'sslmode' not in db_url:
        separator = '&' if '?' in db_url else '?'
        db_url = f'{db_url}{separator}sslmode=require'
        
    # use a fast timeout for connection connect_args={"connect_timeout": 5}
    engine = create_engine(db_url, connect_args={"connect_timeout": 5})
    with engine.connect() as conn:
        print("Successfully connected to Neon.")
        
        # Check if table exists
        result = conn.execute(sqlalchemy.text("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'dangerous_domains');"))
        exists = result.scalar()
        print("Table dangerous_domains exists:", exists)
        
except Exception as e:
    print("Connection error:", e)
