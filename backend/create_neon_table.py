import os
import sys

# Usage: set DATABASE_URL=postgres://... && python create_neon_table.py

print("=========================================")
print("Neon Database Migration Script")
print("=========================================")

db_url = os.environ.get('DATABASE_URL')
if not db_url:
    print("❌ Error: DATABASE_URL environment variable is not set!")
    print("Please set it in your terminal before running this script.")
    print("Example (Windows PowerShell): $env:DATABASE_URL=\"postgres://your_neon_url\"")
    print("Example (Mac/Linux): export DATABASE_URL=\"postgres://your_neon_url\"")
    sys.exit(1)

try:
    if db_url.startswith('postgres://'):
        db_url = db_url.replace('postgres://', 'postgresql://', 1)
        
    if 'sslmode' not in db_url:
        separator = '&' if '?' in db_url else '?'
        db_url = f'{db_url}{separator}sslmode=require'

    from sqlalchemy import create_engine
    engine = create_engine(db_url)
    
    # Import the Base and models so SQLAlchemy knows what tables to create
    sys.path.append(os.path.dirname(__file__))
    from database import Base, DangerousDomain
    
    print("⏳ Connecting to Neon Database...")
    print("🛠️ Creating missing tables...")
    
    # This will safely create any tables defined in models that don't exist in the DB
    Base.metadata.create_all(bind=engine)
    
    print("✅ Success! The 'dangerous_domains' table has been created (if it didn't exist).")
    print("You should no longer get the 500 error on the /api/dangerous-domains endpoint.")
    
except Exception as e:
    print("❌ Failed to create tables in Neon:")
    print(e)
