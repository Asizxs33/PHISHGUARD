import os
import sys

print("=========================================")
print("Neon Database Migration Script - ADD COLUMN")
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

    from sqlalchemy import create_engine, text
    engine = create_engine(db_url)
    
    print("⏳ Connecting to Neon Database...")
    
    # Connect and run raw SQL
    with engine.connect() as conn:
        # Check if the table exists first
        result = conn.execute(text("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'dangerous_domains');"))
        if not result.scalar():
            print("⚠️ Table dangerous_domains does not exist yet. Run create_neon_table.py instead.")
            sys.exit(0)

        # Check if column exists
        result = conn.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name='dangerous_domains' AND column_name='forensics_data';"))
        column_exists = result.scalar() is not None
        
        if not column_exists:
            print("🛠️ Adding missing 'forensics_data' column to 'dangerous_domains' table...")
            
            # Using transaction via `.begin()` to safely commit in SQLAlchemy 2.0+
            with engine.begin() as transaction:
                transaction.execute(text("ALTER TABLE dangerous_domains ADD COLUMN forensics_data TEXT;"))
            
            print("✅ Success! The 'forensics_data' column has been added.")
            print("The 500 error on the /api/dangerous-domains endpoint should now be resolved!")
        else:
            print("✅ The 'forensics_data' column already exists in the 'dangerous_domains' table.")
            
except Exception as e:
    print("❌ Failed to alter table in Neon:")
    print(e)
