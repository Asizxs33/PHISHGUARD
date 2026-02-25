"""
PhishGuard AI — Database Module
PostgreSQL (Neon) database for storing analysis history.
Falls back to SQLite for local development if DATABASE_URL is not set.
"""

import os
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# ─── Database URL Configuration ─────────────────────────────────────────
# Priority: DATABASE_URL env var (Neon PostgreSQL) → fallback to SQLite

DATABASE_URL = os.environ.get('DATABASE_URL')

if DATABASE_URL:
    # Neon/Render often provide postgres:// but SQLAlchemy needs postgresql://
    if DATABASE_URL.startswith('postgres://'):
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
    
    # Add sslmode for Neon (required)
    if 'sslmode' not in DATABASE_URL:
        separator = '&' if '?' in DATABASE_URL else '?'
        DATABASE_URL = f'{DATABASE_URL}{separator}sslmode=require'
    
    engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_size=5, max_overflow=10)
    print(f"✅ Connected to PostgreSQL (Neon)")
else:
    # Fallback: SQLite for local development
    db_path = os.path.join(os.path.dirname(__file__), 'phishguard.db')
    engine = create_engine(f'sqlite:///{db_path}', connect_args={"check_same_thread": False})
    print(f"⚠️ Using SQLite (local): {db_path}")

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class AnalysisHistory(Base):
    """Model for storing analysis history."""
    __tablename__ = 'analysis_history'

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_type = Column(String(20), nullable=False)  # url, email, qr
    input_data = Column(Text, nullable=False)
    score = Column(Float, nullable=False)
    verdict = Column(String(20), nullable=False)
    details = Column(Text, nullable=True)  # JSON string
    timestamp = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'type': self.analysis_type,
            'input': self.input_data[:200],
            'score': self.score,
            'verdict': self.verdict,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }


class DangerousDomain(Base):
    """Model for storing confirmed dangerous domains separated from general history."""
    __tablename__ = 'dangerous_domains'

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain = Column(String(255), nullable=False, unique=True)
    source = Column(String(50), default="user_check")  # e.g., user_check, telegram_bot
    risk_level = Column(String(20), nullable=True)     # e.g., phishing, critical
    forensics_data = Column(Text, nullable=True)       # JSON string of gathered forensics
    timestamp = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'domain': self.domain,
            'source': self.source,
            'risk_level': self.risk_level,
            'forensics_data': self.forensics_data,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }


def init_db():
    """Create all tables."""
    Base.metadata.create_all(bind=engine)
    print("✅ Database tables ready")


def get_db():
    """Get database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def save_analysis(db, analysis_type: str, input_data: str,
                  score: float, verdict: str, details: str = None):
    """Save an analysis result to the database."""
    record = AnalysisHistory(
        analysis_type=analysis_type,
        input_data=input_data,
        score=score,
        verdict=verdict,
        details=details,
        timestamp=datetime.utcnow()
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def get_history(db, limit: int = 50, analysis_type: str = None):
    """Get recent analysis history."""
    query = db.query(AnalysisHistory)
    if analysis_type:
        query = query.filter(AnalysisHistory.analysis_type == analysis_type)
    results = query.order_by(AnalysisHistory.timestamp.desc()).limit(limit).all()
    return [r.to_dict() for r in results]


def get_stats(db):
    """Get aggregate statistics."""
    total = db.query(AnalysisHistory).count()
    safe = db.query(AnalysisHistory).filter(AnalysisHistory.verdict == 'safe').count()
    suspicious = db.query(AnalysisHistory).filter(AnalysisHistory.verdict == 'suspicious').count()
    phishing = db.query(AnalysisHistory).filter(AnalysisHistory.verdict == 'phishing').count()

    url_count = db.query(AnalysisHistory).filter(AnalysisHistory.analysis_type == 'url').count()
    email_count = db.query(AnalysisHistory).filter(AnalysisHistory.analysis_type == 'email').count()
    qr_count = db.query(AnalysisHistory).filter(AnalysisHistory.analysis_type == 'qr').count()

    return {
        'total_analyses': total,
        'safe': safe,
        'suspicious': suspicious,
        'phishing': phishing,
        'by_type': {
            'url': url_count,
            'email': email_count,
            'qr': qr_count
        }
    }


def save_dangerous_domain(db, domain: str, source: str = "user_check", risk_level: str = "phishing", forensics_data: str = None):
    """Save a confirmed dangerous domain to the database."""
    # Check if domain already exists
    existing = db.query(DangerousDomain).filter(DangerousDomain.domain == domain).first()
    if existing:
        if forensics_data and not existing.forensics_data:
            existing.forensics_data = forensics_data
            db.commit()
            db.refresh(existing)
        return existing
    
    record = DangerousDomain(
        domain=domain,
        source=source,
        risk_level=risk_level,
        forensics_data=forensics_data,
        timestamp=datetime.utcnow()
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def get_dangerous_domains(db, limit: int = 100):
    """Get the list of dangerous domains."""
    results = db.query(DangerousDomain).order_by(DangerousDomain.timestamp.desc()).limit(limit).all()
    return [r.to_dict() for r in results]
