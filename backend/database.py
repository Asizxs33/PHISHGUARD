"""
PhishGuard AI — Database Module
SQLite database for storing analysis history.
"""

import os
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# On Render, filesystem is read-only except /tmp
if os.environ.get('RENDER'):
    DATABASE_URL = '/tmp/phishguard.db'
else:
    DATABASE_URL = os.path.join(os.path.dirname(__file__), 'phishguard.db')

engine = create_engine(f'sqlite:///{DATABASE_URL}', connect_args={"check_same_thread": False})
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


def init_db():
    """Create all tables."""
    Base.metadata.create_all(bind=engine)


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
