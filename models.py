from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class System(db.Model):
    __tablename__ = "systems"
    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(120), nullable=False)
    url         = db.Column(db.String(512), nullable=False)
    criticality = db.Column(db.String(16), default="medium")
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    note = db.Column(db.Text)


