from app import app, db
from sqlalchemy import text
with app.app_context():
    try:
        db.session.execute(text("ALTER TABLE announcement ADD COLUMN target_company_id INTEGER REFERENCES company(id)"))
        db.session.commit()
        print("Coluna target_company_id adicionada em announcement!")
    except Exception as e:
        db.session.rollback()
        print(f"Erro ao adicionar coluna: {e}")
