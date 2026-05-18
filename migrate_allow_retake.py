from app import app, db
from sqlalchemy import text
with app.app_context():
    try:
        db.session.execute(text("ALTER TABLE training ADD COLUMN allow_retake BOOLEAN DEFAULT TRUE"))
        db.session.commit()
        print("✅ Coluna allow_retake adicionada com sucesso na tabela training!")
    except Exception as e:
        db.session.rollback()
        print(f"Aviso/Erro (provavelmente coluna já existe): {e}")
