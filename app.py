# -*- coding: utf-8 -*-
from flask import (
    Flask, render_template, request, redirect,
    flash, jsonify, url_for
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

# =====================================================
# CONFIGURAÇÃO DO APP
# =====================================================

app = Flask(__name__)
app.config["SECRET_KEY"] = "secreto"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"

# PASTAS EXISTENTES
app.config["UPLOAD_FOLDER"] = "static/uploads"
app.config["FOTOS_COLAB"] = "static/fotos"
app.config["LOGO_FOLDER"] = "static/logos"

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


# =====================================================
# MODELOS DO BANCO
# =====================================================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120))
    email = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(255))
    role = db.Column(db.String(20))  # admin / colaborador

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


class Company(db.Model):
    __tablename__ = "company"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    cnpj = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    active = db.Column(db.Boolean, default=True)
    logo = db.Column(db.String(255), nullable=True)


class Contract(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey("company.id"))
    description = db.Column(db.Text)
    start_date = db.Column(db.String(20))
    end_date = db.Column(db.String(20))
    status = db.Column(db.String(20), default="ativo")

    company = db.relationship("Company")


class ContractFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    contract_id = db.Column(db.Integer, db.ForeignKey("contract.id"))
    file_path = db.Column(db.String(255))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    contract_id = db.Column(db.Integer, db.ForeignKey("contract.id"))
    title = db.Column(db.String(120))
    description = db.Column(db.Text)
    due_date = db.Column(db.String(20))
    priority = db.Column(db.String(20), default="Normal")
    status = db.Column(db.String(20), default="pendente")

    assigned_to = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

    contract = db.relationship("Contract")
    assigned_user = db.relationship("User", backref="tarefas_recebidas")


class TaskLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey("task.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    note = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    task = db.relationship("Task", backref="logs")
    user = db.relationship("User")


class TaskFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_log_id = db.Column(db.Integer, db.ForeignKey("task_log.id"))
    file_path = db.Column(db.String(255))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    log = db.relationship("TaskLog", backref="files")


class Collaborator(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    matricula = db.Column(db.String(20), unique=True)
    nome = db.Column(db.String(150))
    email = db.Column(db.String(120), unique=True)
    telefone = db.Column(db.String(20))
    setor = db.Column(db.String(120))
    funcao = db.Column(db.String(120))
    foto = db.Column(db.String(255))
    ativo = db.Column(db.Boolean, default=True)
    password = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# =====================================================
# LOGIN MANAGER
# =====================================================

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# =====================================================
# CRIA ADMIN AUTOMÁTICO
# =====================================================

@app.before_request
def criar_admin_automatico():
    admin = User.query.filter_by(email="admin@admin.com").first()
    if not admin:
        novo = User(
            name="Administrador",
            email="admin@admin.com",
            password=generate_password_hash("123"),
            role="admin"
        )
        db.session.add(novo)
        db.session.commit()


# =====================================================
# RESUMO DO DASHBOARD
# =====================================================

def tarefas_por_empresa():
    dados = []
    hoje = datetime.today().strftime("%Y-%m-%d")

    empresas = Company.query.all()

    for emp in empresas:
        contratos = Contract.query.filter_by(company_id=emp.id, status="ativo").all()
        if not contratos:
            continue

        ids = [c.id for c in contratos]

        total = Task.query.filter(Task.contract_id.in_(ids)).count()
        concluidas = Task.query.filter(Task.contract_id.in_(ids), Task.status == "concluida").count()
        pendentes = Task.query.filter(Task.contract_id.in_(ids), Task.status == "pendente").count()
        atrasadas = Task.query.filter(
            Task.contract_id.in_(ids),
            Task.status == "pendente",
            Task.due_date < hoje
        ).count()

        dados.append({
            "empresa": emp,
            "contratos": len(contratos),
            "total": total,
            "concluidas": concluidas,
            "pendentes": pendentes,
            "atrasadas": atrasadas
        })

    return dados


# =====================================================
# DASHBOARD
# =====================================================

@app.route("/")
@login_required
def dashboard():
    if current_user.role == "colaborador":
        return redirect("/painel-colaborador")

    return render_template("dashboard.html", dados=tarefas_por_empresa())


# =====================================================
# LISTA DE CONTRATOS
# =====================================================

@app.route("/contracts")
@login_required
def lista_contratos():
    contracts = Contract.query.all()
    return render_template("contracts.html", contracts=contracts)


# =====================================================
# NOVO CONTRATO
# =====================================================

@app.route("/contracts/new", methods=["POST"])
@login_required
def new_contract():
    logo_file = request.files.get("logo")

    logo_path = None
    if logo_file and logo_file.filename != "":
        filename = secure_filename(logo_file.filename)

        folder = app.config["LOGO_FOLDER"]
        if not os.path.exists(folder):
            os.makedirs(folder)

        logo_path = os.path.join(folder, filename)
        logo_file.save(logo_path)

    company = Company(
        name=request.form["company"],
        cnpj=request.form["cnpj"],
        logo=logo_path
    )
    db.session.add(company)
    db.session.commit()

    contract = Contract(
        company_id=company.id,
        description=request.form["desc"],
        start_date=request.form["start"],
        end_date=request.form["end"],
        status="ativo"
    )
    db.session.add(contract)
    db.session.commit()

    flash("Contrato criado!", "success")
    return redirect("/contracts")
# =====================================================
# ENCERRAR CONTRATO
# =====================================================

@app.route("/contracts/end/<int:id>", methods=["POST"])
@login_required
def end_contract(id):
    data = request.get_json()
    senha = data.get("senha")

    if not check_password_hash(current_user.password, senha):
        return jsonify({"sucesso": False, "mensagem": "Senha incorreta"})

    contrato = Contract.query.get_or_404(id)
    contrato.status = "encerrado"
    db.session.commit()

    return jsonify({"sucesso": True})


# =====================================================
# EXCLUIR CONTRATO
# =====================================================

@app.route("/contracts/delete/<int:id>", methods=["POST"])
@login_required
def delete_contract(id):
    contrato = Contract.query.get_or_404(id)

    if contrato.status != "encerrado":
        return jsonify({
            "sucesso": False,
            "mensagem": "Só é possível excluir contratos encerrados"
        })

    # Remove arquivos vinculados
    arquivos = ContractFile.query.filter_by(contract_id=id).all()
    for arq in arquivos:
        try:
            if arq.file_path and os.path.exists(arq.file_path):
                os.remove(arq.file_path)
        except:
            pass
        db.session.delete(arq)

    db.session.delete(contrato)
    db.session.commit()

    return jsonify({"sucesso": True})


# =====================================================
# VISUALIZAÇÃO DO CONTRATO (TAREFAS, ARQUIVOS, COLABORADORES)
# =====================================================

@app.route("/contract/<int:id>")
@login_required
def contract_view(id):
    contr = Contract.query.get_or_404(id)
    files = ContractFile.query.filter_by(contract_id=id).all()

    colaboradores = User.query.filter_by(role="colaborador").order_by(User.name).all()

    # Admin vê tudo — colaborador vê apenas tarefas destinadas a ele ou "todas"
    if current_user.role == "admin":
        tasks = Task.query.filter_by(contract_id=id).order_by(Task.id.desc()).all()
    else:
        tasks = Task.query.filter(
            Task.contract_id == id,
            ((Task.assigned_to == current_user.id) | (Task.assigned_to == None))
        ).order_by(Task.id.desc()).all()

    # Converte datas
    for t in tasks:
        if isinstance(t.due_date, str) and t.due_date:
            try:
                t.due_date = datetime.strptime(t.due_date, "%Y-%m-%d").date()
            except:
                t.due_date = None

    return render_template(
        "contract_view.html",
        contract=contr,
        files=files,
        tasks=tasks,
        colaboradores=colaboradores,
        now=datetime.utcnow
    )


# =====================================================
# UPLOAD DE ARQUIVOS DO CONTRATO — AGORA MULTIPLO!
# =====================================================

@app.route("/contract/<int:id>/upload", methods=["POST"])
@login_required
def upload_file(id):

    # Pega todos arquivos enviados (input name="files[]")
    files = request.files.getlist("files[]")

    if not files or files == [""]:
        flash("Nenhum arquivo enviado!", "error")
        return redirect(f"/contract/{id}")

    # Garante pasta
    if not os.path.exists(app.config["UPLOAD_FOLDER"]):
        os.makedirs(app.config["UPLOAD_FOLDER"])

    for file in files:
        if file and file.filename:
            filename = secure_filename(file.filename)
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(save_path)

            # cria registro individual
            novo = ContractFile(
                contract_id=id,
                file_path=save_path
            )
            db.session.add(novo)

    db.session.commit()

    flash("Arquivo(s) enviado(s) com sucesso!", "success")
    return redirect(f"/contract/{id}")


# =====================================================
# EXCLUIR ARQUIVO DO CONTRATO
# =====================================================

@app.route("/contract/file/delete/<int:file_id>", methods=["POST"])
@login_required
def delete_contract_file(file_id):
    file = ContractFile.query.get_or_404(file_id)
    contract_id = file.contract_id

    try:
        if file.file_path and os.path.exists(file.file_path):
            os.remove(file.file_path)
    except:
        pass

    db.session.delete(file)
    db.session.commit()

    flash("Arquivo removido!", "success")
    return redirect(f"/contract/{contract_id}")


# =====================================================
# TAREFAS – CRIAR
# =====================================================

@app.route("/task/new/<int:contract_id>", methods=["POST"])
@login_required
def new_task(contract_id):
    title = request.form["title"]
    description = request.form.get("description", "")
    due_date = request.form["due_date"]
    priority = request.form.get("priority", "Normal")
    assigned_to_raw = request.form.get("assigned_to")

    assigned_to_value = None if assigned_to_raw in ["all", "", None] else int(assigned_to_raw)

    nova = Task(
        contract_id=contract_id,
        title=title,
        description=description,
        due_date=due_date,
        priority=priority,
        assigned_to=assigned_to_value
    )

    db.session.add(nova)
    db.session.commit()

    flash("Tarefa criada!", "success")
    return redirect(f"/contract/{contract_id}")
# =====================================================
# LOGS DA TAREFA (DETALHES)
# =====================================================

@app.route("/task/logs/<int:task_id>")
@login_required
def task_logs(task_id):
    log = TaskLog.query.filter_by(task_id=task_id).order_by(TaskLog.created_at.desc()).first()
    if not log:
        return jsonify({"erro": "Sem registros."})

    arquivos = [f.file_path for f in log.files] if log.files else []

    return jsonify({
        "user": log.user.name if log.user else "N/A",
        "data": log.created_at.strftime("%d/%m/%Y %H:%M"),
        "note": log.note,
        "priority": log.task.priority,
        "files": arquivos
    })


# =====================================================
# FINALIZAR TAREFA — SUPORTA MULTIPLOS ARQUIVOS
# =====================================================

@app.route("/task/complete/<int:task_id>", methods=["POST"])
@login_required
def complete_task(task_id):
    task = Task.query.get_or_404(task_id)
    note = request.form["note"]

    # arquivos enviados name="files[]"
    files = request.files.getlist("files[]")

    # cria log sem os arquivos ainda
    log = TaskLog(
        task_id=task.id,
        user_id=current_user.id,
        note=note
    )
    db.session.add(log)
    db.session.flush()  

    if files:
        if not os.path.exists(app.config["UPLOAD_FOLDER"]):
            os.makedirs(app.config["UPLOAD_FOLDER"])

        for f in files:
            if f and f.filename:
                filename = secure_filename(f.filename)
                save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                f.save(save_path)

                registro_arquivo = TaskFile(
                    task_log_id=log.id,
                    file_path=save_path
                )
                db.session.add(registro_arquivo)

    task.status = "concluida"
    db.session.commit()

    flash("Tarefa concluída!", "success")

    if current_user.role == "admin":
        return redirect(f"/contract/{task.contract_id}")

    return redirect("/painel-colaborador")


# =====================================================
# SALVAR FOTO DO COLABORADOR
# =====================================================

def salvar_foto(arquivo):
    if not arquivo or arquivo.filename == "":
        return None

    if not os.path.exists(app.config["FOTOS_COLAB"]):
        os.makedirs(app.config["FOTOS_COLAB"])

    filename = secure_filename(arquivo.filename)
    caminho = os.path.join(app.config["FOTOS_COLAB"], filename)
    arquivo.save(caminho)

    return caminho


# =====================================================
# COLABORADORES — LISTA
# =====================================================

@app.route("/colaboradores")
@login_required
def colaboradores():
    if current_user.role != "admin":
        return redirect("/")

    colaboradores = Collaborator.query.order_by(Collaborator.nome).all()
    return render_template("colaboradores.html", colaboradores=colaboradores)


# =====================================================
# COLABORADORES — CRIAR
# =====================================================

@app.route("/colaboradores/salvar", methods=["POST"])
@login_required
def salvar_colaborador():
    if current_user.role != "admin":
        return redirect("/")

    nome = request.form.get("nome")
    matricula = request.form.get("matricula")
    email = request.form.get("email")
    telefone = request.form.get("telefone")
    setor = request.form.get("setor")
    funcao = request.form.get("funcao")
    password = request.form.get("password")

    if Collaborator.query.filter_by(matricula=matricula).first():
        flash("❌ Matrícula já cadastrada!", "error")
        return redirect("/colaboradores")

    if Collaborator.query.filter_by(email=email).first():
        flash("❌ Este e-mail já está em uso (colaborador)!", "error")
        return redirect("/colaboradores")

    if User.query.filter_by(email=email).first():
        flash("❌ Este e-mail já está em uso (usuário)!", "error")
        return redirect("/colaboradores")

    foto = salvar_foto(request.files.get("foto"))

    novo = Collaborator(
        nome=nome,
        matricula=matricula,
        email=email,
        telefone=telefone,
        setor=setor,
        funcao=funcao,
        foto=foto,
        password=generate_password_hash(password)
    )
    db.session.add(novo)
    db.session.commit()

    usuario = User(
        name=nome,
        email=email,
        password=generate_password_hash(password),
        role="colaborador"
    )
    db.session.add(usuario)
    db.session.commit()

    flash("✅ Colaborador cadastrado com sucesso!", "success")
    return redirect("/colaboradores")


# =====================================================
# COLABORADORES — EDITAR
# =====================================================

@app.route("/colaboradores/editar/<int:id>", methods=["POST"])
@login_required
def editar_colaborador(id):
    if current_user.role != "admin":
        return redirect("/")

    colab = Collaborator.query.get_or_404(id)
    email_antigo = colab.email

    colab.nome = request.form.get("nome")
    colab.matricula = request.form.get("matricula")
    colab.email = request.form.get("email")
    colab.telefone = request.form.get("telefone")
    colab.setor = request.form.get("setor")
    colab.funcao = request.form.get("funcao")

    nova_foto = request.files.get("foto")
    if nova_foto and nova_foto.filename != "":
        colab.foto = salvar_foto(nova_foto)

    usuario = User.query.filter_by(email=email_antigo).first()
    if usuario:
        usuario.name = colab.nome
        usuario.email = colab.email

    db.session.commit()

    flash("Atualizado com sucesso!", "success")
    return redirect("/colaboradores")


# =====================================================
# COLABORADORES — EXCLUIR
# =====================================================

@app.route("/colaboradores/excluir/<int:id>", methods=["POST"])
@login_required
def excluir_colaborador(id):
    if current_user.role != "admin":
        return redirect("/")

    colab = Collaborator.query.get_or_404(id)
    usuario = User.query.filter_by(email=colab.email).first()

    if usuario:
        db.session.delete(usuario)

    if colab.foto and os.path.exists(colab.foto):
        try:
            os.remove(colab.foto)
        except:
            pass

    db.session.delete(colab)
    db.session.commit()

    flash("Colaborador removido!", "success")
    return redirect("/colaboradores")


# =====================================================
# ADMINISTRADORES — LISTA
# =====================================================

@app.route("/administradores")
@login_required
def administradores():
    if current_user.role != "admin":
        return redirect("/")
    admins = User.query.filter_by(role="admin").all()
    return render_template("administradores.html", admins=admins)


# =====================================================
# ADMIN — CRIAR
# =====================================================

@app.route("/administradores/salvar", methods=["POST"])
@login_required
def salvar_admin():
    if current_user.role != "admin":
        return redirect("/")

    nome = request.form["nome"]
    email = request.form["email"]
    senha = request.form["senha"]

    if User.query.filter_by(email=email).first():
        flash("❌ Este e-mail já existe!", "error")
        return redirect("/administradores")

    novo_admin = User(
        name=nome,
        email=email,
        password=generate_password_hash(senha),
        role="admin"
    )
    db.session.add(novo_admin)
    db.session.commit()

    flash("Administrador criado!", "success")
    return redirect("/administradores")


# =====================================================
# ADMIN – EDITAR
# =====================================================

@app.route("/administradores/editar/<int:id>", methods=["POST"])
@login_required
def editar_admin(id):
    if current_user.role != "admin":
        return redirect("/")

    admin = User.query.get_or_404(id)
    novo_email = request.form["email"]
    nome = request.form["nome"]

    if User.query.filter(User.email == novo_email, User.id != id).first():
        flash("❌ Este e-mail já está em uso!", "error")
        return redirect("/administradores")

    admin.name = nome
    admin.email = novo_email

    if request.form.get("senha"):
        admin.password = generate_password_hash(request.form.get("senha"))

    db.session.commit()

    flash("Administrador atualizado!", "success")
    return redirect("/administradores")


# =====================================================
# ADMIN — EXCLUIR
# =====================================================

@app.route("/administradores/excluir/<int:id>", methods=["POST"])
@login_required
def excluir_admin(id):
    if current_user.role != "admin":
        return redirect("/")

    admin = User.query.get_or_404(id)

    if admin.email == "admin@admin.com":
        flash("⚠ Não é permitido excluir o admin principal!", "error")
        return redirect("/administradores")

    db.session.delete(admin)
    db.session.commit()

    flash("Administrador removido!", "success")
    return redirect("/administradores")


# =====================================================
# PAINEL DO COLABORADOR
# =====================================================

@app.route("/painel-colaborador")
@login_required
def painel_colaborador():
    if current_user.role != "colaborador":
        return redirect("/")

    tarefas = Task.query.filter(
        Task.status == "pendente",
        ((Task.assigned_to == current_user.id) | (Task.assigned_to == None))
    ).order_by(Task.id.desc()).all()

    return render_template("painel_colaborador.html", tarefas=tarefas)


# =====================================================
# ALTERAR SENHA
# =====================================================

@app.route("/alterar_senha", methods=["POST"])
@login_required
def alterar_senha():
    data = request.get_json()
    senha_atual = data.get("senha_atual")
    nova_senha = data.get("nova_senha")

    if not current_user.check_password(senha_atual):
        return jsonify({"sucesso": False, "mensagem": "Senha atual incorreta."})

    current_user.set_password(nova_senha)
    db.session.commit()

    return jsonify({"sucesso": True})


# =====================================================
# ATIVIDADES (LOGS)
# =====================================================

@app.route("/atividades")
@login_required
def atividades():
    if current_user.role == "admin":
        logs = TaskLog.query.order_by(TaskLog.created_at.desc()).all()
    else:
        logs = TaskLog.query.filter_by(user_id=current_user.id).order_by(TaskLog.created_at.desc()).all()

    return render_template("atividades.html", logs=logs)


# =====================================================
# LOGIN / LOGOUT
# =====================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect("/")
        else:
            flash("❌ Login inválido!", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    logout_user()
    return redirect("/login")


# =====================================================
# EXECUTAR APLICAÇÃO
# =====================================================

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
