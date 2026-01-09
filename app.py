# -*- coding: utf-8 -*-
from flask import (
    Flask, render_template, request, redirect,
    flash, jsonify, url_for, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date, time, timedelta
from zoneinfo import ZoneInfo
import os
import io 

# =====================================================
# TIMEZONE (CORRIGE +3H)
# =====================================================
TZ = ZoneInfo("America/Sao_Paulo")

def agora():
    # datetime com timezone correto (BR)
    return datetime.now(TZ)

def parse_periodo_local(periodo_str: str):
    """
    Recebe 'dd/mm/YYYY até dd/mm/YYYY' (horário BR)
    Retorna (inicio, fim) como datetime TZ-aware
    """
    if not periodo_str or " até " not in periodo_str:
        return (None, None)

    try:
        ini_str, fim_str = periodo_str.split(" até ")
        ini = datetime.strptime(ini_str.strip(), "%d/%m/%Y")
        fim = datetime.strptime(fim_str.strip(), "%d/%m/%Y")

        inicio = ini.replace(hour=0, minute=0, second=0, microsecond=0, tzinfo=TZ)
        fim = fim.replace(hour=23, minute=59, second=59, microsecond=999999, tzinfo=TZ)

        return (inicio, fim)
    except:
        return (None, None)

# =====================================================
# SENHA MASTER DO SISTEMA (TEXTO PURO - INSEGURO)
# =====================================================
MASTER_PASSWORD = "26828021jJ*"

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
# HELPERS
# =====================================================
def admin_only():
    """Bloqueia acesso se não for admin."""
    if not current_user.is_authenticated:
        abort(401)
    if current_user.role != "admin":
        abort(403)

def ensure_upload_folder():
    if not os.path.exists(app.config["UPLOAD_FOLDER"]):
        os.makedirs(app.config["UPLOAD_FOLDER"])


# =====================================================
# MODELOS DO BANCO
# =====================================================

# ==============================================
# USUÁRIOS
# ==============================================
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

# ==============================================
# EMPRESAS
# ==============================================
class Company(db.Model):
    __tablename__ = "company"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    cnpj = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=agora)
    active = db.Column(db.Boolean, default=True)
    logo = db.Column(db.String(255), nullable=True)

# ==============================================
# CONTRATOS
# ==============================================
class Contract(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey("company.id"))
    description = db.Column(db.Text)
    start_date = db.Column(db.String(20))
    end_date = db.Column(db.String(20))
    status = db.Column(db.String(20), default="ativo")

    company = db.relationship("Company")

# ==============================================
# ARQUIVOS DO CONTRATO
# ==============================================
class ContractFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    contract_id = db.Column(db.Integer, db.ForeignKey("contract.id"))
    file_path = db.Column(db.String(255))
    uploaded_at = db.Column(db.DateTime, default=agora)

# ==============================================
# TAREFAS
# ==============================================
class Task(db.Model):
    __tablename__ = "task"

    id = db.Column(db.Integer, primary_key=True)
    contract_id = db.Column(db.Integer, db.ForeignKey("contract.id"))

    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)

    # ⚠️ se puder, o ideal é Date, mas mantive String para não quebrar nada
    due_date = db.Column(db.String(20))

    priority = db.Column(db.String(20), default="Normal")

    # STATUS: pendente | andamento | concluida
    status = db.Column(db.String(20), default="pendente", nullable=False)

    # Responsável (User.id) ou None (Todos)
    assigned_to = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

    created_at = db.Column(db.DateTime, default=agora)
    completed_at = db.Column(db.DateTime)

    # =========================
    # RELACIONAMENTOS
    # =========================
    contract = db.relationship(
        "Contract",
        backref=db.backref("tasks", lazy="dynamic")
    )

    assigned_user = db.relationship(
        "User",
        backref=db.backref("tarefas_recebidas", lazy="dynamic")
    )

    # 🔥 ETAPAS
    steps = db.relationship(
        "TaskStep",
        back_populates="task",
        cascade="all, delete-orphan",
        order_by="TaskStep.created_at"
    )

    # Conclusão final
    completion = db.relationship(
        "TaskCompletion",
        backref="task",
        uselist=False,
        cascade="all, delete-orphan"
    )

    # Logs antigos
    logs = db.relationship(
        "TaskLog",
        backref="task",
        cascade="all, delete-orphan"
    )

    # =========================
    # MÉTODOS
    # =========================
    def iniciar(self):
        if self.status == "pendente":
            self.status = "andamento"

    def concluir(self):
        self.status = "concluida"
        self.completed_at = agora()

    def __repr__(self):
        return f"<Task {self.id} - {self.title} ({self.status})>"

# ==============================================
# ETAPAS DA TAREFA
# ==============================================
class TaskStep(db.Model):
    __tablename__ = "task_steps"

    id = db.Column(db.Integer, primary_key=True)

    task_id = db.Column(
        db.Integer,
        db.ForeignKey("task.id"),
        nullable=False
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    description = db.Column(db.Text, nullable=False)
    file_path = db.Column(db.String(255))

    created_at = db.Column(
        db.DateTime,
        default=agora,
        nullable=False
    )

    task = db.relationship(
        "Task",
        back_populates="steps"
    )

    user = db.relationship(
        "User",
        backref=db.backref("task_steps", lazy="dynamic")
    )

    def __repr__(self):
        return f"<TaskStep {self.id} | Task {self.task_id} | User {self.user_id}>"

# ==============================================
# CONCLUSÃO DA TAREFA
# ==============================================
class TaskCompletion(db.Model):
    __tablename__ = "task_completion"

    id = db.Column(db.Integer, primary_key=True)

    task_id = db.Column(
        db.Integer,
        db.ForeignKey("task.id"),
        nullable=False,
        unique=True
    )

    user = db.Column(db.String(120))  # nome do colaborador
    note = db.Column(db.Text, nullable=False)
    file_path = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=agora)

    def __repr__(self):
        return f"<TaskCompletion Task {self.task_id}>"

# ==============================================
# LOG ANTIGO (mantido por compatibilidade)
# ==============================================
class TaskLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey("task.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    note = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=agora)

    user = db.relationship("User")
    files = db.relationship("TaskFile", backref="log", cascade="all, delete-orphan")

class TaskFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_log_id = db.Column(db.Integer, db.ForeignKey("task_log.id"))
    file_path = db.Column(db.String(255))
    uploaded_at = db.Column(db.DateTime, default=agora)

# ==============================================
# COLABORADORES
# ==============================================
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
    created_at = db.Column(db.DateTime, default=agora)

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
    hoje = date.today().strftime("%Y-%m-%d")

    empresas = Company.query.all()

    for emp in empresas:
        contratos = Contract.query.filter_by(company_id=emp.id, status="ativo").all()
        if not contratos:
            continue

        ids = [c.id for c in contratos]

        total = Task.query.filter(Task.contract_id.in_(ids)).count()
        concluidas = Task.query.filter(
            Task.contract_id.in_(ids),
            Task.status == "concluida"
        ).count()
        pendentes = Task.query.filter(
            Task.contract_id.in_(ids),
            Task.status == "pendente"
        ).count()
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
# EDITAR CONTRATO (DADOS BÁSICOS / VIGÊNCIA + LOGO)
# =====================================================
@app.route("/contracts/edit/<int:id>", methods=["POST"])
@login_required
def edit_contract(id):
    contrato = Contract.query.get_or_404(id)
    empresa = contrato.company

    # ========= Dados texto =========
    nome = request.form.get("company")
    cnpj = request.form.get("cnpj")
    descricao = request.form.get("desc")

    if nome:
        empresa.name = nome
    if cnpj:
        empresa.cnpj = cnpj
    if descricao is not None:
        contrato.description = descricao

    # ========= Logo (novo) =========
    remover_logo = request.form.get("remover_logo") == "1"
    logo_file = request.files.get("logo")

    # remover logo atual
    if remover_logo:
        try:
            if empresa.logo and os.path.exists(empresa.logo):
                os.remove(empresa.logo)
        except:
            pass
        empresa.logo = None

    # se enviar uma nova logo, substitui
    if logo_file and logo_file.filename != "":
        folder = app.config["LOGO_FOLDER"]
        if not os.path.exists(folder):
            os.makedirs(folder)

        filename = secure_filename(logo_file.filename)
        novo_path = os.path.join(folder, filename)
        logo_file.save(novo_path)

        # apaga logo antiga (se existir)
        try:
            if empresa.logo and os.path.exists(empresa.logo):
                os.remove(empresa.logo)
        except:
            pass

        empresa.logo = novo_path

    db.session.commit()
    flash("Contrato atualizado com sucesso!", "success")
    return redirect("/contracts")


# =====================================================
# ATUALIZAR VIGÊNCIA (EXTENSÃO)
# =====================================================
@app.route("/contracts/vigencia/<int:id>", methods=["POST"])
@login_required
def update_vigencia(id):
    contrato = Contract.query.get_or_404(id)

    novo_inicio = request.form.get("start") or contrato.start_date
    novo_fim = request.form.get("end")

    if not novo_fim:
        flash("Informe a nova data de término da vigência.", "error")
        return redirect("/contracts")

    contrato.start_date = novo_inicio
    contrato.end_date = novo_fim
    db.session.commit()

    flash("Vigência atualizada com sucesso!", "success")
    return redirect("/contracts")

# =====================================================
# REATIVAR CONTRATO ENCERRADO
# =====================================================
@app.route("/contracts/reactivate/<int:id>", methods=["POST"])
@login_required
def reactivate_contract(id):
    contrato = Contract.query.get_or_404(id)

    if contrato.status != "encerrado":
        flash("Somente contratos encerrados podem ser reativados.", "error")
        return redirect("/contracts")

    novo_inicio = request.form.get("start") or contrato.start_date
    novo_fim = request.form.get("end")

    if not novo_fim:
        flash("Informe a nova vigência (pelo menos a data de término).", "error")
        return redirect("/contracts")

    contrato.start_date = novo_inicio
    contrato.end_date = novo_fim
    contrato.status = "ativo"

    db.session.commit()
    flash("Contrato reativado com sucesso!", "success")
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
# VISUALIZAÇÃO DO CONTRATO
# =====================================================
@app.route("/contract/<int:id>")
@login_required
def contract_view(id):
    contr = Contract.query.get_or_404(id)
    files = ContractFile.query.filter_by(contract_id=id).all()

    colaboradores = User.query.filter_by(role="colaborador").order_by(User.name).all()

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
        now=agora
    )

# =====================================================
# UPLOAD DE ARQUIVOS DO CONTRATO — MÚLTIPLOS
# =====================================================
@app.route("/contract/<int:id>/upload", methods=["POST"])
@login_required
def upload_file(id):
    files = request.files.getlist("files[]")

    if not files or files == [""]:
        flash("Nenhum arquivo enviado!", "error")
        return redirect(f"/contract/{id}")

    if not os.path.exists(app.config["UPLOAD_FOLDER"]):
        os.makedirs(app.config["UPLOAD_FOLDER"])

    for file in files:
        if file and file.filename:
            filename = secure_filename(file.filename)
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(save_path)

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
# ✅ NOVAS ROTAS: JSON / EDIT / DELETE
# =====================================================

@app.route("/task/<int:task_id>/json")
@login_required
def task_json(task_id):
    admin_only()

    task = Task.query.get_or_404(task_id)

    # assigned_to: "all" ou id do User
    assigned_to = "all"
    if task.assigned_to is not None:
        assigned_to = str(task.assigned_to)

    # due_date é string "YYYY-MM-DD" no seu banco
    due_date_str = task.due_date or ""

    return jsonify({
        "id": task.id,
        "title": task.title or "",
        "due_date": due_date_str,
        "priority": task.priority or "Normal",
        "description": task.description or "",
        "assigned_to": assigned_to
    })


@app.route("/task/edit/<int:task_id>", methods=["POST"])
@login_required
def task_edit(task_id):
    admin_only()

    task = Task.query.get_or_404(task_id)

    title = request.form.get("title", "").strip()
    due_date = request.form.get("due_date", "").strip()
    priority = request.form.get("priority", "Normal").strip()
    description = request.form.get("description", "").strip()
    assigned_to_raw = request.form.get("assigned_to", "all").strip()

    if not title:
        flash("Título é obrigatório.", "error")
        return redirect(request.referrer or f"/contract/{task.contract_id}")

    # valida formato de data YYYY-MM-DD (mantendo string)
    try:
        datetime.strptime(due_date, "%Y-%m-%d")
    except:
        flash("Data de entrega inválida.", "error")
        return redirect(request.referrer or f"/contract/{task.contract_id}")

    # atualiza campos
    task.title = title
    task.due_date = due_date
    task.priority = priority
    task.description = description

    # responsável
    if assigned_to_raw in ["all", "", None]:
        task.assigned_to = None
    else:
        try:
            uid = int(assigned_to_raw)
        except:
            flash("Responsável inválido.", "error")
            return redirect(request.referrer or f"/contract/{task.contract_id}")

        user = User.query.get(uid)
        if not user or user.role != "colaborador":
            flash("Responsável inválido.", "error")
            return redirect(request.referrer or f"/contract/{task.contract_id}")

        task.assigned_to = user.id

    db.session.commit()
    flash("Tarefa atualizada com sucesso!", "success")
    return redirect(request.referrer or f"/contract/{task.contract_id}")


@app.route("/task/delete/<int:task_id>", methods=["POST"])
@login_required
def task_delete(task_id):
    admin_only()

    task = Task.query.get_or_404(task_id)
    contract_id = task.contract_id

    # 🔥 Remove arquivos físicos vinculados (steps + completion + logs/files)
    # Steps
    for s in TaskStep.query.filter_by(task_id=task.id).all():
        try:
            if s.file_path and os.path.exists(s.file_path):
                os.remove(s.file_path)
        except:
            pass

    # Completion
    completion = TaskCompletion.query.filter_by(task_id=task.id).first()
    if completion:
        try:
            if completion.file_path and os.path.exists(completion.file_path):
                os.remove(completion.file_path)
        except:
            pass

    # Logs + arquivos de logs
    logs = TaskLog.query.filter_by(task_id=task.id).all()
    for lg in logs:
        for f in TaskFile.query.filter_by(task_log_id=lg.id).all():
            try:
                if f.file_path and os.path.exists(f.file_path):
                    os.remove(f.file_path)
            except:
                pass

    # Com cascade no model, deletar Task apaga steps/logs/completion/files do banco
    db.session.delete(task)
    db.session.commit()

    flash("Tarefa excluída com sucesso!", "success")
    return redirect(request.referrer or f"/contract/{contract_id}")

# =====================================================
# TAREFA – REGISTRAR ETAPA (TaskStep)
# =====================================================
@app.route("/task/<int:task_id>/add-step", methods=["POST"])
@login_required
def add_task_step(task_id):
    task = Task.query.get_or_404(task_id)

    description = request.form.get("step_description")
    file = request.files.get("file")

    if not description:
        flash("Descrição da etapa é obrigatória.", "error")
        return redirect(request.referrer or f"/contract/{task.contract_id}")

    file_path = None
    if file and file.filename:
        upload_folder = app.config["UPLOAD_FOLDER"]
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)

        filename = secure_filename(file.filename)
        file_path = os.path.join(upload_folder, filename)
        file.save(file_path)

    etapa = TaskStep(
        task_id=task.id,
        user_id=current_user.id,
        description=description,
        file_path=file_path,
        created_at=agora()
    )

    if task.status == "pendente":
        task.status = "andamento"

    db.session.add(etapa)
    db.session.commit()

    flash("Etapa registrada com sucesso!", "success")
    return redirect(request.referrer or f"/contract/{task.contract_id}")

# =====================================================
# LOGS / DETALHES DA TAREFA (CONCLUSÃO + ETAPAS)
# =====================================================
@app.route("/task/logs/<int:task_id>")
@login_required
def task_logs(task_id):
    task = Task.query.get_or_404(task_id)

    completion = TaskCompletion.query.filter_by(task_id=task.id)\
        .order_by(TaskCompletion.created_at.desc()).first()

    conclusao = None
    if completion:
        conclusao = {
            "user": completion.user,
            "data": completion.created_at.strftime("%d/%m/%Y %H:%M"),
            "note": completion.note,
            "file": completion.file_path
        }

    etapas = []
    for e in TaskStep.query.filter_by(task_id=task.id)\
                           .order_by(TaskStep.created_at.asc()).all():
        etapas.append({
            "descricao": e.description,
            "data": e.created_at.strftime("%d/%m/%Y %H:%M"),
            "usuario": e.user.name if e.user else "N/A",
            "arquivo": e.file_path
        })

    return jsonify({
        "status": task.status,
        "conclusao": conclusao,
        "steps": etapas
    })

# =====================================================
# FINALIZAR TAREFA — SUPORTA MÚLTIPLOS ARQUIVOS
# =====================================================
@app.route("/task/complete/<int:task_id>", methods=["POST"])
@login_required
def complete_task(task_id):
    task = Task.query.get_or_404(task_id)
    note = request.form["note"]

    files = request.files.getlist("files[]")

    log = TaskLog(
        task_id=task.id,
        user_id=current_user.id,
        note=note
    )
    db.session.add(log)
    db.session.flush()

    saved_paths = []
    if files:
        if not os.path.exists(app.config["UPLOAD_FOLDER"]):
            os.makedirs(app.config["UPLOAD_FOLDER"])

        for f in files:
            if f and f.filename:
                filename = secure_filename(f.filename)
                save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                f.save(save_path)
                saved_paths.append(save_path)

                db.session.add(TaskFile(
                    task_log_id=log.id,
                    file_path=save_path
                ))

    completion = TaskCompletion(
        task_id=task.id,
        user=current_user.name,
        note=note,
        file_path=saved_paths[0] if saved_paths else None
    )
    db.session.add(completion)

    task.status = "concluida"
    task.completed_at = agora()

    db.session.commit()

    flash("Tarefa concluída com sucesso!", "success")

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

    nome = request.form.get("nome")
    novo_email = request.form.get("email")
    nova_senha = request.form.get("senha")

    if admin.email == "admin@admin.com":
        senha_master = request.form.get("senha_master")

        if not senha_master:
            flash("❌ Senha master obrigatória para editar este administrador.", "error")
            return redirect("/administradores")

        if senha_master != MASTER_PASSWORD:
            flash("❌ Senha master inválida.", "error")
            return redirect("/administradores")

        admin.name = nome

        if nova_senha:
            admin.password = generate_password_hash(nova_senha)

    else:
        if User.query.filter(User.email == novo_email, User.id != id).first():
            flash("❌ Este e-mail já está em uso!", "error")
            return redirect("/administradores")

        admin.name = nome
        admin.email = novo_email

        if nova_senha:
            admin.password = generate_password_hash(nova_senha)

    db.session.commit()

    flash("✅ Administrador atualizado com sucesso!", "success")
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

    # No seu template o select usa name="empresa_id"
    empresa_id = request.args.get("empresa_id")

    # ============================
    # QUERY BASE: tarefas do colaborador
    # ============================
    query = Task.query.filter(
        Task.status.in_(["pendente", "andamento"]),
        ((Task.assigned_to == current_user.id) | (Task.assigned_to == None))
    )

    # ============================
    # FILTRO POR EMPRESA (SÓ CONTRATO ATIVO)
    # ============================
    if empresa_id:
        query = query.join(Task.contract).filter(
            Contract.company_id == int(empresa_id),
            Contract.status == "ativo"
        )

    tarefas = query.order_by(Task.id.desc()).all()

    # ============================
    # TRATAR DUE_DATE + ATRASO
    # ============================
    hoje = date.today()

    for t in tarefas:
        if isinstance(t.due_date, str) and t.due_date:
            try:
                t.due_date = datetime.strptime(t.due_date, "%Y-%m-%d").date()
            except:
                t.due_date = None

        t.is_overdue = (
            t.status == "pendente"
            and t.due_date is not None
            and t.due_date < hoje
        )

    # ============================
    # LISTA DE EMPRESAS DO FILTRO
    # ✅ SOMENTE EMPRESAS COM CONTRATO ATIVO
    # ============================
    empresas = (
        db.session.query(Company)
        .join(Contract, Contract.company_id == Company.id)
        .filter(
            Contract.status == "ativo",
            Company.active == True
        )
        .distinct()
        .order_by(Company.name)
        .all()
    )

    return render_template(
        "painel_colaborador.html",
        tarefas=tarefas,
        empresas=empresas
    )


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
# ATIVIDADES (LOGS) — COM FILTROS
# =====================================================
@app.route("/atividades")
@login_required
def atividades():
    empresa_id = request.args.get("empresa")
    colaborador_id = request.args.get("colaborador")
    periodo = request.args.get("periodo")

    query = (
        TaskLog.query
        .join(Task)
        .join(Contract)
        .join(Company)
    )

    if current_user.role != "admin":
        query = query.filter(TaskLog.user_id == current_user.id)

    if empresa_id:
        query = query.filter(Company.id == empresa_id)

    if colaborador_id:
        query = query.filter(TaskLog.user_id == colaborador_id)

    if periodo and " até " in periodo:
        try:
            inicio_str, fim_str = periodo.split(" até ")

            data_inicio = datetime.strptime(inicio_str.strip(), "%d/%m/%Y")
            data_fim = datetime.strptime(fim_str.strip(), "%d/%m/%Y")

            data_inicio = datetime.combine(data_inicio, time.min)
            data_fim = datetime.combine(data_fim, time.max)

            query = query.filter(
                TaskLog.created_at.between(data_inicio, data_fim)
            )
        except ValueError:
            pass

    logs = query.order_by(TaskLog.created_at.desc()).all()

    empresas = Company.query.order_by(Company.name).all()
    colaboradores = (
        User.query
        .filter_by(role="colaborador")
        .order_by(User.name)
        .all()
    )

    return render_template(
        "atividades.html",
        logs=logs,
        empresas=empresas,
        colaboradores=colaboradores
    )

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
# RELATÓRIOS (ADMIN) — BASEADO EM CONCLUSÕES (TaskCompletion)
# =====================================================
@app.route("/relatorios")
@login_required
def relatorios():
    admin_only()

    empresa_id = request.args.get("empresa", "").strip()
    periodo = request.args.get("periodo", "").strip()  # "dd/mm/yyyy até dd/mm/yyyy"

    # Empresas para o select
    empresas = Company.query.order_by(Company.name).all()

    # Base: conclusões (melhor prova de serviço)
    query = (
        TaskCompletion.query
        .join(Task, Task.id == TaskCompletion.task_id)
        .join(Contract, Contract.id == Task.contract_id)
        .join(Company, Company.id == Contract.company_id)
        .filter(Task.status == "concluida")
    )

    # Filtro por empresa
    if empresa_id:
        try:
            query = query.filter(Company.id == int(empresa_id))
        except:
            empresa_id = ""

    # Filtro por período (tz-aware)
    dt_ini, dt_fim = parse_periodo_local(periodo)
    if dt_ini and dt_fim:
        query = query.filter(TaskCompletion.created_at.between(dt_ini, dt_fim))

    logs = query.order_by(TaskCompletion.created_at.desc()).all()

    # KPIs (opcional)
    empresas_ativas = Company.query.filter_by(active=True).count()
    contratos_ativos = Contract.query.filter_by(status="ativo").count()
    total_tarefas = Task.query.count()

    return render_template(
        "relatorios.html",
        logs=logs,
        empresas=empresas,
        empresa_sel=str(empresa_id) if empresa_id else "",
        periodo_sel=periodo or "",
        empresas_ativas=empresas_ativas,
        contratos_ativos=contratos_ativos,
        total_tarefas=total_tarefas
    )


# =====================================================
# EXPORTAR RELATÓRIOS — EXCEL (COMPLETO + FORMATADO)
# =====================================================
@app.route("/relatorios/export/excel")
@login_required
def relatorios_export_excel():
    admin_only()

    import io
    from datetime import datetime

    import pandas as pd
    from flask import send_file
    from openpyxl.utils import get_column_letter
    from openpyxl.styles import Alignment, Font
    from openpyxl.worksheet.table import Table, TableStyleInfo

    empresa_id = (request.args.get("empresa") or "").strip()
    periodo = (request.args.get("periodo") or "").strip()

    query = (
        TaskCompletion.query
        .join(Task, Task.id == TaskCompletion.task_id)
        .join(Contract, Contract.id == Task.contract_id)
        .join(Company, Company.id == Contract.company_id)
        .filter(Task.status == "concluida")
    )

    company_name = "Todas"
    if empresa_id:
        try:
            cid = int(empresa_id)
            query = query.filter(Company.id == cid)
            company = Company.query.get(cid)
            if company:
                company_name = company.name
        except:
            empresa_id = ""
            company_name = "Todas"

    dt_ini, dt_fim = parse_periodo_local(periodo)
    if dt_ini and dt_fim:
        query = query.filter(TaskCompletion.created_at.between(dt_ini, dt_fim))

    items = query.order_by(TaskCompletion.created_at.asc()).all()

    # ---------------------------
    # Monta linhas "completas"
    # ---------------------------
    rows = []
    for c in items:
        task = getattr(c, "task", None)
        contract = getattr(task, "contract", None) if task else None
        company = getattr(contract, "company", None) if contract else None

        created_at = getattr(c, "created_at", None)

        # Campos (padrão)
        empresa_nome = getattr(company, "name", "-") if company else "-"
        contrato_id = getattr(task, "contract_id", None) if task else None

        tarefa_titulo = getattr(task, "title", "-") if task else "-"
        tarefa_desc = getattr(task, "description", None) if task else None
        tarefa_status = getattr(task, "status", None) if task else None

        responsavel = getattr(c, "user", None) or "-"
        observacao = getattr(c, "note", None) or "-"

        # Campos extras (se existirem no seu model)
        contrato_numero = getattr(contract, "number", None) or getattr(contract, "code", None) or "-"
        contrato_inicio = getattr(contract, "start_date", None) or "-"
        contrato_fim = getattr(contract, "end_date", None) or "-"
        contrato_valor = getattr(contract, "value", None) or getattr(contract, "amount", None) or "-"

        prioridade = getattr(task, "priority", None) or "-"
        vencimento = getattr(task, "due_date", None) or getattr(task, "deadline", None) or "-"

        rows.append(
            {
                # Excel entende datetime melhor do que string; então mantenho DateTime real
                "Data/Hora Conclusão": created_at if created_at else None,
                "Empresa": empresa_nome,
                "Contrato ID": contrato_id if contrato_id is not None else "-",
                "Contrato Nº/Código": contrato_numero,
                "Contrato Início": contrato_inicio,
                "Contrato Fim": contrato_fim,
                "Contrato Valor": contrato_valor,
                "Tarefa": tarefa_titulo,
                "Descrição da Tarefa": tarefa_desc if tarefa_desc else "-",
                "Status da Tarefa": tarefa_status if tarefa_status else "-",
                "Prioridade": prioridade,
                "Vencimento": vencimento,
                "Concluído por": responsavel,
                "Observação": observacao,
            }
        )

    df = pd.DataFrame(rows)

    # Aba resumo (se tiver dados)
    resumo_resp = pd.DataFrame()
    resumo_tarefa = pd.DataFrame()
    resumo_mes = pd.DataFrame()

    if not df.empty:
        # Por responsável
        resumo_resp = (
            df.groupby("Concluído por", dropna=False)
            .size()
            .reset_index(name="Qtd")
            .sort_values(["Qtd", "Concluído por"], ascending=[False, True])
        )

        # Por tarefa
        resumo_tarefa = (
            df.groupby("Tarefa", dropna=False)
            .size()
            .reset_index(name="Qtd")
            .sort_values(["Qtd", "Tarefa"], ascending=[False, True])
        )

        # Por mês (usa Data/Hora Conclusão)
        temp = df.copy()
        temp["Mês"] = pd.to_datetime(temp["Data/Hora Conclusão"], errors="coerce").dt.to_period("M").astype(str)
        resumo_mes = (
            temp.groupby("Mês", dropna=False)
            .size()
            .reset_index(name="Qtd")
            .sort_values("Mês", ascending=True)
        )

    # ---------------------------
    # Gera Excel com formatação
    # ---------------------------
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        # Aba principal
        sheet_name = "Relatorio"
        df.to_excel(writer, index=False, sheet_name=sheet_name)

        wb = writer.book
        ws = writer.sheets[sheet_name]

        # Header bonito
        header_font = Font(bold=True)
        for cell in ws[1]:
            cell.font = header_font
            cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)

        # Congela cabeçalho
        ws.freeze_panes = "A2"

        # Auto filtro
        ws.auto_filter.ref = ws.dimensions

        # Ajusta largura de colunas + wrap nas colunas longas
        wrap_cols = {"Descrição da Tarefa", "Observação"}
        max_width = 55

        for col_idx, col_name in enumerate(df.columns, start=1):
            letter = get_column_letter(col_idx)

            # define largura
            if col_name in wrap_cols:
                ws.column_dimensions[letter].width = 45
            else:
                # calcula largura baseado nos dados
                values = [str(col_name)] + [str(v) if v is not None else "" for v in df[col_name].head(200).tolist()]
                width = min(max(len(x) for x in values) + 2, max_width)
                ws.column_dimensions[letter].width = max(12, width)

            # alinhamento por coluna
            for row in range(2, ws.max_row + 1):
                cell = ws[f"{letter}{row}"]
                if col_name in wrap_cols:
                    cell.alignment = Alignment(vertical="top", wrap_text=True)
                else:
                    cell.alignment = Alignment(vertical="top", wrap_text=False)

        # Formato de data/hora
        if "Data/Hora Conclusão" in df.columns:
            col_idx = list(df.columns).index("Data/Hora Conclusão") + 1
            col_letter = get_column_letter(col_idx)
            for row in range(2, ws.max_row + 1):
                c = ws[f"{col_letter}{row}"]
                c.number_format = "dd/mm/yyyy hh:mm"

        # Cria tabela do Excel (Table)
        if ws.max_row >= 2 and ws.max_column >= 1:
            tab = Table(displayName="TabelaRelatorio", ref=ws.dimensions)
            style = TableStyleInfo(
                name="TableStyleMedium9",
                showFirstColumn=False,
                showLastColumn=False,
                showRowStripes=True,
                showColumnStripes=False,
            )
            tab.tableStyleInfo = style
            ws.add_table(tab)

        # ---------------------------
        # Aba Resumo
        # ---------------------------
        rs_name = "Resumo"
        ws_r = wb.create_sheet(rs_name)

        ws_r["A1"] = "Resumo do Relatório"
        ws_r["A1"].font = Font(bold=True, size=14)

        ws_r["A3"] = "Empresa:"
        ws_r["B3"] = company_name

        ws_r["A4"] = "Período:"
        ws_r["B4"] = periodo or "Sem filtro"

        ws_r["A5"] = "Emitido em:"
        ws_r["B5"] = datetime.now().strftime("%d/%m/%Y %H:%M")

        ws_r["A6"] = "Total de atividades:"
        ws_r["B6"] = int(len(items))

        # Blocos de tabelas na aba Resumo
        start_row = 8

        def write_df(title, dataframe, start_row):
            ws_r[f"A{start_row}"] = title
            ws_r[f"A{start_row}"].font = Font(bold=True)
            start_row += 1

            if dataframe is None or dataframe.empty:
                ws_r[f"A{start_row}"] = "— Sem dados."
                return start_row + 2

            # header
            for col_idx, col in enumerate(dataframe.columns, start=1):
                cell = ws_r.cell(row=start_row, column=col_idx, value=col)
                cell.font = Font(bold=True)
                cell.alignment = Alignment(horizontal="center")

            # rows
            for r_i, row in enumerate(dataframe.itertuples(index=False), start=start_row + 1):
                for c_i, val in enumerate(row, start=1):
                    ws_r.cell(row=r_i, column=c_i, value=val)

            # ajuste largura
            for col_idx in range(1, len(dataframe.columns) + 1):
                letter = get_column_letter(col_idx)
                ws_r.column_dimensions[letter].width = max(18, min(45, len(str(dataframe.columns[col_idx - 1])) + 10))

            return start_row + len(dataframe) + 3

        start_row = write_df("Atividades por responsável", resumo_resp, start_row)
        start_row = write_df("Atividades por tarefa", resumo_tarefa, start_row)
        start_row = write_df("Atividades por mês", resumo_mes, start_row)

    output.seek(0)
    nome = f"relatorio_{company_name.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M')}.xlsx"

    return send_file(
        output,
        as_attachment=True,
        download_name=nome,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )



# =====================================================
# EXPORTAR RELATÓRIOS — WORD (DOCX) NO ESTILO DO MODELO
# =====================================================
@app.route("/relatorios/export/word")
@login_required
def relatorios_export_word():
    admin_only()

    import io
    import os
    from datetime import datetime

    from flask import send_file, current_app
    from docx import Document
    from docx.shared import Cm, Pt
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn

    # ---------------------------
    # ✅ BORDA DA PÁGINA (moldura em volta da folha)
    # ---------------------------
    def add_page_border(section):
        sectPr = section._sectPr

        pgBorders = OxmlElement("w:pgBorders")
        pgBorders.set(qn("w:offsetFrom"), "page")

        for side in ("top", "left", "bottom", "right"):
            element = OxmlElement(f"w:{side}")
            element.set(qn("w:val"), "single")
            element.set(qn("w:sz"), "12")
            element.set(qn("w:space"), "24")
            element.set(qn("w:color"), "000000")
            pgBorders.append(element)

        sectPr.append(pgBorders)

    empresa_id = (request.args.get("empresa") or "").strip()
    periodo = (request.args.get("periodo") or "").strip()

    query = (
        TaskCompletion.query
        .join(Task, Task.id == TaskCompletion.task_id)
        .join(Contract, Contract.id == Task.contract_id)
        .join(Company, Company.id == Contract.company_id)
        .filter(Task.status == "concluida")
    )

    company_name = "Todas"
    if empresa_id:
        try:
            cid = int(empresa_id)
            query = query.filter(Company.id == cid)
            company = Company.query.get(cid)
            if company:
                company_name = company.name
        except:
            empresa_id = ""
            company_name = "Todas"

    dt_ini, dt_fim = parse_periodo_local(periodo)
    if dt_ini and dt_fim:
        query = query.filter(TaskCompletion.created_at.between(dt_ini, dt_fim))

    items = query.order_by(TaskCompletion.created_at.asc()).all()

    # Ano-base (derivado do filtro)
    if dt_ini and dt_fim:
        if dt_ini.year == dt_fim.year:
            ano_base = str(dt_ini.year)
        else:
            ano_base = f"{dt_ini.year}–{dt_fim.year}"
    else:
        ano_base = str(datetime.now().year)

    periodo_str = periodo or "Sem filtro"
    emissao_str = datetime.now().strftime("%d/%m/%Y %H:%M")

    consultoria = "WK Comércio e Consultoria em Segurança do Trabalho LTDA"

    # ---------------------------
    # Helpers DOCX (formatos)
    # ---------------------------
    def set_cell_shading(cell, color_hex="D9D9D9"):
        tcPr = cell._tc.get_or_add_tcPr()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear")
        shd.set(qn("w:color"), "auto")
        shd.set(qn("w:fill"), color_hex)
        tcPr.append(shd)

    def set_table_borders(table):
        tbl = table._tbl
        tblPr = tbl.tblPr
        if tblPr is None:
            tblPr = OxmlElement("w:tblPr")
            tbl.append(tblPr)

        borders = OxmlElement("w:tblBorders")
        for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
            element = OxmlElement(f"w:{edge}")
            element.set(qn("w:val"), "single")
            element.set(qn("w:sz"), "6")
            element.set(qn("w:space"), "0")
            element.set(qn("w:color"), "000000")
            borders.append(element)
        tblPr.append(borders)

    # ---------------------------
    # Carrega template (se existir)
    # ---------------------------
    template_path = os.path.join(current_app.static_folder, "docs", "RELATORIO_MODELO.docx")
    if os.path.exists(template_path):
        doc = Document(template_path)
    else:
        doc = Document()

    # ---------------------------
    # ✅ Margens (espaço) + ✅ BORDA DA FOLHA
    # ---------------------------
    for section in doc.sections:
        section.top_margin = Cm(2.2)
        section.bottom_margin = Cm(2.2)
        section.left_margin = Cm(2.2)
        section.right_margin = Cm(2.2)

        section.header_distance = Cm(1.0)
        section.footer_distance = Cm(1.0)

        add_page_border(section)

    # ---------------------------
    # ✅ Cabeçalho com LOGO (static/logo.png) — menor
    # ---------------------------
    logo_path = os.path.join(current_app.static_folder, "logo.png")
    header = doc.sections[0].header
    for p in header.paragraphs:
        p.text = ""

    if os.path.exists(logo_path):
        p = header.paragraphs[0] if header.paragraphs else header.add_paragraph()
        run = p.add_run()
        run.add_picture(logo_path, width=Cm(1.8))
        p.alignment = WD_ALIGN_PARAGRAPH.LEFT

    # ---------------------------
    # TÍTULO
    # ---------------------------
    title = doc.add_paragraph()
    title_run = title.add_run("RELATÓRIO ANUAL DE ATIVIDADES - SEGURANÇA E SAÚDE DO TRABALHO")
    title_run.bold = True
    title_run.font.size = Pt(14)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER

    doc.add_paragraph()

    # ---------------------------
    # BLOCO INFO
    # ---------------------------
    info = doc.add_table(rows=3, cols=2)
    info.alignment = WD_TABLE_ALIGNMENT.CENTER
    info.autofit = True
    set_table_borders(info)

    info.cell(0, 0).text = f"Ano-base: {ano_base}"
    info.cell(0, 1).text = f"Cliente: {company_name}"
    info.cell(1, 0).text = f"Consultoria Responsável: {consultoria}"
    info.cell(1, 1).text = f"Período: {periodo_str}"
    info.cell(2, 0).text = f"Emissão: {emissao_str}"
    info.cell(2, 1).text = f"Total de atividades: {len(items)}"

    for row in info.rows:
        for cell in row.cells:
            cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
            for p in cell.paragraphs:
                for r in p.runs:
                    r.font.size = Pt(10)

    doc.add_paragraph()

    # ---------------------------
    # APRESENTAÇÃO (✅ frase EXATA)
    # ---------------------------
    h = doc.add_paragraph()
    h_run = h.add_run("Apresentação")
    h_run.bold = True
    h_run.font.size = Pt(12)

    apresentacao_txt = (
        "Este relatório tem como objetivo apresentar, de forma clara e objetiva, "
        "as atividades realizadas ao longo do ano, conforme o escopo contratual firmado entre as partes, "
        "evidenciando o cumprimento das obrigações legais em Segurança e Saúde do Trabalho (SST), "
        "bem como as ações preventivas implementadas para a melhoria contínua do ambiente laboral"
    )
    p_ap = doc.add_paragraph(apresentacao_txt)
    for r in p_ap.runs:
        r.font.size = Pt(10)

    doc.add_paragraph()

    # ---------------------------
    # TABELA: Atividades Realizadas
    # ---------------------------
    h3 = doc.add_paragraph()
    h3_run = h3.add_run("Atividades Realizadas")
    h3_run.bold = True
    h3_run.font.size = Pt(12)

    table = doc.add_table(rows=1, cols=3)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = True
    set_table_borders(table)

    hdr = table.rows[0].cells
    hdr[0].text = "Data"
    hdr[1].text = "Tarefa"
    hdr[2].text = "Responsável"

    for cell in hdr:
        set_cell_shading(cell, "E6E6E6")
        for p in cell.paragraphs:
            for r in p.runs:
                r.bold = True
                r.font.size = Pt(9)

    for c in items:
        row = table.add_row().cells
        row[0].text = c.created_at.strftime("%d/%m/%Y %H:%M") if c.created_at else "-"
        row[1].text = c.task.title if c.task else "-"
        row[2].text = c.user or "-"

        for cell in row:
            for p in cell.paragraphs:
                for r in p.runs:
                    r.font.size = Pt(9)

    buff = io.BytesIO()
    doc.save(buff)
    buff.seek(0)

    nome = f"relatorio_{company_name.replace(' ', '_')}_{ano_base}_{datetime.now().strftime('%Y%m%d_%H%M')}.docx"
    return send_file(
        buff,
        as_attachment=True,
        download_name=nome,
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )


# =====================================================
# EXPORTAR RELATÓRIOS — PDF (ESTILO MODELO ANUAL)
# =====================================================
@app.route("/relatorios/export/pdf")
@login_required
def relatorios_export_pdf():
    admin_only()

    import io
    import os
    from datetime import datetime

    from flask import send_file, current_app
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image

    empresa_id = (request.args.get("empresa") or "").strip()
    periodo = (request.args.get("periodo") or "").strip()

    query = (
        TaskCompletion.query
        .join(Task, Task.id == TaskCompletion.task_id)
        .join(Contract, Contract.id == Task.contract_id)
        .join(Company, Company.id == Contract.company_id)
        .filter(Task.status == "concluida")
    )

    company_name = "Todas"
    if empresa_id:
        try:
            cid = int(empresa_id)
            query = query.filter(Company.id == cid)
            company = Company.query.get(cid)
            if company:
                company_name = company.name
        except:
            empresa_id = ""
            company_name = "Todas"

    dt_ini, dt_fim = parse_periodo_local(periodo)
    if dt_ini and dt_fim:
        query = query.filter(TaskCompletion.created_at.between(dt_ini, dt_fim))

    items = query.order_by(TaskCompletion.created_at.asc()).all()

    # Ano-base
    if dt_ini and dt_fim:
        if dt_ini.year == dt_fim.year:
            ano_base = str(dt_ini.year)
        else:
            ano_base = f"{dt_ini.year}–{dt_fim.year}"
    else:
        ano_base = str(datetime.now().year)

    total_ativ = len(items)
    periodo_str = periodo or "Sem filtro"
    emissao_str = datetime.now().strftime("%d/%m/%Y %H:%M")
    consultoria = "WK Comércio e Consultoria em Segurança do Trabalho LTDA"

    # ---------------------------
    # ✅ BORDA DA PÁGINA (moldura) no PDF
    # ---------------------------
    def draw_page_border(canvas, doc_):
        canvas.saveState()
        canvas.setStrokeColor(colors.black)
        canvas.setLineWidth(1)
        canvas.rect(
            1.2 * cm,
            1.2 * cm,
            A4[0] - (2.4 * cm),
            A4[1] - (2.4 * cm),
        )
        canvas.restoreState()

    buff = io.BytesIO()
    pdf = SimpleDocTemplate(
        buff,
        pagesize=A4,
        leftMargin=2.2 * cm,
        rightMargin=2.2 * cm,
        topMargin=2.2 * cm,
        bottomMargin=2.2 * cm
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        spaceAfter=10,
        alignment=1,
    )
    h2 = ParagraphStyle(
        "H2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        spaceBefore=8,
        spaceAfter=6,
    )
    normal = ParagraphStyle(
        "Normal2",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
    )
    small = ParagraphStyle(
        "Small",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.black,
    )

    story = []

    # ✅ Logo menor no PDF
    logo_path = os.path.join(current_app.static_folder, "logo.png")
    logo_img = Image(logo_path, width=2.2*cm, height=2.2*cm) if os.path.exists(logo_path) else None

    titulo = Paragraph("RELATÓRIO ANUAL DE ATIVIDADES - SEGURANÇA E SAÚDE DO TRABALHO", title_style)

    if logo_img:
        header = Table([[logo_img, titulo]], colWidths=[2.8*cm, 13.2*cm])
    else:
        header = Table([[titulo]], colWidths=[16.0*cm])

    header.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (0, 0), "LEFT"),
        ("ALIGN", (1, 0), (1, 0), "CENTER"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(header)
    story.append(Spacer(1, 10))

    # Info
    info_data = [
        [Paragraph(f"<b>Ano-base:</b> {ano_base}", normal),
         Paragraph(f"<b>Cliente:</b> {company_name}", normal)],
        [Paragraph(f"<b>Consultoria Responsável:</b> {consultoria}", normal),
         Paragraph(f"<b>Período:</b> {periodo_str}", normal)],
        [Paragraph(f"<b>Emissão:</b> {emissao_str}", normal),
         Paragraph(f"<b>Total de atividades:</b> {total_ativ}", normal)],
    ]
    info = Table(info_data, colWidths=[8.0*cm, 8.0*cm])
    info.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.8, colors.black),
        ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(info)
    story.append(Spacer(1, 12))

    # Apresentação (✅ frase EXATA)
    story.append(Paragraph("Apresentação", h2))
    apresentacao_txt = (
        "Este relatório tem como objetivo apresentar, de forma clara e objetiva, as atividades realizadas ao longo do ano, "
        "conforme o escopo contratual firmado entre as partes, evidenciando o cumprimento das obrigações legais em Segurança e "
        "Saúde do Trabalho (SST), bem como as ações preventivas implementadas para a melhoria contínua do ambiente laboral"
    )
    story.append(Paragraph(apresentacao_txt, normal))
    story.append(Spacer(1, 10))

    # Tabela: Atividades Realizadas
    story.append(Paragraph("Atividades Realizadas", h2))

    table_rows = [[
        Paragraph("<b>Data</b>", small),
        Paragraph("<b>Tarefa</b>", small),
        Paragraph("<b>Responsável</b>", small),
    ]]

    for it in items:
        data_str = it.created_at.strftime("%d/%m/%Y %H:%M") if it.created_at else "-"
        tarefa = it.task.title if it.task else "-"
        resp = it.user or "-"

        table_rows.append([
            Paragraph(data_str, small),
            Paragraph(tarefa, small),
            Paragraph(resp, small),
        ])

    tbl = Table(table_rows, colWidths=[3.8*cm, 8.8*cm, 3.4*cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(tbl)

    pdf.build(
        story,
        onFirstPage=draw_page_border,
        onLaterPages=draw_page_border
    )

    buff.seek(0)

    nome = f"relatorio_{ano_base}_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
    return send_file(buff, as_attachment=True, download_name=nome, mimetype="application/pdf")




# =====================================================
# EXECUTAR APLICAÇÃO
# =====================================================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    # 🔥 Permite acessar de outros PCs na mesma rede
    # Acesse de outro PC: http://IP_DO_SEU_PC:5000
    app.run(host="0.0.0.0", port=5000, debug=True)
