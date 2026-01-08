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
from datetime import datetime, date, time
from zoneinfo import ZoneInfo
import os

# =====================================================
# TIMEZONE (CORRIGE +3H)
# =====================================================
TZ = ZoneInfo("America/Sao_Paulo")

def agora():
    return datetime.now(TZ)

# =====================================================
# SENHA MASTER DO SISTEMA (TEXTO PURO - INSEGURO)
# =====================================================
MASTER_PASSWORD = "26828021jJ*"

# =====================================================
# CONFIGURAÇÃO DO APP
# =====================================================

app = Flask(__name__)
app.config["SECRET_KEY"] = "secreto"
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL",
    "postgresql://jonatas:26828021jJ@localhost/contratos")

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
# EXECUTAR APLICAÇÃO
# =====================================================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    # 🔥 Permite acessar de outros PCs na mesma rede
    # Acesse de outro PC: http://IP_DO_SEU_PC:5000
    app.run(host="0.0.0.0", port=5000, debug=True)
