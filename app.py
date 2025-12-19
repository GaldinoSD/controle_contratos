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
from datetime import datetime, date,time
import os

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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
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
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)


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

    # Responsável
    assigned_to = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
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

    # 🔥 ETAPAS (CORRIGIDO)
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
        self.completed_at = datetime.utcnow()

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
        default=datetime.utcnow,
        nullable=False
    )

    # 🔁 RELACIONAMENTOS (SEM backref)
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

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User")
    files = db.relationship("TaskFile", backref="log", cascade="all, delete-orphan")


class TaskFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_log_id = db.Column(db.Integer, db.ForeignKey("task_log.id"))
    file_path = db.Column(db.String(255))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)


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
# EDITAR CONTRATO (DADOS BÁSICOS / VIGÊNCIA)
# =====================================================

@app.route("/contracts/edit/<int:id>", methods=["POST"])
@login_required
def edit_contract(id):
    contrato = Contract.query.get_or_404(id)
    empresa = contrato.company  # pega a empresa vinculada

    # Atualiza dados da empresa
    nome = request.form.get("company")
    cnpj = request.form.get("cnpj")

    if nome:
        empresa.name = nome
    if cnpj:
        empresa.cnpj = cnpj

    # Atualiza dados do contrato
    descricao = request.form.get("desc")
    inicio = request.form.get("start")
    fim = request.form.get("end")

    if descricao is not None:
        contrato.description = descricao
    if inicio:
        contrato.start_date = inicio
    if fim:
        contrato.end_date = fim

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
# UPLOAD DE ARQUIVOS DO CONTRATO — MÚLTIPLOS
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
# TAREFA – REGISTRAR ETAPA (TaskStep)  ✅ ROTA ÚNICA
# URL: /task/<task_id>/add-step
# =====================================================

@app.route("/task/<int:task_id>/add-step", methods=["POST"])
@login_required
def add_task_step(task_id):

    task = Task.query.get_or_404(task_id)

    # Campo do formulário
    description = request.form.get("step_description")
    file = request.files.get("file")

    if not description:
        flash("Descrição da etapa é obrigatória.", "error")
        return redirect(request.referrer or f"/contract/{task.contract_id}")

    # Upload opcional
    file_path = None
    if file and file.filename:
        upload_folder = app.config["UPLOAD_FOLDER"]

        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)

        filename = secure_filename(file.filename)
        file_path = os.path.join(upload_folder, filename)
        file.save(file_path)

    # ✅ CRIA ETAPA COM USUÁRIO LOGADO
    etapa = TaskStep(
        task_id=task.id,
        user_id=current_user.id,   # 🔥 CORREÇÃO PRINCIPAL
        description=description,
        file_path=file_path,
        created_at=datetime.utcnow()
    )

    # Regra de negócio: pendente → andamento
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

    # ================= CONCLUSÃO =================
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

    # ================= ETAPAS =================
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

    # STATUS FINAL
    task.status = "concluida"
    task.completed_at = datetime.utcnow()

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

    # Apenas admin acessa
    if current_user.role != "admin":
        return redirect("/")

    admin = User.query.get_or_404(id)

    nome = request.form.get("nome")
    novo_email = request.form.get("email")
    nova_senha = request.form.get("senha")

    # ==============================
    # ADMIN MASTER
    # ==============================
    if admin.email == "admin@admin.com":

        senha_master = request.form.get("senha_master")

        # senha master obrigatória
        if not senha_master:
            flash("❌ Senha master obrigatória para editar este administrador.", "error")
            return redirect("/administradores")

        # 🔐 VALIDA SENHA MASTER DEFINIDA NO BACKEND (TEXTO)
        if senha_master != MASTER_PASSWORD:
            flash("❌ Senha master inválida.", "error")
            return redirect("/administradores")

        # pode alterar SOMENTE nome e senha
        admin.name = nome

        if nova_senha:
            admin.password = generate_password_hash(nova_senha)

    # ==============================
    # ADMIN COMUM
    # ==============================
    else:
        # verifica e-mail duplicado
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

    empresa_id = request.args.get("empresa_id")

    query = Task.query.filter(
        Task.status.in_(["pendente", "andamento"]),
        ((Task.assigned_to == current_user.id) | (Task.assigned_to == None))
    )

    # 🔥 FILTRO POR EMPRESA
    if empresa_id:
        query = query.join(Task.contract).filter(
            Contract.company_id == int(empresa_id)
        )

    tarefas = query.order_by(Task.id.desc()).all()

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

    # 🔥 LISTA DE EMPRESAS PARA O SELECT
    empresas = Company.query.order_by(Company.name).all()

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

    # ======================
    # PARAMETROS GET
    # ======================
    empresa_id = request.args.get("empresa")
    colaborador_id = request.args.get("colaborador")
    periodo = request.args.get("periodo")

    # ======================
    # QUERY BASE
    # ======================
    query = (
        TaskLog.query
        .join(Task)
        .join(Contract)
        .join(Company)
    )

    # ======================
    # CONTROLE DE ACESSO
    # ======================
    if current_user.role != "admin":
        query = query.filter(TaskLog.user_id == current_user.id)

    # ======================
    # FILTRO EMPRESA
    # ======================
    if empresa_id:
        query = query.filter(Company.id == empresa_id)

    # ======================
    # FILTRO COLABORADOR
    # ======================
    if colaborador_id:
        query = query.filter(TaskLog.user_id == colaborador_id)

    # ======================
    # FILTRO PERÍODO (CORRIGIDO)
    # ======================
    if periodo and " até " in periodo:
        try:
            inicio_str, fim_str = periodo.split(" até ")

            data_inicio = datetime.strptime(inicio_str.strip(), "%d/%m/%Y")
            data_fim = datetime.strptime(fim_str.strip(), "%d/%m/%Y")

            # Pega o dia inteiro
            data_inicio = datetime.combine(data_inicio, time.min)
            data_fim = datetime.combine(data_fim, time.max)

            query = query.filter(
                TaskLog.created_at.between(data_inicio, data_fim)
            )

        except ValueError:
            pass  # não quebra se vier inválido

    # ======================
    # RESULTADO FINAL
    # ======================
    logs = query.order_by(TaskLog.created_at.desc()).all()

    # ======================
    # DADOS PARA OS FILTROS
    # ======================
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
    app.run(debug=True)
