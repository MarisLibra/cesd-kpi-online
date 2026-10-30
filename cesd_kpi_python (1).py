"""CESD KPI - Python API (FastAPI + SQLAlchemy).
Independent implementation of the core workflow in the provided Supabase SQL.
Not a literal replacement for PostgreSQL RLS, Supabase Auth, or Storage.
"""
from __future__ import annotations

import os
import hashlib
import secrets
import uuid
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from pathlib import Path
from fastapi.responses import FileResponse
from decimal import Decimal
from typing import Annotated, Literal

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from fastapi import Depends, FastAPI, HTTPException, UploadFile, File, Request
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import (
    JSON, Boolean, CheckConstraint, Column, Date, DateTime, Float, ForeignKey,
    Integer, String, Text, UniqueConstraint, create_engine, func, select,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./cesd_kpi.db')
JWT_SECRET = os.getenv('JWT_SECRET', '')
if len(JWT_SECRET) < 32:
    raise RuntimeError('Cần đặt biến môi trường JWT_SECRET (ít nhất 32 ký tự).')

is_sqlite = DATABASE_URL.startswith('sqlite')
engine = create_engine(DATABASE_URL, connect_args={'check_same_thread': False} if is_sqlite else {}, pool_pre_ping=True)
SessionLocal = sessionmaker(engine, expire_on_commit=False)
app = FastAPI(title='CESD - Quản lý công việc và KPI', version='1.0')
security = HTTPBearer()
ph = PasswordHasher()


def uid(): return str(uuid.uuid4())
def now(): return datetime.now(timezone.utc)
def today_vn(): return datetime.now(ZoneInfo("Asia/Ho_Chi_Minh")).date()
def error(msg, code=400): raise HTTPException(code, msg)
def require(cond, msg='Không có quyền', code=403):
    if not cond: error(msg, code)


class Base(DeclarativeBase): pass


class Department(Base):
    __tablename__ = 'departments'
    id = Column(String(36), primary_key=True, default=uid)
    code = Column(String(40), unique=True, nullable=False)
    name = Column(String(200), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)


class Position(Base):
    __tablename__ = 'positions'
    id = Column(String(36), primary_key=True, default=uid)
    code = Column(String(40), unique=True, nullable=False)
    name = Column(String(200), nullable=False)
    staff_group = Column(String(120))
    is_active = Column(Boolean, default=True, nullable=False)


class Employee(Base):
    __tablename__ = 'employees'
    id = Column(String(36), primary_key=True, default=uid)
    employee_code = Column(String(30), unique=True, nullable=False)
    full_name = Column(String(200), nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(Text, nullable=False)
    department_id = Column(String(36), ForeignKey('departments.id'), nullable=False)
    position_id = Column(String(36), ForeignKey('positions.id'), nullable=False)
    role = Column(String(15), default='user', nullable=False)
    status = Column(String(20), default='active', nullable=False)
    start_date = Column(Date)
    end_date = Column(Date)
    phone = Column(String(30))


class DepartmentManager(Base):
    __tablename__ = 'department_managers'
    department_id = Column(String(36), ForeignKey('departments.id'), primary_key=True)
    employee_id = Column(String(36), ForeignKey('employees.id'), primary_key=True)


class EmployeeHistory(Base):
    __tablename__ = 'employee_history'
    id = Column(String(36), primary_key=True, default=uid)
    employee_id = Column(String(36), ForeignKey('employees.id'), nullable=False)
    change_type = Column(String(40), nullable=False)
    old_value = Column(Text)
    new_value = Column(Text)
    actor_id = Column(String(36))
    created_at = Column(DateTime(timezone=True), default=now)


class Setting(Base):
    __tablename__ = 'app_settings'
    key = Column(String(100), primary_key=True)
    value = Column(JSON, nullable=False)


class CriteriaSet(Base):
    __tablename__ = 'kpi_criteria_sets'
    id = Column(String(36), primary_key=True, default=uid)
    name = Column(String(200), nullable=False)
    position_id = Column(String(36), ForeignKey('positions.id'))
    department_id = Column(String(36), ForeignKey('departments.id'))
    staff_group = Column(String(120))
    priority = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)


class RuleVersion(Base):
    __tablename__ = 'kpi_rule_versions'
    id = Column(String(36), primary_key=True, default=uid)
    set_id = Column(String(36), ForeignKey('kpi_criteria_sets.id'), nullable=False)
    version_no = Column(Integer, nullable=False)
    effective_from = Column(Date, nullable=False)
    effective_to = Column(Date)
    status = Column(String(20), default='draft')
    note = Column(Text)
    __table_args__ = (UniqueConstraint('set_id', 'version_no'),)


class Criterion(Base):
    __tablename__ = 'kpi_criteria'
    id = Column(String(36), primary_key=True, default=uid)
    rule_version_id = Column(String(36), ForeignKey('kpi_rule_versions.id'), nullable=False)
    code = Column(String(40), nullable=False)
    name = Column(String(200), nullable=False)
    description = Column(Text)
    weight = Column(Float, nullable=False)
    scale_max = Column(Float, default=10, nullable=False)
    method = Column(String(30), default='direct', nullable=False)
    sort_order = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    __table_args__ = (UniqueConstraint('rule_version_id', 'code'), CheckConstraint('weight > 0 AND weight <= 100'),)


class Rating(Base):
    __tablename__ = 'rating_levels'
    id = Column(String(36), primary_key=True, default=uid)
    name = Column(String(100), nullable=False)
    min_score = Column(Float, nullable=False)
    is_active = Column(Boolean, default=True)


class Task(Base):
    __tablename__ = 'tasks'
    id = Column(String(36), primary_key=True, default=uid)
    code = Column(String(40), unique=True, nullable=False)
    title = Column(String(300), nullable=False)
    content = Column(Text)
    department_id = Column(String(36), ForeignKey('departments.id'), nullable=False)
    assigner_id = Column(String(36), ForeignKey('employees.id'), nullable=False)
    assigned_date = Column(Date, default=date.today)
    due_date = Column(Date, nullable=False)
    priority = Column(String(15), default='normal')
    expected_output = Column(Text)
    acceptance_criteria = Column(Text)
    kpi_weight = Column(Float, default=1)
    is_cancelled = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=now)


class Assignment(Base):
    __tablename__ = 'task_assignments'
    id = Column(String(36), primary_key=True, default=uid)
    task_id = Column(String(36), ForeignKey('tasks.id'), nullable=False)
    employee_id = Column(String(36), ForeignKey('employees.id'), nullable=False)
    role_type = Column(String(15), default='collaborator')
    status = Column(String(30), default='not_started')
    progress_percent = Column(Integer, default=0)
    result_text = Column(Text)
    report_text = Column(Text)
    submitted_at = Column(DateTime(timezone=True))
    __table_args__ = (UniqueConstraint('task_id', 'employee_id'), CheckConstraint('progress_percent BETWEEN 0 AND 100'),)


class Evaluation(Base):
    __tablename__ = 'task_evaluations'
    id = Column(String(36), primary_key=True, default=uid)
    assignment_id = Column(String(36), ForeignKey('task_assignments.id'), nullable=False)
    evaluator_id = Column(String(36), ForeignKey('employees.id'), nullable=False)
    decision = Column(String(20), nullable=False)
    completion_percent = Column(Integer, nullable=False)
    quality_score = Column(Float)
    comment = Column(Text)
    eval_month = Column(Date, nullable=False)
    monthly_kpi_id = Column(String(36), ForeignKey('monthly_kpi.id'))
    created_at = Column(DateTime(timezone=True), default=now)


class MonthlyKPI(Base):
    __tablename__ = 'monthly_kpi'
    id = Column(String(36), primary_key=True, default=uid)
    employee_id = Column(String(36), ForeignKey('employees.id'), nullable=False)
    year = Column(Integer, nullable=False)
    month = Column(Integer, nullable=False)
    department_id = Column(String(36), ForeignKey('departments.id'), nullable=False)
    position_id = Column(String(36), ForeignKey('positions.id'), nullable=False)
    rule_version_id = Column(String(36), ForeignKey('kpi_rule_versions.id'), nullable=False)
    status = Column(String(30), default='awaiting_self')
    self_comment = Column(Text)
    manager_comment = Column(Text)
    admin_comment = Column(Text)
    self_total = Column(Float)
    manager_total = Column(Float)
    total_score = Column(Float)
    approved_by = Column(String(36))
    approved_at = Column(DateTime(timezone=True))
    locked_at = Column(DateTime(timezone=True))
    __table_args__ = (UniqueConstraint('employee_id', 'year', 'month'),)


class KPIDetail(Base):
    __tablename__ = 'monthly_kpi_details'
    id = Column(String(36), primary_key=True, default=uid)
    kpi_id = Column(String(36), ForeignKey('monthly_kpi.id'), nullable=False)
    criterion_id = Column(String(36), ForeignKey('kpi_criteria.id'), nullable=False)
    weight = Column(Float, nullable=False)
    scale_max = Column(Float, nullable=False)
    method = Column(String(30), nullable=False)
    sort_order = Column(Integer, default=0)
    auto_score = Column(Float)
    self_score = Column(Float)
    manager_score = Column(Float)
    final_score = Column(Float)
    self_note = Column(Text)
    manager_note = Column(Text)
    __table_args__ = (UniqueConstraint('kpi_id', 'criterion_id'),)


class AnnualKPI(Base):
    __tablename__ = 'annual_kpi'
    id = Column(String(36), primary_key=True, default=uid)
    employee_id = Column(String(36), ForeignKey('employees.id'), nullable=False)
    year = Column(Integer, nullable=False)
    department_id = Column(String(36), ForeignKey('departments.id'), nullable=False)
    position_id = Column(String(36), ForeignKey('positions.id'), nullable=False)
    month_scores = Column(JSON, default=dict)
    months_counted = Column(Integer, default=0)
    avg_score = Column(Float)
    rating = Column(String(100))
    comment = Column(Text)
    status = Column(String(30), default='draft')
    approved_by = Column(String(36))
    approved_at = Column(DateTime(timezone=True))
    __table_args__ = (UniqueConstraint('employee_id', 'year'),)


class ApprovalLog(Base):
    __tablename__ = 'approval_history'
    id = Column(String(36), primary_key=True, default=uid)
    entity_type = Column(String(40), nullable=False)
    entity_id = Column(String(36), nullable=False)
    action = Column(String(50), nullable=False)
    from_status = Column(String(30))
    to_status = Column(String(30))
    actor_id = Column(String(36))
    comment = Column(Text)
    created_at = Column(DateTime(timezone=True), default=now)


class AuditLog(Base):
    __tablename__ = 'audit_logs'
    id = Column(Integer, primary_key=True, autoincrement=True)
    table_name = Column(String(60), nullable=False)
    record_id = Column(String(36))
    action = Column(String(40), nullable=False)
    actor_id = Column(String(36))
    details = Column(JSON)
    created_at = Column(DateTime(timezone=True), default=now)


class TaskComment(Base):
    __tablename__ = 'task_comments'
    id = Column(String(36), primary_key=True, default=uid)
    task_id = Column(String(36), ForeignKey('tasks.id'), nullable=False)
    author_id = Column(String(36), ForeignKey('employees.id'), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=now)


class Attachment(Base):
    __tablename__ = 'task_attachments'
    id = Column(String(36), primary_key=True, default=uid)
    task_id = Column(String(36), ForeignKey('tasks.id'), nullable=False)
    assignment_id = Column(String(36), ForeignKey('task_assignments.id'))
    file_name = Column(String(250), nullable=False)
    mime_type = Column(String(120))
    size_bytes = Column(Integer, nullable=False)
    storage_path = Column(Text, unique=True, nullable=False)
    uploaded_by = Column(String(36), ForeignKey('employees.id'), nullable=False)
    created_at = Column(DateTime(timezone=True), default=now)


class AccountSecurity(Base):
    __tablename__ = 'account_security'
    employee_id = Column(String(36), ForeignKey('employees.id'), primary_key=True)
    token_version = Column(Integer, default=0, nullable=False)
    failed_logins = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime(timezone=True))


class ContentLock(Base):
    __tablename__ = 'content_locks'
    id = Column(String(36), primary_key=True, default=uid)
    entity_type = Column(String(40), nullable=False)
    entity_id = Column(String(36), nullable=False)
    reason = Column(Text)
    locked_by = Column(String(36), ForeignKey('employees.id'), nullable=False)
    locked_at = Column(DateTime(timezone=True), default=now)
    __table_args__ = (UniqueConstraint('entity_type','entity_id'),)


Base.metadata.create_all(engine)
with SessionLocal() as s:
    if not s.get(Setting, 'annual_min_months'):
        s.add_all([Setting(key='annual_min_months', value=1), Setting(key='allow_admin_self_approval', value=False)])
    if s.scalar(select(func.count()).select_from(Rating)) == 0:
        s.add_all([Rating(name=n, min_score=v) for n, v in [('Xuất sắc',90),('Tốt',80),('Hoàn thành',50),('Không hoàn thành',0)]])
    # CESD_ADMIN_EMAIL / CESD_ADMIN_PASSWORD: chỉ tạo tài khoản khi chưa có quản trị.
    # KHÔNG tự ghi đè mật khẩu mỗi lần Render khởi động, vì người dùng có thể đã đổi
    # mật khẩu trong ứng dụng. Khôi phục một lần bằng CESD_ADMIN_RESET_ID (xem dưới).
    admin_email = os.getenv('CESD_ADMIN_EMAIL', '').strip().lower()
    admin_pw = os.getenv('CESD_ADMIN_PASSWORD', '')
    reset_id = os.getenv('CESD_ADMIN_RESET_ID', '').strip()

    owner = s.scalar(select(Employee).where(Employee.role == 'owner'))
    any_admin = s.scalar(select(Employee.id).where(Employee.role.in_(['admin', 'owner'])))

    if admin_email and admin_pw and not any_admin:
        d = s.scalar(select(Department).where(Department.code == 'BGD'))
        p = s.scalar(select(Position).where(Position.code == 'GD'))
        if d is None:
            d = Department(code='BGD', name='Ban Giám đốc')
            s.add(d)
        if p is None:
            p = Position(code='GD', name='Giám đốc')
            s.add(p)
        s.flush()
        owner = Employee(
            employee_code='NV001', full_name='Quản trị CESD',
            email=admin_email, password_hash=ph.hash(admin_pw),
            department_id=d.id, position_id=p.id, role='owner',
        )
        s.add(owner)
        s.flush()

    # Khôi phục có chủ đích, đúng MỘT LẦN cho mỗi mã reset.
    # Chỉ người quản trị Render (có quyền sửa environment) mới có thể kích hoạt.
    # Không xóa hay tạo lại tài khoản: giữ nguyên employee ID và liên kết KPI.
    # Thay đổi CESD_ADMIN_PASSWORD đơn thuần KHÔNG kích hoạt reset.
    if reset_id:
        if len(reset_id) < 12:
            raise RuntimeError('CESD_ADMIN_RESET_ID phải có ít nhất 12 ký tự.')
        if not admin_email or len(admin_pw) < 12:
            raise RuntimeError('Khi khôi phục, cần CESD_ADMIN_EMAIL và CESD_ADMIN_PASSWORD (ít nhất 12 ký tự).')

        reset_fingerprint = hashlib.sha256(reset_id.encode('utf-8')).hexdigest()
        marker = s.get(Setting, 'owner_password_reset_fingerprint')
        if marker is None or marker.value != reset_fingerprint:
            if owner is None:
                raise RuntimeError('Không tìm thấy owner để khôi phục; cần kiểm tra tài khoản quản trị hiện có.')

            email_user = s.scalar(select(Employee).where(Employee.email == admin_email))
            if email_user is not None and email_user.id != owner.id:
                raise RuntimeError(
                    'Email CESD_ADMIN_EMAIL đang được dùng bởi tài khoản khác. '
                    'Không đổi chủ sở hữu tự động để tránh mất quyền hoặc sai dữ liệu.'
                )

            previous_email = owner.email
            owner.email = admin_email
            owner.password_hash = ph.hash(admin_pw)
            owner.status = 'active'

            sec = s.get(AccountSecurity, owner.id)
            if sec is None:
                sec = AccountSecurity(employee_id=owner.id, token_version=0)
                s.add(sec)
            sec.token_version += 1   # Thu hồi token đăng nhập cũ
            sec.failed_logins = 0    # Mở khóa sau khi khôi phục
            sec.locked_until = None

            s.add(AuditLog(
                table_name='employees', record_id=owner.id,
                action='owner_recovery_via_render',
                actor_id=None,
                details={'previous_email': previous_email, 'new_email': admin_email},
            ))
            if marker is None:
                s.add(Setting(key='owner_password_reset_fingerprint', value=reset_fingerprint))
            else:
                marker.value = reset_fingerprint
            print('CESD: owner recovery applied once; existing employee and KPI data preserved.')
    s.commit()


def db_session():
    with SessionLocal() as db:
        yield db

DB = Annotated[Session, Depends(db_session)]


def current_user(credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)], db: DB) -> Employee:
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=['HS256'])
        employee = db.get(Employee, payload['sub'])
        require(employee is not None and employee.status == 'active', 'Tài khoản không hợp lệ', 401)
        sec = db.get(AccountSecurity, employee.id)
        require(payload.get('ver', 0) == (sec.token_version if sec else 0), 'Phiên đăng nhập đã bị thu hồi', 401)
        return employee
    except (jwt.PyJWTError, KeyError):
        error('Token không hợp lệ hoặc đã hết hạn', 401)

User = Annotated[Employee, Depends(current_user)]


def by_id(db, cls, item_id):
    obj = db.get(cls, item_id)
    require(obj is not None, 'Không tìm thấy dữ liệu', 404)
    return obj


def is_admin(user): return user.role in ('admin', 'owner')
def is_owner(user): return user.role == 'owner'
def is_manager(db, user, dept_id):
    return user.role == 'manager' and db.get(DepartmentManager, (dept_id, user.id)) is not None

def manages_employee(db, user, emp_id):
    e = db.get(Employee, emp_id)
    return e is not None and is_manager(db, user, e.department_id)

def can_manage(db, user, emp_id): return is_admin(user) or manages_employee(db, user, emp_id)
def can_view_task(db, user, task):
    return (is_admin(user) or task.assigner_id == user.id or is_manager(db, user, task.department_id)
            or db.scalar(select(Assignment.id).where(Assignment.task_id == task.id, Assignment.employee_id == user.id)) is not None)

def can_view_kpi(db, user, kpi):
    return is_admin(user) or kpi.employee_id == user.id or manages_employee(db, user, kpi.employee_id)

def audit(db, actor, table, record, action, **details):
    db.add(AuditLog(table_name=table, record_id=record, action=action, actor_id=actor.id, details=details))

def transition(db, actor, typ, entity_id, action, previous, following, comment=None):
    db.add(ApprovalLog(entity_type=typ, entity_id=entity_id, action=action, from_status=previous,
                       to_status=following, actor_id=actor.id, comment=comment))
    audit(db, actor, typ, entity_id, action, from_status=previous, to_status=following)

def serialize(obj):
    return {column.name: (getattr(obj, column.name).isoformat() if isinstance(getattr(obj,column.name), (date,datetime)) else getattr(obj,column.name))
            for column in obj.__table__.columns if column.name != 'password_hash'}


class LoginIn(BaseModel):
    email: str
    password: str

@app.post('/auth/login')
def login(body: LoginIn, db: DB):
    e = db.scalar(select(Employee).where(Employee.email == body.email.strip().lower()))
    if not e or e.status != 'active': error('Sai email hoặc mật khẩu', 401)
    sec = db.get(AccountSecurity, e.id)
    if not sec:
        sec = AccountSecurity(employee_id=e.id); db.add(sec); db.flush()
    until = sec.locked_until
    if until and until.replace(tzinfo=timezone.utc) > now(): error('Tạm khóa đăng nhập. Thử lại sau 15 phút', 429)
    try: ph.verify(e.password_hash, body.password)
    except (VerifyMismatchError, VerificationError):
        sec.failed_logins += 1
        if sec.failed_logins >= 5:
            sec.locked_until = now() + timedelta(minutes=15)
            sec.failed_logins = 0
        db.commit()
        error('Sai email hoặc mật khẩu', 401)
    sec.failed_logins = 0; sec.locked_until = None; db.commit()
    token = jwt.encode({'sub': e.id, 'ver': sec.token_version, 'exp': now() + timedelta(hours=8)}, JWT_SECRET, algorithm='HS256')
    return {'access_token': token, 'token_type': 'bearer', 'role': e.role, 'full_name': e.full_name}


class NamedIn(BaseModel):
    code: str
    name: str

@app.post('/departments')
def create_department(body: NamedIn, db: DB, user: User):
    require(is_admin(user)); d = Department(code=body.code, name=body.name)
    db.add(d); db.flush(); audit(db,user,'departments',d.id,'create'); db.commit(); return serialize(d)

@app.post('/positions')
def create_position(body: NamedIn, db: DB, user: User):
    require(is_admin(user)); p = Position(code=body.code, name=body.name)
    db.add(p); db.flush(); audit(db,user,'positions',p.id,'create'); db.commit(); return serialize(p)


class EmployeeIn(BaseModel):
    employee_code: str
    full_name: str
    email: str
    password: str = Field(min_length=10)
    department_id: str
    position_id: str
    role: Literal['user','manager','admin'] = 'user'

@app.post('/employees')
def create_employee(body: EmployeeIn, db: DB, user: User):
    require(is_admin(user))
    require(body.role != 'admin' or is_owner(user), 'Chỉ chủ hệ thống được tạo quản trị viên')
    by_id(db,Department,body.department_id); by_id(db,Position,body.position_id)
    require(not db.scalar(select(Employee).where(Employee.email == body.email.lower())), 'Email đã tồn tại')
    e = Employee(**{k:v for k,v in body.model_dump().items() if k != 'password' and k != 'email'},
                 email=body.email.strip().lower(), password_hash=ph.hash(body.password))
    db.add(e); db.flush(); audit(db,user,'employees',e.id,'create'); db.commit(); return serialize(e)


class EmployeeUpdate(BaseModel):
    department_id: str | None = None
    position_id: str | None = None
    role: Literal['user','manager','admin'] | None = None
    status: Literal['active','inactive','resigned'] | None = None

@app.patch('/employees/{employee_id}')
def update_employee(employee_id: str, body: EmployeeUpdate, db: DB, user: User):
    require(is_admin(user)); e = by_id(db, Employee, employee_id)
    require(e.role != 'owner' or is_owner(user), 'Không được sửa tài khoản chủ hệ thống')
    require(not (body.role == 'admin' and not is_owner(user)), 'Chỉ chủ hệ thống cấp quyền quản trị')
    require(not (e.role == 'admin' and not is_owner(user)), 'Chỉ chủ hệ thống được sửa quản trị viên')
    require(not (e.role == 'owner' and body.role is not None), 'Không được thay đổi vai trò chủ hệ thống')
    require(not (e.id == user.id and body.status in ('inactive','resigned')), 'Không thể tự khóa tài khoản')
    for k, v in body.model_dump(exclude_none=True).items():
        if k in ('department_id','position_id'): by_id(db,Department if k == 'department_id' else Position,v)
        old = getattr(e,k)
        if old != v:
            db.add(EmployeeHistory(employee_id=e.id, change_type=k, old_value=str(old), new_value=str(v), actor_id=user.id))
            setattr(e,k,v)
    if e.status == 'resigned' and e.end_date is None: e.end_date = today_vn()
    if e.status == 'active': e.end_date = None
    audit(db,user,'employees',e.id,'update'); db.commit(); return serialize(e)


class ManagerIn(BaseModel):
    department_id: str
    employee_id: str

@app.post('/department-managers')
def add_manager(body: ManagerIn, db: DB, user: User):
    require(is_admin(user)); e = by_id(db,Employee,body.employee_id)
    require(e.role == 'manager', 'Nhân sự phải có vai trò manager')
    by_id(db,Department,body.department_id)
    if not db.get(DepartmentManager,(body.department_id,body.employee_id)):
        db.add(DepartmentManager(**body.model_dump()))
    audit(db,user,'department_managers',body.employee_id,'assign',department_id=body.department_id)
    db.commit(); return {'ok': True}

@app.get('/directory')
def directory(db: DB, user: User):
    return [{k:v for k,v in serialize(e).items() if k in ('id','employee_code','full_name','department_id','position_id')}
            for e in db.scalars(select(Employee).where(Employee.status == 'active')).all()]

@app.get('/employees')
def employees(db: DB, user: User):
    return [serialize(e) for e in db.scalars(select(Employee)).all()
            if is_admin(user) or e.id == user.id or is_manager(db,user,e.department_id)]


class TaskAssigneeIn(BaseModel):
    employee_id: str
    role_type: Literal['primary','collaborator']

class TaskIn(BaseModel):
    title: str = Field(min_length=1)
    content: str = ''
    department_id: str
    due_date: date
    priority: Literal['low','normal','high','urgent'] = 'normal'
    expected_output: str = ''
    acceptance_criteria: str = ''
    kpi_weight: float = Field(default=1, ge=0)
    assignees: list[TaskAssigneeIn] = Field(min_length=1)

@app.post('/tasks')
def create_task(body: TaskIn, db: DB, user: User):
    require(is_admin(user) or is_manager(db,user,body.department_id))
    require(body.due_date >= today_vn(), 'Ngày đến hạn trước ngày giao')
    require(sum(a.role_type == 'primary' for a in body.assignees) == 1, 'Cần đúng 1 người phụ trách chính')
    require(len({a.employee_id for a in body.assignees}) == len(body.assignees), 'Nhân sự bị trùng')
    for a in body.assignees:
        e = by_id(db,Employee,a.employee_id)
        require(e.status == 'active' and can_manage(db,user,e.id), 'Không thể phân công nhân sự này')
    t = Task(code='NV-' + str(today_vn().year) + '-' + uuid.uuid4().hex[:8].upper(),
             **body.model_dump(exclude={'assignees'}),assigner_id=user.id)
    db.add(t); db.flush()
    for a in body.assignees: db.add(Assignment(task_id=t.id,**a.model_dump()))
    transition(db,user,'task',t.id,'create',None,'not_started')
    db.commit(); return {'task_id':t.id,'code':t.code}

@app.get('/tasks')
def list_tasks(db: DB, user: User):
    result = []
    for t in db.scalars(select(Task).order_by(Task.due_date.desc())).all():
        if can_view_task(db,user,t):
            r = serialize(t)
            r['assignments'] = [serialize(a) for a in db.scalars(select(Assignment).where(Assignment.task_id==t.id)).all()]
            for a in r['assignments']:
                a['effective_status'] = 'overdue' if t.due_date < today_vn() and a['status'] in ('not_started','in_progress','needs_revision') else a['status']
            result.append(r)
    return result


class ProgressIn(BaseModel):
    progress_percent: int = Field(ge=0, le=100)
    result_text: str = ''

@app.post('/assignments/{aid}/progress')
def update_progress(aid: str, body: ProgressIn, db: DB, user: User):
    a = by_id(db,Assignment,aid)
    require(a.employee_id == user.id)
    require(a.status not in ('pending_acceptance','completed','approved'), 'Nhiệm vụ đang chờ/đã nghiệm thu')
    old = a.status
    a.progress_percent, a.result_text = body.progress_percent,body.result_text
    if a.status != 'needs_revision' and body.progress_percent > 0: a.status = 'in_progress'
    transition(db,user,'task_assignment',aid,'update_progress',old,a.status,str(body.progress_percent)+'%')
    db.commit(); return {'status':a.status}


class ReportIn(BaseModel):
    report_text: str = ''

@app.post('/assignments/{aid}/request-acceptance')
def request_acceptance(aid: str, body: ReportIn, db: DB, user: User):
    a = by_id(db,Assignment,aid)
    require(a.employee_id == user.id)
    require(a.status in ('not_started','in_progress','needs_revision'), 'Trạng thái không cho phép nghiệm thu')
    old=a.status; a.status='pending_acceptance'; a.report_text=body.report_text; a.submitted_at=now()
    transition(db,user,'task_assignment',aid,'request_acceptance',old,a.status,body.report_text)
    db.commit(); return {'status':a.status}


class EvaluateIn(BaseModel):
    decision: Literal['accepted','needs_revision','approved','rejected']
    completion_percent: int = Field(ge=0,le=100)
    quality_score: float | None = Field(default=None,ge=0,le=10)
    comment: str = ''

@app.post('/assignments/{aid}/evaluate')
def evaluate(aid: str, body: EvaluateIn, db: DB, user: User):
    a=by_id(db,Assignment,aid); t=by_id(db,Task,a.task_id)
    require(is_admin(user) or is_manager(db,user,t.department_id))
    require(user.id != a.employee_id,'Không được tự nghiệm thu')
    require(body.decision != 'approved' or is_admin(user),'Chỉ Admin duyệt cuối')
    require(a.status in ('pending_acceptance','completed'),'Chưa ở trạng thái cần nghiệm thu')
    old=a.status; a.status={'accepted':'completed','approved':'approved','needs_revision':'needs_revision','rejected':'needs_revision'}[body.decision]
    if a.status in ('completed','approved'): a.progress_percent=100
    e=Evaluation(assignment_id=aid,evaluator_id=user.id,decision=body.decision,
                 completion_percent=body.completion_percent,quality_score=body.quality_score,
                 comment=body.comment,eval_month=today_vn().replace(day=1))
    db.add(e); db.flush(); transition(db,user,'task_assignment',aid,'evaluate:'+body.decision,old,a.status,body.comment)
    db.commit(); return {'evaluation_id':e.id,'status':a.status}


class CommentIn(BaseModel):
    content: str = Field(min_length=1)

@app.post('/tasks/{tid}/comments')
def add_comment(tid: str, body: CommentIn, db: DB, user: User):
    t=by_id(db,Task,tid); require(can_view_task(db,user,t))
    c=TaskComment(task_id=tid,author_id=user.id,content=body.content)
    db.add(c); db.flush(); audit(db,user,'task_comments',c.id,'create'); db.commit(); return serialize(c)

@app.get('/tasks/{tid}/comments')
def list_comments(tid: str, db: DB, user: User):
    t=by_id(db,Task,tid); require(can_view_task(db,user,t))
    return [serialize(c) for c in db.scalars(select(TaskComment).where(TaskComment.task_id==tid).order_by(TaskComment.created_at)).all()]


class SetIn(BaseModel):
    name: str
    position_id: str | None = None
    department_id: str | None = None
    staff_group: str | None = None
    priority: int = 0

@app.post('/kpi/criteria-sets')
def create_set(body: SetIn, db: DB, user: User):
    require(is_admin(user)); x=CriteriaSet(**body.model_dump())
    db.add(x); db.flush(); audit(db,user,'kpi_criteria_sets',x.id,'create'); db.commit(); return serialize(x)

class VersionIn(BaseModel):
    set_id: str
    effective_from: date

@app.post('/kpi/rule-versions')
def create_version(body: VersionIn, db: DB, user: User):
    require(is_admin(user)); by_id(db,CriteriaSet,body.set_id)
    number=db.scalar(select(func.max(RuleVersion.version_no)).where(RuleVersion.set_id==body.set_id)) or 0
    v=RuleVersion(set_id=body.set_id,version_no=number+1,effective_from=body.effective_from)
    db.add(v); db.flush(); audit(db,user,'kpi_rule_versions',v.id,'create'); db.commit(); return serialize(v)

class CriterionIn(BaseModel):
    rule_version_id: str
    code: str
    name: str
    weight: float = Field(gt=0,le=100)
    scale_max: float = Field(default=10,gt=0)
    method: Literal['direct','completion_ratio','level','task_auto'] = 'direct'
    description: str = ''
    sort_order: int = 0

@app.post('/kpi/criteria')
def add_criterion(body: CriterionIn, db: DB, user: User):
    require(is_admin(user)); v=by_id(db,RuleVersion,body.rule_version_id)
    require(v.status=='draft','Phiên bản đã sử dụng, không thể sửa')
    c=Criterion(**body.model_dump()); db.add(c); db.flush()
    audit(db,user,'kpi_criteria',c.id,'create'); db.commit(); return serialize(c)

@app.post('/kpi/rule-versions/{vid}/activate')
def activate_version(vid: str, db: DB, user: User):
    require(is_admin(user)); v=by_id(db,RuleVersion,vid)
    require(v.status=='draft','Chỉ kích hoạt bản nháp')
    total=sum(c.weight for c in db.scalars(select(Criterion).where(Criterion.rule_version_id==vid, Criterion.is_active==True)))
    require(abs(total-100)<0.001, f'Tổng trọng số phải là 100%; đang là {total}')
    for old in db.scalars(select(RuleVersion).where(RuleVersion.set_id==v.set_id,RuleVersion.status=='active')).all():
        require(v.effective_from > old.effective_from,'Ngày hiệu lực không được lùi so với bản đang dùng')
        old.status='archived'; old.effective_to=v.effective_from-timedelta(days=1)
    v.status='active'; audit(db,user,'kpi_rule_versions',v.id,'activate'); db.commit(); return serialize(v)


class CloneIn(BaseModel):
    effective_from: date

@app.post('/kpi/rule-versions/{vid}/clone')
def clone_version(vid: str, body: CloneIn, db: DB, user: User):
    require(is_admin(user)); src=by_id(db,RuleVersion,vid)
    number=db.scalar(select(func.max(RuleVersion.version_no)).where(RuleVersion.set_id==src.set_id)) or 0
    v=RuleVersion(set_id=src.set_id,version_no=number+1,effective_from=body.effective_from,
                  status='draft',note=f'Sao chép từ phiên bản {src.version_no}')
    db.add(v); db.flush()
    for c in db.scalars(select(Criterion).where(Criterion.rule_version_id==vid)).all():
        db.add(Criterion(rule_version_id=v.id,code=c.code,name=c.name,description=c.description,
                         weight=c.weight,scale_max=c.scale_max,method=c.method,
                         sort_order=c.sort_order,is_active=c.is_active))
    audit(db,user,'kpi_rule_versions',v.id,'clone',source=vid)
    db.commit(); return serialize(v)


def resolve_rule(db, employee, target):
    eligible=[]
    for s,v in db.execute(select(CriteriaSet,RuleVersion).join(RuleVersion,CriteriaSet.id==RuleVersion.set_id)).all():
        if not s.is_active or v.status not in ('active','archived'): continue
        if s.position_id and s.position_id!=employee.position_id: continue
        if s.department_id and s.department_id!=employee.department_id: continue
        if s.staff_group:
            p=db.get(Position,employee.position_id)
            if not p or s.staff_group!=p.staff_group: continue
        if v.effective_from > target or (v.effective_to and v.effective_to < target): continue
        eligible.append((2*bool(s.position_id)+bool(s.department_id),s.priority,v.effective_from,v.id))
    return max(eligible)[3] if eligible else None


def refresh_auto(db, k):
    month_start=date(k.year,k.month,1)
    month_end=date(k.year+(k.month==12),k.month%12+1,1)
    assignment_ids=[a.id for a in db.scalars(select(Assignment).where(Assignment.employee_id==k.employee_id))]
    approved_evals=db.scalars(select(Evaluation).where(Evaluation.assignment_id.in_(assignment_ids),
                      Evaluation.eval_month==month_start,Evaluation.decision.in_(['accepted','approved']))
                      .order_by(Evaluation.created_at.desc())).all() if assignment_ids else []
    latest={}
    for e in approved_evals: latest.setdefault(e.assignment_id,e)
    numerator=denominator=0.
    for aid,e in latest.items():
        a=db.get(Assignment,aid); t=db.get(Task,a.task_id)
        numerator+=e.completion_percent*t.kpi_weight; denominator+=t.kpi_weight
        if e.monthly_kpi_id is None: e.monthly_kpi_id=k.id
    due=[]
    for a in db.scalars(select(Assignment).where(Assignment.employee_id==k.employee_id)):
        t=db.get(Task,a.task_id)
        if not t.is_cancelled and month_start <= t.due_date < month_end: due.append(a)
    ratio=sum(a.status in ('completed','approved') for a in due)/len(due) if due else None
    for d in db.scalars(select(KPIDetail).where(KPIDetail.kpi_id==k.id)):
        if d.method=='task_auto': d.auto_score=round(numerator/denominator/100*d.scale_max,2) if denominator else None
        if d.method=='completion_ratio': d.auto_score=round(ratio*d.scale_max,2) if ratio is not None else None


class MonthIn(BaseModel):
    year: int = Field(ge=2000,le=2100)
    month: int = Field(ge=1,le=12)

@app.post('/kpi/monthly/generate')
def generate_month(body: MonthIn, db: DB, user: User):
    require(is_admin(user)); first=date(body.year,body.month,1)
    month_end=date(body.year+(body.month==12),body.month%12+1,1)
    created=skipped=0
    for e in db.scalars(select(Employee).where(Employee.status=='active')).all():
        if e.start_date and e.start_date>=month_end: continue
        if db.scalar(select(MonthlyKPI.id).where(MonthlyKPI.employee_id==e.id,
                        MonthlyKPI.year==body.year,MonthlyKPI.month==body.month)): continue
        vid=resolve_rule(db,e,first)
        if not vid: skipped+=1; continue
        k=MonthlyKPI(employee_id=e.id,year=body.year,month=body.month,
                     department_id=e.department_id,position_id=e.position_id,rule_version_id=vid)
        db.add(k); db.flush()
        for c in db.scalars(select(Criterion).where(Criterion.rule_version_id==vid,Criterion.is_active==True)):
            db.add(KPIDetail(kpi_id=k.id,criterion_id=c.id,weight=c.weight,
                             scale_max=c.scale_max,method=c.method,sort_order=c.sort_order))
        db.flush(); refresh_auto(db,k); created+=1
        audit(db,user,'monthly_kpi',k.id,'generate')
    db.commit(); return {'created':created,'skipped_no_rule':skipped}

@app.get('/kpi/monthly')
def list_monthly(db: DB, user: User, year: int | None=None, month: int | None=None):
    stmt=select(MonthlyKPI)
    if year is not None: stmt=stmt.where(MonthlyKPI.year==year)
    if month is not None: stmt=stmt.where(MonthlyKPI.month==month)
    return [serialize(k) for k in db.scalars(stmt).all() if can_view_kpi(db,user,k)]

@app.get('/kpi/monthly/{kid}')
def get_monthly(kid: str, db: DB, user: User):
    k=by_id(db,MonthlyKPI,kid); require(can_view_kpi(db,user,k))
    out=serialize(k)
    out['details']=[serialize(d) for d in db.scalars(select(KPIDetail).where(KPIDetail.kpi_id==kid).order_by(KPIDetail.sort_order)).all()]
    return out

@app.post('/kpi/monthly/{kid}/refresh')
def refresh_kpi(kid: str, db: DB, user: User):
    k=by_id(db,MonthlyKPI,kid); require(can_view_kpi(db,user,k))
    require(k.status not in ('approved','locked'),'Phiếu đã duyệt')
    refresh_auto(db,k); audit(db,user,'monthly_kpi',kid,'refresh'); db.commit(); return {'ok':True}


class ScoreIn(BaseModel):
    score: float = Field(ge=0)
    note: str = ''

@app.put('/kpi/details/{did}/self')
def self_score(did: str, body: ScoreIn, db: DB, user: User):
    d=by_id(db,KPIDetail,did); k=by_id(db,MonthlyKPI,d.kpi_id)
    require(k.employee_id==user.id and k.status in ('awaiting_self','draft','revision_requested'))
    require(body.score<=d.scale_max,'Điểm vượt thang điểm')
    d.self_score=body.score; d.self_note=body.note
    audit(db,user,'monthly_kpi_details',did,'self_score'); db.commit(); return {'ok':True}

@app.put('/kpi/details/{did}/manager')
def manager_score(did: str, body: ScoreIn, db: DB, user: User):
    d=by_id(db,KPIDetail,did); k=by_id(db,MonthlyKPI,d.kpi_id)
    require(manages_employee(db,user,k.employee_id) and k.employee_id!=user.id and k.status=='awaiting_manager')
    require(body.score<=d.scale_max,'Điểm vượt thang điểm')
    d.manager_score=body.score; d.manager_note=body.note
    audit(db,user,'monthly_kpi_details',did,'manager_score'); db.commit(); return {'ok':True}

@app.put('/kpi/details/{did}/admin')
def final_score(did: str, body: ScoreIn, db: DB, user: User):
    require(is_admin(user)); d=by_id(db,KPIDetail,did); k=by_id(db,MonthlyKPI,d.kpi_id)
    require(k.status=='awaiting_admin','Phiếu chưa đến bước Admin')
    require(body.score<=d.scale_max,'Điểm vượt thang điểm')
    d.final_score=body.score
    audit(db,user,'monthly_kpi_details',did,'final_score'); db.commit(); return {'ok':True}


def weighted_total(details, field):
    return round(sum(getattr(d,field)/d.scale_max*d.weight for d in details),2)

class ReviewIn(BaseModel):
    comment: str = ''
    return_for_revision: bool = False

@app.post('/kpi/monthly/{kid}/submit-self')
def submit_self(kid: str, body: ReviewIn, db: DB, user: User):
    k=by_id(db,MonthlyKPI,kid)
    require(k.employee_id==user.id and k.status in ('draft','awaiting_self','revision_requested'))
    ds=db.scalars(select(KPIDetail).where(KPIDetail.kpi_id==kid)).all()
    require(ds and all(d.self_score is not None for d in ds),'Cần nhập đủ điểm tự đánh giá')
    k.self_total=weighted_total(ds,'self_score'); old=k.status
    k.status='awaiting_admin' if user.role=='manager' else 'awaiting_manager'
    k.self_comment=body.comment
    transition(db,user,'monthly_kpi',kid,'submit_self',old,k.status,body.comment)
    db.commit(); return {'status':k.status,'self_total':k.self_total}

@app.post('/kpi/monthly/{kid}/manager-review')
def review_manager(kid: str, body: ReviewIn, db: DB, user: User):
    k=by_id(db,MonthlyKPI,kid)
    require(manages_employee(db,user,k.employee_id) and k.employee_id!=user.id)
    require(k.status=='awaiting_manager','Chưa đến bước quản lý')
    ds=db.scalars(select(KPIDetail).where(KPIDetail.kpi_id==kid)).all()
    if not body.return_for_revision: require(ds and all(d.manager_score is not None for d in ds),'Thiếu điểm quản lý')
    if ds and all(d.manager_score is not None for d in ds): k.manager_total=weighted_total(ds,'manager_score')
    old=k.status; k.status='revision_requested' if body.return_for_revision else 'awaiting_admin'
    k.manager_comment=body.comment
    transition(db,user,'monthly_kpi',kid,'manager_review',old,k.status,body.comment)
    db.commit(); return {'status':k.status,'manager_total':k.manager_total}

@app.post('/kpi/monthly/{kid}/admin-approve')
def approve_month(kid: str, body: ReviewIn, db: DB, user: User):
    require(is_admin(user)); k=by_id(db,MonthlyKPI,kid)
    require(k.status=='awaiting_admin','Chưa đến bước Admin')
    allow=db.get(Setting,'allow_admin_self_approval')
    require(k.employee_id!=user.id or bool(allow and allow.value),'Admin không được tự phê duyệt')
    old=k.status; k.admin_comment=body.comment
    if body.return_for_revision: k.status='revision_requested'
    else:
        ds=db.scalars(select(KPIDetail).where(KPIDetail.kpi_id==kid)).all()
        for d in ds:
            if d.final_score is None: d.final_score=d.manager_score if d.manager_score is not None else d.auto_score
        require(ds and all(d.final_score is not None for d in ds),'Thiếu điểm cuối cùng')
        k.total_score=weighted_total(ds,'final_score')
        k.status='approved'; k.approved_at=now(); k.approved_by=user.id
    transition(db,user,'monthly_kpi',kid,'admin_return' if body.return_for_revision else 'admin_approve',old,k.status,body.comment)
    db.commit(); return {'status':k.status,'total_score':k.total_score}

@app.post('/kpi/monthly/lock')
def lock_month(body: MonthIn, db: DB, user: User):
    require(is_admin(user)); count=0
    for k in db.scalars(select(MonthlyKPI).where(MonthlyKPI.year==body.year,MonthlyKPI.month==body.month,
                                                   MonthlyKPI.status=='approved')):
        k.status='locked'; k.locked_at=now();count+=1
        transition(db,user,'monthly_kpi',k.id,'lock','approved','locked')
    db.commit(); return {'locked':count}


def rating_for(db,score):
    ratings=db.scalars(select(Rating).where(Rating.is_active==True).order_by(Rating.min_score.desc())).all()
    return next((r.name for r in ratings if score>=r.min_score),None)

class YearIn(BaseModel):
    year: int = Field(ge=2000,le=2100)

@app.post('/kpi/annual/refresh')
def annual_refresh(body: YearIn, db: DB, user: User):
    require(is_admin(user)); limit=db.get(Setting,'annual_min_months').value; count=0
    ids=db.scalars(select(MonthlyKPI.employee_id).where(MonthlyKPI.year==body.year).distinct()).all()
    for eid in ids:
        all_months=db.scalars(select(MonthlyKPI).where(MonthlyKPI.year==body.year,
                                MonthlyKPI.employee_id==eid).order_by(MonthlyKPI.month)).all()
        approved=[k for k in all_months if k.status in ('approved','locked') and k.total_score is not None]
        if len(approved)<limit: continue
        old=db.scalar(select(AnnualKPI).where(AnnualKPI.employee_id==eid,AnnualKPI.year==body.year))
        if old and old.status in ('approved','locked'): continue
        a=old or AnnualKPI(employee_id=eid,year=body.year)
        last=all_months[-1]; a.department_id=last.department_id; a.position_id=last.position_id
        a.month_scores={str(k.month):k.total_score for k in approved}
        a.months_counted=len(approved); a.avg_score=round(sum(k.total_score for k in approved)/len(approved),2)
        a.rating=rating_for(db,a.avg_score)
        if not old: db.add(a)
        count+=1
    db.commit(); return {'refreshed':count}

@app.get('/kpi/annual')
def list_annual(db: DB, user: User, year: int | None=None):
    query=select(AnnualKPI)
    if year: query=query.where(AnnualKPI.year==year)
    return [serialize(a) for a in db.scalars(query) if is_admin(user) or manages_employee(db,user,a.employee_id)
            or (a.employee_id==user.id and a.status in ('approved','locked'))]

@app.post('/kpi/annual/{aid}/approve')
def annual_approve(aid: str, body: ReviewIn, db: DB, user: User):
    require(is_admin(user)); a=by_id(db,AnnualKPI,aid)
    require(a.status not in ('approved','locked'),'Phiếu năm đã duyệt')
    old=a.status; a.status='approved'; a.rating=rating_for(db,a.avg_score)
    a.comment=body.comment; a.approved_by=user.id; a.approved_at=now()
    transition(db,user,'annual_kpi',aid,'approve',old,a.status,body.comment)
    db.commit(); return {'rating':a.rating,'avg_score':a.avg_score}


class SettingIn(BaseModel):
    value: int | bool

@app.put('/settings/{key}')
def update_setting(key: str, body: SettingIn, db: DB, user: User):
    require(is_admin(user))
    require(key in ('annual_min_months','allow_admin_self_approval'),'Không thể thay đổi cấu hình này')
    if key=='annual_min_months': require(type(body.value) is int and 1 <= body.value <= 12, 'Yêu cầu số tháng từ 1 đến 12')
    else: require(type(body.value) is bool,'Yêu cầu true hoặc false')
    x=by_id(db,Setting,key); x.value=body.value
    audit(db,user,'app_settings',key,'update',value=body.value)
    db.commit(); return {'key':key,'value':x.value}


class RatingIn(BaseModel):
    name: str
    min_score: float = Field(ge=0,le=100)

@app.post('/kpi/ratings')
def create_rating(body: RatingIn, db: DB, user: User):
    require(is_admin(user))
    r=Rating(**body.model_dump()); db.add(r); db.flush()
    audit(db,user,'rating_levels',r.id,'create'); db.commit(); return serialize(r)


# Lưu file lên máy chủ Python (không dùng Supabase Storage).
# Khi dùng nhiều máy chủ cần thay thư mục này bằng kho lưu trữ dùng chung.
UPLOAD_ROOT = Path(os.getenv('CESD_UPLOAD_DIR', './cesd_uploads')).resolve()

@app.post('/tasks/{tid}/attachments')
async def add_attachment(tid: str, db: DB, user: User, file: UploadFile = File(...)):
    t=by_id(db,Task,tid); require(can_view_task(db,user,t))
    # Không tin file name từ trình duyệt: chỉ giữ tên hiển thị, tên lưu sinh UUID.
    safe_name=Path((file.filename or 'tep-dinh-kem').replace('\\','/')).name[:250]
    require(bool(safe_name),'Tên file không hợp lệ')
    data=await file.read(10*1024*1024+1)
    require(len(data)<=10*1024*1024,'Tệp vượt quá 10 MB',413)
    directory=UPLOAD_ROOT/tid; directory.mkdir(parents=True,exist_ok=True)
    path=directory/uuid.uuid4().hex
    path.write_bytes(data)
    a=Attachment(task_id=tid,storage_path=str(path),file_name=safe_name,
                 mime_type=file.content_type,size_bytes=len(data),uploaded_by=user.id)
    db.add(a)
    try:
        db.flush(); audit(db,user,'task_attachments',a.id,'upload');db.commit()
    except Exception:
        db.rollback(); path.unlink(missing_ok=True); raise
    return {'id':a.id,'file_name':a.file_name,'size_bytes':a.size_bytes}

@app.get('/attachments/{attachment_id}')
def download_attachment(attachment_id: str, db: DB, user: User):
    a=by_id(db,Attachment,attachment_id)
    t=by_id(db,Task,a.task_id); require(can_view_task(db,user,t))
    require(Path(a.storage_path).is_file(),'Không tìm thấy tệp trên máy chủ',404)
    return FileResponse(a.storage_path,filename=a.file_name,media_type=a.mime_type or 'application/octet-stream')

@app.get('/audit')
def read_audit(db: DB, user: User, limit: int=100):
    require(is_admin(user)); return [serialize(x) for x in db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(min(limit,500)))]

@app.get('/approvals')
def read_approvals(db: DB, user: User):
    result=[]
    for x in db.scalars(select(ApprovalLog).order_by(ApprovalLog.created_at.desc()).limit(500)):
        if is_admin(user): result.append(serialize(x)); continue
        if x.entity_type=='task_assignment':
            a=db.get(Assignment,x.entity_id)
            if a and can_view_task(db,user,db.get(Task,a.task_id)): result.append(serialize(x))
        if x.entity_type=='monthly_kpi':
            k=db.get(MonthlyKPI,x.entity_id)
            if k and can_view_kpi(db,user,k): result.append(serialize(x))
    return result

# Chạy: uvicorn cesd_kpi_python:app --host 0.0.0.0 --port 8000
# Mở: http://127.0.0.1:8000/docs


# WEB APP + GOVERNANCE -------------------------------------------------------
from fastapi.responses import RedirectResponse

@app.get('/', response_class=HTMLResponse, include_in_schema=False)
def homepage():
    return Path(__file__).with_name('index.html').read_text(encoding='utf-8')

@app.get('/auth/me')
def auth_me(user: User):
    return {'id':user.id, 'full_name':user.full_name,'role':user.role,'email':user.email}

class PasswordChange(BaseModel):
    old_password: str
    new_password: str = Field(min_length=12)

@app.post('/auth/change-password')
def change_password(body: PasswordChange, db: DB, user: User):
    try: ph.verify(user.password_hash, body.old_password)
    except (VerifyMismatchError, VerificationError): error('Mật khẩu cũ không đúng', 400)
    user.password_hash = ph.hash(body.new_password)
    sec = db.get(AccountSecurity,user.id)
    if not sec: sec=AccountSecurity(employee_id=user.id,token_version=0);db.add(sec)
    sec.token_version += 1
    audit(db,user,'employees',user.id,'change_password'); db.commit()
    return {'ok':True, 'message':'Đăng nhập lại bằng mật khẩu mới'}

class ResetPassword(BaseModel):
    new_password: str = Field(min_length=12)

@app.post('/owner/users/{employee_id}/reset-password')
def owner_reset_password(employee_id: str, body: ResetPassword, db: DB, user: User):
    require(is_owner(user),'Chỉ chủ hệ thống')
    e=by_id(db,Employee,employee_id)
    e.password_hash=ph.hash(body.new_password)
    sec=db.get(AccountSecurity,e.id)
    if not sec: sec=AccountSecurity(employee_id=e.id,token_version=0);db.add(sec)
    sec.token_version+=1; sec.failed_logins=0; sec.locked_until=None
    audit(db,user,'employees',e.id,'reset_password');db.commit()
    return {'ok':True}

@app.post('/owner/users/{employee_id}/revoke-sessions')
def owner_revoke_sessions(employee_id: str,db: DB,user: User):
    require(is_owner(user),'Chỉ chủ hệ thống')
    by_id(db,Employee,employee_id)
    sec=db.get(AccountSecurity,employee_id)
    if not sec: sec=AccountSecurity(employee_id=employee_id,token_version=0);db.add(sec)
    sec.token_version+=1
    audit(db,user,'employees',employee_id,'revoke_sessions');db.commit()
    return {'ok':True}

class LockIn(BaseModel):
    entity_type: Literal['task','monthly_kpi','annual_kpi']
    entity_id: str
    reason: str = ''

@app.post('/owner/locks')
def lock_content(body: LockIn,db: DB,user: User):
    require(is_owner(user),'Chỉ chủ hệ thống được khóa nội dung')
    model={'task':Task,'monthly_kpi':MonthlyKPI,'annual_kpi':AnnualKPI}[body.entity_type]
    by_id(db,model,body.entity_id)
    require(not db.scalar(select(ContentLock).where(ContentLock.entity_type==body.entity_type,ContentLock.entity_id==body.entity_id)), 'Đã khóa')
    lock=ContentLock(**body.model_dump(),locked_by=user.id)
    db.add(lock); db.flush(); audit(db,user,'content_locks',lock.id,'lock',entity_type=lock.entity_type,entity_id=lock.entity_id)
    db.commit();return serialize(lock)

@app.get('/owner/locks')
def list_locks(db: DB,user: User):
    require(is_owner(user))
    return [serialize(x) for x in db.scalars(select(ContentLock).order_by(ContentLock.locked_at.desc())).all()]

@app.delete('/owner/locks/{lock_id}')
def unlock_content(lock_id: str,db: DB,user: User):
    require(is_owner(user),'Chỉ chủ hệ thống được mở khóa')
    lock=by_id(db,ContentLock,lock_id)
    audit(db,user,'content_locks',lock.id,'unlock',entity_type=lock.entity_type,entity_id=lock.entity_id)
    db.delete(lock); db.commit();return {'ok':True}

@app.middleware('http')
async def content_lock_guard(request: Request, call_next):
    # Block write operations to locked records at server-side, not merely hiding buttons.
    if request.method in ('POST','PUT','PATCH','DELETE'):
        parts=[p for p in request.url.path.split('/') if p]
        entity_type=entity_id=None
        if len(parts)>=2 and parts[0]=='tasks' and parts[1] not in ('',):
            entity_type,entity_id='task',parts[1]
        elif len(parts)>=2 and parts[0]=='assignments':
            with SessionLocal() as db:
                a=db.get(Assignment,parts[1]); entity_type,entity_id=('task',a.task_id) if a else (None,None)
        elif len(parts)>=3 and parts[:2]==['kpi','monthly'] and parts[2] not in ('generate','lock'):
            entity_type,entity_id='monthly_kpi',parts[2]
        elif len(parts)>=3 and parts[:2]==['kpi','annual'] and parts[2] not in ('refresh',):
            entity_type,entity_id='annual_kpi',parts[2]
        elif len(parts)>=3 and parts[:2]==['kpi','details']:
            with SessionLocal() as db:
                detail=db.get(KPIDetail,parts[2]); entity_type,entity_id=('monthly_kpi',detail.kpi_id) if detail else (None,None)
        if entity_id:
            with SessionLocal() as db:
                locked=db.scalar(select(ContentLock.id).where(ContentLock.entity_type==entity_type,ContentLock.entity_id==entity_id))
                if locked:
                    from fastapi.responses import JSONResponse
                    return JSONResponse({'detail':'Nội dung đã khóa bởi chủ hệ thống'},status_code=423)
    return await call_next(request)

@app.get('/departments-list')
def departments_list(db: DB, user: User):
    return [serialize(d) for d in db.scalars(select(Department).where(Department.is_active == True)).all()]

@app.get('/positions-list')
def positions_list(db: DB, user: User):
    return [serialize(p) for p in db.scalars(select(Position).where(Position.is_active == True)).all()]

class TaskEditIn(BaseModel):
    title: str | None = Field(default=None, min_length=1)
    content: str | None = None
    due_date: date | None = None
    priority: Literal['low','normal','high','urgent'] | None = None
    expected_output: str | None = None
    acceptance_criteria: str | None = None
    kpi_weight: float | None = Field(default=None, ge=0)

@app.patch('/tasks/{tid}')
def edit_task(tid: str, body: TaskEditIn, db: DB, user: User):
    t = by_id(db, Task, tid)
    require(is_admin(user) or is_manager(db,user,t.department_id), 'Không được sửa nhiệm vụ này')
    changed = body.model_dump(exclude_unset=True)
    if 'due_date' in changed: require(changed['due_date'] >= t.assigned_date, 'Hạn không hợp lệ')
    for key, value in changed.items():
        require(value is not None, 'Không được xóa trường bắt buộc') if key in ('title','due_date','priority','kpi_weight') else None
        setattr(t,key,value)
    audit(db,user,'tasks',tid,'edit',fields=list(changed))
    db.commit()
    return serialize(t)
