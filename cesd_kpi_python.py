"""CESD KPI - Python API (FastAPI + SQLAlchemy).
Independent implementation of the core workflow in the provided Supabase SQL.
Not a literal replacement for PostgreSQL RLS, Supabase Auth, or Storage.
"""
from __future__ import annotations

import os
import hashlib
import re
import secrets
from urllib.parse import quote
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
from fastapi import Depends, FastAPI, HTTPException, UploadFile, File, Form, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import (
    JSON, Boolean, CheckConstraint, Column, Date, DateTime, Float, ForeignKey,
    Integer, String, Text, LargeBinary, UniqueConstraint, create_engine, func, select,
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




# Separate tables: safe migration for an existing PostgreSQL database.
# SQLAlchemy create_all adds these tables without changing/deleting old KPI tables.
class TaskProgressEntry(Base):
    __tablename__ = 'task_progress_entries'
    id = Column(String(36), primary_key=True, default=uid)
    assignment_id = Column(String(36), ForeignKey('task_assignments.id'), nullable=False, index=True)
    author_id = Column(String(36), ForeignKey('employees.id'), nullable=False)
    progress_percent = Column(Integer, nullable=False)
    note = Column(Text, default='', nullable=False)
    created_at = Column(DateTime(timezone=True), default=now, nullable=False)
    __table_args__ = (CheckConstraint('progress_percent BETWEEN 0 AND 100'),)


class TaskProgressFile(Base):
    __tablename__ = 'task_progress_files'
    id = Column(String(36), primary_key=True, default=uid)
    progress_entry_id = Column(String(36), ForeignKey('task_progress_entries.id'), nullable=False, index=True)
    file_name = Column(String(250), nullable=False)
    mime_type = Column(String(120), nullable=False)
    size_bytes = Column(Integer, nullable=False)
    file_data = Column(LargeBinary, nullable=False)


class TaskDeletion(Base):
    __tablename__ = 'task_deletions'
    task_id = Column(String(36), ForeignKey('tasks.id'), primary_key=True)
    deleted_by = Column(String(36), ForeignKey('employees.id'), nullable=False)
    deleted_at = Column(DateTime(timezone=True), default=now, nullable=False)
    reason = Column(Text, nullable=False)


Base.metadata.create_all(engine)
with SessionLocal() as s:
    if not s.get(Setting, 'annual_min_months'):
        s.add_all([Setting(key='annual_min_months', value=1), Setting(key='allow_admin_self_approval', value=False)])
    if s.scalar(select(func.count()).select_from(Rating)) == 0:
        s.add_all([Rating(name=n, min_score=v) for n, v in [('Xuất sắc',90),('Tốt',80),('Hoàn thành',50),('Không hoàn thành',0)]])
    # CESD_ADMIN_EMAIL / CESD_ADMIN_PASSWORD: chỉ tạo tài khoản khi chưa có quản trị.
    # KHÔNG tự ghi đè mật khẩu mỗi lần Render khởi động, vì người dùng có thể đã đổi
    # mật khẩu trong ứng dụng. Khôi phục một lần bằng CESD_ADMIN_RESET_ID (xem dưới).
    # Official CESD structure and independent professional positions.
    # Existing codes are untouched; no employee's job title is altered.
    default_departments = [
        ('TCD', 'Tổ Công nghệ số và Dự báo Môi trường'),
        ('TKH', 'Tổ Khoa học và Công nghệ Môi trường'),
        ('TST', 'Tổ Sinh thái và Phát triển bền vững'),
        ('PTN', 'Phòng Thí nghiệm và Quan trắc Môi trường'),
    ]
    existing_department_codes = set(s.scalars(select(Department.code)).all())
    for code, name in default_departments:
        if code not in existing_department_codes:
            s.add(Department(code=code, name=name))
    default_positions = [
        ('PGD', 'Phó Giám đốc'),
        ('TRUONG_TO', 'Tổ trưởng chuyên môn'),
        ('PHO_TO', 'Tổ phó chuyên môn'),
        ('TRUONG_PTN', 'Trưởng phòng Thí nghiệm'),
        ('PHO_PTN', 'Phó Trưởng phòng Thí nghiệm'),
        ('NCVC', 'Nghiên cứu viên cao cấp'),
        ('NCVC_CHINH', 'Nghiên cứu viên chính'),
        ('NCV', 'Nghiên cứu viên'),
        ('KS', 'Kỹ sư'),
        ('KTV', 'Kỹ thuật viên'),
        ('CV', 'Chuyên viên'),
        ('NV', 'Nhân viên'),
    ]
    existing_position_codes = set(s.scalars(select(Position.code)).all())
    for code, name in default_positions:
        if code not in existing_position_codes:
            s.add(Position(code=code, name=name))

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


def is_task_deleted(db, task_id):
    return db.get(TaskDeletion, task_id) is not None


def by_id(db, cls, item_id):
    obj = db.get(cls, item_id)
    require(obj is not None, 'Không tìm thấy dữ liệu', 404)
    if cls is Task:
        require(not is_task_deleted(db, item_id), 'Nhiệm vụ đã chuyển vào thùng rác', 404)
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
    if task is None or is_task_deleted(db, task.id):
        return False
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
                if a['status'] == 'declined':
                    last_decline = db.scalar(select(ApprovalLog).where(
                        ApprovalLog.entity_type == 'task_assignment',
                        ApprovalLog.entity_id == a['id'],
                        ApprovalLog.action == 'decline',
                    ).order_by(ApprovalLog.created_at.desc()))
                    a['decline_reason'] = last_decline.comment if last_decline else ''
            result.append(r)
    return result


class ProgressIn(BaseModel):
    progress_percent: int = Field(ge=0, le=100)
    result_text: str = ''

def record_progress(db, assignment, actor, percent, note):
    by_id(db, Task, assignment.task_id)
    require(assignment.employee_id == actor.id, 'Chỉ người được giao mới cập nhật', 403)
    require(assignment.status in ('not_started','in_progress','needs_revision'),
            'Nhiệm vụ đã từ chối hoặc đang chờ/đã nghiệm thu', 409)
    old = assignment.status
    assignment.progress_percent = percent
    assignment.result_text = note
    if old != 'needs_revision' and percent > 0:
        assignment.status = 'in_progress'
    entry = TaskProgressEntry(assignment_id=assignment.id, author_id=actor.id,
                              progress_percent=percent, note=note)
    db.add(entry)
    db.flush()
    transition(db,actor,'task_assignment',assignment.id,'update_progress',old,
               assignment.status,f'{percent}%: {note[:200]}')
    return entry


@app.post('/assignments/{aid}/progress')
def update_progress(aid: str, body: ProgressIn, db: DB, user: User):
    a = by_id(db,Assignment,aid)
    entry = record_progress(db,a,user,body.progress_percent,body.result_text)
    db.commit()
    return {'status': a.status, 'progress_entry_id': entry.id}


class ReportIn(BaseModel):
    report_text: str = ''

@app.post('/assignments/{aid}/request-acceptance')
def request_acceptance(aid: str, body: ReportIn, db: DB, user: User):
    a = by_id(db,Assignment,aid)
    by_id(db, Task, a.task_id)  # Không cho nộp nghiệm thu nhiệm vụ đã xóa
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
        if t is None or is_task_deleted(db,t.id) or a.status=='declined': continue
        numerator+=e.completion_percent*t.kpi_weight; denominator+=t.kpi_weight
        if e.monthly_kpi_id is None: e.monthly_kpi_id=k.id
    due=[]
    for a in db.scalars(select(Assignment).where(Assignment.employee_id==k.employee_id)):
        t=db.get(Task,a.task_id)
        if not is_task_deleted(db,t.id) and not t.is_cancelled and a.status!='declined' and month_start <= t.due_date < month_end: due.append(a)
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
    # Preserve the complete existing UI without replacing index.html.
    original = Path(__file__).with_name('index.html').read_text(encoding='utf-8')
    head_script = INTEGRATED_LOGIN_BRIDGE
    if re.search(r'</head\s*>',original,re.I):
        html=re.sub(r'</head\s*>',lambda m: head_script + m.group(0), original,count=1,flags=re.I)
    else:
        html=head_script + original
    return HTMLResponse(content=html, headers={'Cache-Control':'no-store'})

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


# CESD WORKFLOW ENHANCEMENTS -----------------------------------------------
# Existing endpoints remain available to the original index.html.
MAX_PROGRESS_FILE_BYTES = 5 * 1024 * 1024
ALLOWED_PROGRESS_EXTENSIONS = {
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.txt', '.csv', '.png', '.jpg', '.jpeg', '.odt', '.ods',
}


class DeclineAssignmentIn(BaseModel):
    reason: str = Field(min_length=5, max_length=2000)


@app.post('/assignments/{aid}/decline')
def decline_assignment(aid: str, body: DeclineAssignmentIn, db: DB, user: User):
    assignment = by_id(db, Assignment, aid)
    task = by_id(db, Task, assignment.task_id)
    require(user.id == assignment.employee_id, 'Chỉ nhân sự được giao có thể từ chối', 403)
    require(assignment.status in ('not_started', 'in_progress', 'needs_revision'),
            'Nhiệm vụ không còn ở trạng thái có thể từ chối', 409)
    require(not task.is_cancelled, 'Nhiệm vụ đã hủy', 409)
    old = assignment.status
    assignment.status = 'declined'
    transition(db, user, 'task_assignment', aid, 'decline', old, 'declined', body.reason.strip())
    db.commit()
    return {'status': assignment.status, 'reason': body.reason.strip()}


class ReopenAssignmentIn(BaseModel):
    reason: str = Field(min_length=5, max_length=2000)


@app.post('/assignments/{aid}/reopen')
def reopen_declined_assignment(aid: str, body: ReopenAssignmentIn, db: DB, user: User):
    assignment = by_id(db, Assignment, aid)
    task = by_id(db, Task, assignment.task_id)
    require(is_admin(user) or task.assigner_id == user.id or is_manager(db, user, task.department_id),
            'Không có quyền xử lý nhiệm vụ bị từ chối', 403)
    require(assignment.status == 'declined', 'Chỉ mở lại nhiệm vụ đã bị từ chối', 409)
    assignment.status = 'not_started'
    assignment.progress_percent = 0
    transition(db, user, 'task_assignment', aid, 'reopen', 'declined', 'not_started', body.reason.strip())
    db.commit()
    return {'status': assignment.status}


class ReassignDeclinedIn(BaseModel):
    declined_assignment_id: str
    new_employee_id: str
    reason: str = Field(min_length=5, max_length=2000)


@app.post('/tasks/{tid}/reassign')
def reassign_declined_task(tid: str, body: ReassignDeclinedIn, db: DB, user: User):
    task = by_id(db, Task, tid)
    require(is_admin(user) or task.assigner_id == user.id or is_manager(db, user, task.department_id),
            'Không có quyền giao lại nhiệm vụ', 403)
    require(not task.is_cancelled, 'Nhiệm vụ đã hủy', 409)
    old_assignment = by_id(db, Assignment, body.declined_assignment_id)
    require(old_assignment.task_id == tid and old_assignment.status == 'declined',
            'Phải chọn phân công đã từ chối thuộc nhiệm vụ này', 409)
    target = by_id(db, Employee, body.new_employee_id)
    require(target.status == 'active', 'Nhân sự nhận việc phải đang hoạt động', 409)
    require(is_admin(user) or can_manage(db, user, target.id), 'Không được phân công nhân sự này', 403)
    require(target.id != old_assignment.employee_id,
            'Để giao lại cùng người, dùng chức năng Mở lại', 409)
    assigned = db.scalar(select(Assignment).where(
        Assignment.task_id == tid, Assignment.employee_id == target.id))
    if assigned:
        require(assigned.status == 'declined',
                'Nhân sự này đã được phân công trong nhiệm vụ', 409)
        assigned.status = 'not_started'
        assigned.progress_percent = 0
        assigned.role_type = old_assignment.role_type
    else:
        assigned = Assignment(task_id=tid, employee_id=target.id,
                              role_type=old_assignment.role_type, status='not_started')
        db.add(assigned)
        db.flush()
    transition(db, user, 'task_assignment', old_assignment.id, 'reassign',
               'declined', 'declined', f'{body.reason.strip()} | assigned_to={target.id}')
    transition(db, user, 'task_assignment', assigned.id, 'new_assignment', None,
               'not_started', body.reason.strip())
    db.commit()
    return {'ok': True, 'new_assignment_id': assigned.id}


@app.get('/assignments/{aid}/progress-history')
def assignment_progress_history(aid: str, db: DB, user: User):
    assignment = by_id(db, Assignment, aid)
    task = by_id(db, Task, assignment.task_id)
    require(can_view_task(db, user, task), 'Không được xem lịch sử công việc', 403)
    entries = db.scalars(select(TaskProgressEntry).where(
        TaskProgressEntry.assignment_id == aid).order_by(TaskProgressEntry.created_at.asc(),
                                                         TaskProgressEntry.id.asc())).all()
    result = []
    for entry in entries:
        row = serialize(entry)
        author = db.get(Employee, entry.author_id)
        row['author_name'] = author.full_name if author else ''
        files = db.scalars(select(TaskProgressFile).where(
            TaskProgressFile.progress_entry_id == entry.id)).all()
        row['files'] = [{'id': f.id, 'file_name': f.file_name,
                         'size_bytes': f.size_bytes} for f in files]
        result.append(row)
    return result


@app.post('/assignments/{aid}/progress-reports')
async def submit_progress_report(
    aid: str,
    db: DB,
    user: User,
    progress_percent: int = Form(..., ge=0, le=100),
    note: str = Form('', max_length=10000),
    file: UploadFile | None = File(None),
):
    assignment = by_id(db, Assignment, aid)
    file_name, file_bytes, content_type = None, None, None
    if file is not None and file.filename:
        file_name = Path(file.filename.replace('\\', '/')).name[:250]
        require(bool(file_name) and Path(file_name).suffix.lower() in ALLOWED_PROGRESS_EXTENSIONS,
                'Chỉ chấp nhận PDF, Office, văn bản hoặc ảnh (không nhận file thực thi)', 400)
        file_bytes = await file.read(MAX_PROGRESS_FILE_BYTES + 1)
        require(0 < len(file_bytes) <= MAX_PROGRESS_FILE_BYTES,
                'File báo cáo phải từ 1 byte đến 5 MB', 413)
        content_type = (file.content_type or 'application/octet-stream')[:120]
    require(bool(note.strip()) or file_bytes is not None,
            'Cần nhập nội dung cập nhật hoặc đính kèm báo cáo', 400)
    entry = record_progress(db, assignment, user, progress_percent, note.strip())
    if file_bytes is not None:
        db.add(TaskProgressFile(progress_entry_id=entry.id, file_name=file_name,
                                mime_type=content_type, size_bytes=len(file_bytes),
                                file_data=file_bytes))
    db.commit()
    return {'status': assignment.status, 'progress_entry_id': entry.id,
            'progress_percent': entry.progress_percent, 'file_uploaded': file_bytes is not None}


@app.get('/progress-files/{file_id}')
def download_progress_file(file_id: str, db: DB, user: User):
    doc = by_id(db, TaskProgressFile, file_id)
    entry = by_id(db, TaskProgressEntry, doc.progress_entry_id)
    assignment = by_id(db, Assignment, entry.assignment_id)
    task = by_id(db, Task, assignment.task_id)
    require(can_view_task(db, user, task), 'Không được tải file báo cáo', 403)
    # Header uses RFC 5987 encoding, protecting non-ASCII Vietnamese filenames.
    return Response(content=doc.file_data,
                    media_type='application/octet-stream',
                    headers={
                        'Content-Disposition': "attachment; filename*=UTF-8''" + quote(doc.file_name),
                        'X-Content-Type-Options': 'nosniff',
                        'Cache-Control': 'private, no-store',
                    })


class DeleteAssignedTaskIn(BaseModel):
    reason: str = Field(min_length=5, max_length=2000)


@app.delete('/tasks/{tid}')
def delete_assigned_task(tid: str, body: DeleteAssignedTaskIn, db: DB, user: User):
    task = by_id(db, Task, tid)
    require(is_admin(user) or task.assigner_id == user.id,
            'Chỉ quản trị hoặc người giao việc được xóa', 403)
    approved = db.scalar(select(Evaluation.id).join(
        Assignment, Evaluation.assignment_id == Assignment.id).where(
            Assignment.task_id == tid, Evaluation.decision == 'approved'))
    require(not approved or is_owner(user),
            'Nhiệm vụ đã duyệt cuối: chỉ chủ hệ thống được đưa vào thùng rác', 403)
    db.add(TaskDeletion(task_id=tid, deleted_by=user.id, reason=body.reason.strip()))
    transition(db, user, 'task', tid, 'soft_delete', 'active', 'deleted', body.reason.strip())
    db.commit()
    return {'ok': True, 'deleted': True, 'message': 'Đã chuyển nhiệm vụ vào thùng rác'}


@app.get('/tasks/deleted')
def list_deleted_tasks(db: DB, user: User):
    require(is_admin(user), 'Chỉ quản trị được xem thùng rác', 403)
    rows = db.scalars(select(TaskDeletion).order_by(TaskDeletion.deleted_at.desc())).all()
    result = []
    for deleted in rows:
        task = db.get(Task, deleted.task_id)
        if task:
            result.append({'id': task.id, 'code': task.code, 'title': task.title,
                           'deleted_at': deleted.deleted_at.isoformat() if deleted.deleted_at else '',
                           'reason': deleted.reason, 'deleted_by': deleted.deleted_by})
    return result


@app.post('/tasks/{tid}/restore')
def restore_deleted_task(tid: str, db: DB, user: User):
    require(is_admin(user), 'Chỉ quản trị được khôi phục', 403)
    deleted = db.get(TaskDeletion, tid)
    require(deleted is not None, 'Nhiệm vụ không nằm trong thùng rác', 404)
    db.delete(deleted)
    transition(db, user, 'task', tid, 'restore', 'deleted', 'active', 'Khôi phục nhiệm vụ')
    db.commit()
    return {'ok': True, 'restored': True}


INTEGRATED_LOGIN_BRIDGE = '<style>\n#cesd-main-nav{display:none;position:sticky;top:0;z-index:9990;background:#e9f2fe;border-bottom:1px solid #bad0ed;padding:10px 4%;gap:10px;align-items:center;font:600 14px Arial,sans-serif;box-shadow:0 1px 8px #082a4f12}\n#cesd-main-nav button{font:600 14px Arial,sans-serif;padding:11px 17px;border-radius:9px;cursor:pointer;border:1px solid #b6cbe5;color:#1a476f;background:#fff}\n#cesd-main-nav button.cesd-active{background:#174f87;color:white;border-color:#174f87}\n#cesd-main-nav .cesd-who{font-size:12px;color:#496a88;font-weight:400;margin-left:auto}\n#cesd-module-host{display:none;margin:0 auto;max-width:1400px;background:#f3f6fb;min-height:70vh}\n#cesd-module-frame{display:block;border:0;width:100%;min-height:750px;height:850px;background:#f3f6fb}\n@media(max-width:640px){#cesd-main-nav{padding:8px;gap:5px;flex-wrap:wrap}#cesd-main-nav button{padding:9px;font-size:12px}#cesd-main-nav .cesd-who{width:100%;margin:0}}\n</style>\n<script>\n(function(){\n \'use strict\';\n const ORIGIN=location.origin;\n const KEY=\'cesd_integrated_access_token\';\n let token=\'\',showing=false,authorized=false,frameReady=false,frame=null,nav=null,host=null;\n let name=\'\';\n const originalFetch=window.fetch.bind(window);\n const jToken=v=>typeof v===\'string\' && v.split(\'.\').length===3 && v.length>=40;\n function findStoredToken(){\n   // Only values from this application\'s origin; validate against /auth/me before use.\n   for(const store of [sessionStorage,localStorage]){\n     const preferred=[\'cesd_integrated_access_token\',\'cesd_kpi_token\',\'cesd_token\',\'access_token\',\'token\',\'cesd_tools_token\'];\n     const keys=[...preferred,...Array.from({length:store.length},(_,i)=>store.key(i)).filter(Boolean)];\n     for(const k of [...new Set(keys)]){\n       let value;try{value=store.getItem(k)}catch{continue}\n       if(jToken(value))return value;\n       if(value && value.startsWith(\'{\')){\n         try{const obj=JSON.parse(value);for(const prop of [\'access_token\',\'accessToken\',\'token\'])if(jToken(obj[prop]))return obj[prop]}catch{}\n       }\n     }\n   }\n   return \'\';\n }\n function sendToken(){if(frame&&frame.contentWindow&&frameReady)frame.contentWindow.postMessage({type:\'cesd-auth-token\',token},ORIGIN)}\n function putToken(t){\n   if(!jToken(t))return;\n   token=t;try{sessionStorage.setItem(KEY,token)}catch{}\n   verifyToken(token);\n }\n function clearToken(){\n   token=\'\';authorized=false;name=\'\';try{sessionStorage.removeItem(KEY)}catch{}\n   if(nav)nav.style.display=\'none\';sendToken();if(showing)activate(\'kpi\');\n }\n async function verifyToken(t){\n   try{const r=await originalFetch(\'/auth/me\',{headers:{Authorization:\'Bearer \'+t},cache:\'no-store\'});\n     if(!r.ok){if(t===token)clearToken();return}\n     const user=await r.json();if(t!==token)return;\n     authorized=true;name=user.full_name||\'\';if(nav){nav.style.display=\'flex\';nav.querySelector(\'.cesd-who\').textContent=name;}\n     sendToken();\n     if(location.hash===\'#cong-viec\' && !showing)activate(\'workflow\');\n   }catch(e){/* Temporary network errors should not destroy the session. */}\n }\n // Get the successful token from the ORIGINAL sign-in request, never inspect passwords.\n window.fetch=async function(...args){\n   const r=await originalFetch(...args);\n   let path=\'\';try{let input=args[0];path=new URL(typeof input===\'string\'?input:input.url,location.href).pathname}catch{}\n   if(path===\'/auth/login\' && r.ok){r.clone().json().then(x=>putToken(x.access_token||x.accessToken||x.token)).catch(()=>{});}\n   if(path===\'/auth/change-password\' && r.ok){clearToken();}\n   return r;\n };\n function activate(which){\n   if(which===\'workflow\'&&!authorized){return}\n   showing=(which===\'workflow\');\n   const a=document.getElementById(\'cesd-main-nav\');\n   const h=document.getElementById(\'cesd-module-host\');\n   if(!a||!h)return;\n   // Hide only original top-level content. Existing event handlers and app state survive.\n   for(const el of Array.from(document.body.children)){\n     if(el===a||el===h||el.tagName===\'SCRIPT\'||el.tagName===\'STYLE\')continue;\n     if(showing){if(!el.hasAttribute(\'data-cesd-prev-display\'))el.setAttribute(\'data-cesd-prev-display\',el.style.display||\'__empty__\');el.style.display=\'none\'}\n     else if(el.hasAttribute(\'data-cesd-prev-display\')){const prev=el.getAttribute(\'data-cesd-prev-display\');el.style.display=prev===\'__empty__\'?\'\':prev;el.removeAttribute(\'data-cesd-prev-display\')}\n   }\n   h.style.display=showing?\'block\':\'none\';\n   a.querySelector(\'#cesd-tab-kpi\').classList.toggle(\'cesd-active\',!showing);\n   a.querySelector(\'#cesd-tab-workflow\').classList.toggle(\'cesd-active\',showing);\n   if(showing){if(!frame.src || frame.src===\'about:blank\')frame.src=\'/cesd-workflow-embedded\';else sendToken();}\n   if(location.hash!==(showing?\'#cong-viec\':\'\'))history.replaceState(null,\'\',location.pathname+location.search+(showing?\'#cong-viec\':\'\'));\n }\n function init(){\n   nav=document.createElement(\'div\');nav.id=\'cesd-main-nav\';\n   nav.innerHTML=\'<button id="cesd-tab-kpi" class="cesd-active" type="button">Tổng quan / KPI</button><button id="cesd-tab-workflow" type="button">Công việc &amp; Tiến độ</button><span class="cesd-who"></span>\';\n   host=document.createElement(\'div\');host.id=\'cesd-module-host\';\n   frame=document.createElement(\'iframe\');frame.id=\'cesd-module-frame\';frame.title=\'Công việc, báo cáo tiến độ và nhân sự CESD\';frame.setAttribute(\'loading\',\'eager\');\n   host.appendChild(frame);document.body.prepend(host);document.body.prepend(nav);\n   nav.querySelector(\'#cesd-tab-kpi\').addEventListener(\'click\',()=>activate(\'kpi\'));\n   nav.querySelector(\'#cesd-tab-workflow\').addEventListener(\'click\',()=>activate(\'workflow\'));\n   const fromStorage=findStoredToken();if(fromStorage)putToken(fromStorage);\n   document.addEventListener(\'click\',e=>{\n     const btn=e.target.closest(\'button,a\');if(!btn || btn.closest(\'#cesd-main-nav\'))return;\n     if((btn.textContent||\'\').trim().toLowerCase().includes(\'đăng xuất\'))clearToken();\n   },true);\n }\n window.addEventListener(\'message\',e=>{\n   if(e.origin!==ORIGIN || !frame || e.source!==frame.contentWindow || !e.data)return;\n   if(e.data.type===\'cesd-module-ready\'){frameReady=true;sendToken()}\n   if(e.data.type===\'cesd-module-height\' && Number.isFinite(e.data.height))frame.style.height=Math.min(25000,Math.max(750,e.data.height+12))+\'px\';\n   if(e.data.type===\'cesd-session-expired\')clearToken();\n });\n if(document.readyState===\'loading\')document.addEventListener(\'DOMContentLoaded\',init,{once:true});else init();\n})();\n</script>'

INTEGRATED_WORKFLOW_PAGE = '<!doctype html>\n<html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">\n<title>CESD · Công việc & Báo cáo</title>\n<style>\n:root{font-family:Arial,"Segoe UI",sans-serif;color:#17304f;background:#f3f6fb}*{box-sizing:border-box}body{margin:0}header{background:#12375f;color:white;padding:19px 5%;display:flex;justify-content:space-between;gap:15px;align-items:center;flex-wrap:wrap}header strong{font-size:21px}header a{color:#dceaff;text-decoration:none}main{max-width:1180px;margin:25px auto;padding:0 18px}.card{background:white;border:1px solid #d8e2ed;border-radius:13px;padding:20px;margin-bottom:16px;box-shadow:0 2px 7px #08274608}h1{font-size:23px}h2{font-size:19px;margin:0 0 14px}h3{margin:12px 0 8px;font-size:16px}p{line-height:1.5}small,.muted{color:#56708d}.notice{padding:12px 15px;background:#e9f1fd;border-radius:8px;margin:12px 0;color:#164c86}.err{background:#fff1f1;color:#a32222}.ok{background:#e9f8ef;color:#206137}label{display:block;margin:9px 0 5px;font-weight:600;font-size:14px}input,select,textarea{font:inherit;border:1px solid #c8d4e5;border-radius:7px;padding:10px;width:100%;background:white;color:#153452}textarea{min-height:68px;resize:vertical}button,.btn{border:0;border-radius:8px;background:#1861a7;color:white;padding:11px 15px;font-weight:600;cursor:pointer;font-size:14px}button:hover{background:#134d85}button:disabled{opacity:.55;cursor:not-allowed}.mutebtn{background:#e5eef9;color:#173d65}.mutebtn:hover{background:#d3e3f6}.danger{background:#a53a3a}.danger:hover{background:#812e2e}.warning{background:#9a6116}.warning:hover{background:#775010}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(205px,1fr));gap:13px}.line{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.pill{display:inline-block;padding:5px 9px;border-radius:30px;background:#e4ecf4;font-size:12px;color:#1b436f}.task{border-top:1px solid #dce5f0;padding:17px 0}.task:first-child{border:0}nav{display:flex;gap:9px;flex-wrap:wrap;margin:18px 0}nav button{background:#dfe8f4;color:#143b65}nav button.active{background:#17548b;color:white}.assignee{border:1px solid #e0e8f0;padding:14px;border-radius:10px;margin-top:10px;background:#fafcff}.entry{padding:10px;border-left:3px solid #2775ae;background:#f3f7fc;margin:9px 0}.entry p{margin:6px 0;white-space:pre-wrap}.hidden{display:none!important}.inlineform{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.inlineform>*{flex:1}.inlineform button{flex:0 0 auto}.login{max-width:490px;margin:65px auto}.status{font-size:13px;color:#436181}.actions{display:flex;gap:9px;flex-wrap:wrap;margin-top:10px}.fieldnote{font-size:12px;color:#667b93;margin-top:5px}.section-title{margin-top:20px;border-bottom:1px solid #dce5ed;padding-bottom:10px}details summary{cursor:pointer;font-weight:600;color:#215c9a}footer{text-align:center;padding:28px;color:#607995;font-size:13px}@media(max-width:650px){header{padding:15px}main{padding:0 10px}.card{padding:14px}}\n</style></head><body>\n<header><strong>CESD · Công việc & Tiến độ</strong><span id="who"></span></header>\n<main>\n<section class="card login" id="loginHint"><h2>Sử dụng chung tài khoản CESD</h2><p class="muted">Bạn đăng nhập duy nhất tại trang KPI chính. Không cần đăng nhập lại khi chuyển sang Công việc & Tiến độ.</p></section>\n<section id="appPanel" class="hidden"><div class="notice">Lịch sử tiến độ và file báo cáo được lưu theo từng lần cập nhật. Xóa nhiệm vụ là chuyển vào thùng rác, không xóa vĩnh viễn.</div>\n<nav><button id="tab-tasks" onclick="showTab(\'tasks\')">Công việc & tiến độ</button><button id="tab-positions" onclick="showTab(\'positions\')">Chức danh / Nhân sự</button><button id="tab-trash" onclick="showTab(\'trash\')">Thùng rác</button><button class="mutebtn" onclick="refreshAll()">↻ Làm mới</button></nav>\n<section id="view-tasks" class="card"><h2>Nhiệm vụ được giao và tiến độ thực hiện</h2><p class="muted">Mỗi nhân viên tự cập nhật nhiều lần trên nhiệm vụ được phân công, kèm nội dung và tệp báo cáo. Mỗi lần gửi đều được lưu thành nhật ký riêng. Nhân viên có thể từ chối nhiệm vụ và ghi lý do.</p><div id="tasksArea">Đang tải dữ liệu...</div></section>\n<section id="view-positions" class="card hidden"><h2>Cơ cấu tổ chức và chức danh CESD</h2><div class="grid"><div><h3>Đơn vị</h3><div id="departmentsArea"></div></div><div><h3>Chức danh</h3><div id="positionsArea"></div></div></div>\n<div id="adminForms" class="hidden"><h3 class="section-title">Thêm đơn vị</h3><form id="departmentForm" class="grid"><div><label>Mã đơn vị</label><input name="code" required maxlength="40"></div><div><label>Tên đơn vị</label><input name="name" required maxlength="200"></div><div style="align-self:end"><button type="submit">Thêm đơn vị</button></div></form>\n<h3 class="section-title">Thêm chức danh</h3><form id="positionForm" class="grid"><div><label>Mã chức danh</label><input name="code" required maxlength="40"></div><div><label>Tên chức danh</label><input name="name" required maxlength="200"></div><div style="align-self:end"><button type="submit">Thêm chức danh</button></div></form>\n<h3 class="section-title">Tạo tài khoản nhân sự theo đơn vị và chức danh</h3><form id="employeeForm"><div class="grid"><div><label>Mã nhân viên</label><input name="employee_code" required maxlength="30"></div><div><label>Họ tên</label><input name="full_name" required maxlength="200"></div><div><label>Email</label><input name="email" type="email" required></div><div><label>Mật khẩu ban đầu (ít nhất 10 ký tự)</label><input name="password" type="password" minlength="10" required autocomplete="new-password"></div><div><label>Đơn vị</label><select name="department_id" id="employeeDepartment" required></select></div><div><label>Chức danh</label><select name="position_id" id="employeePosition" required></select></div><div><label>Quyền</label><select name="role"><option value="user">Nhân viên</option><option value="manager">Quản lý</option><option value="admin">Quản trị viên (owner mới được cấp)</option></select></div></div><div class="actions"><button type="submit">Tạo tài khoản</button></div></form></div></section>\n<section id="view-trash" class="card hidden"><h2>Thùng rác nhiệm vụ</h2><p class="muted">Chỉ quản trị viên được xem và khôi phục nhiệm vụ đã xóa.</p><div id="trashArea"></div></section>\n</section><div id="message" class="hidden notice" role="status"></div></main><footer>CESD · Một tài khoản · Một hệ thống · Nhật ký tiến độ được lưu theo từng lần</footer>\n<script>\n\'use strict\';\nconst S={token:\'\',user:null,tasks:[],employees:[],directory:[],departments:[],positions:[]};\nconst $=id=>document.getElementById(id);\nconst esc=s=>String(s??\'\').replace(/[&<>"\']/g,c=>({\'&\':\'&amp;\',\'<\':\'&lt;\',\'>\':\'&gt;\',\'"\':\'&quot;\',"\'":\'&#39;\'}[c]));\nconst labelStatus={not_started:\'Chưa thực hiện\',in_progress:\'Đang thực hiện\',needs_revision:\'Cần sửa\',pending_acceptance:\'Chờ nghiệm thu\',completed:\'Đã hoàn thành\',approved:\'Đã duyệt\',declined:\'Đã từ chối\',overdue:\'Quá hạn\'};\nconst isAdmin=()=>S.user&&[\'admin\',\'owner\'].includes(S.user.role);\nconst person=id=>(S.directory.find(x=>x.id===id)||S.employees.find(x=>x.id===id)||{}).full_name||id;\nconst dept=id=>(S.departments.find(x=>x.id===id)||{}).name||\'Không xác định\';\nfunction showMessage(msg,kind=\'\'){const e=$(\'message\');e.className=\'notice \'+(kind||\'\');e.textContent=msg;e.classList.remove(\'hidden\');window.scrollTo({top:0,behavior:\'smooth\'});}\nasync function api(path,opts={}){\n const headers={...(opts.headers||{}),...(S.token?{Authorization:\'Bearer \'+S.token}:{})};\n if(opts.body&&!(opts.body instanceof FormData)&&typeof opts.body!==\'string\'){headers[\'Content-Type\']=\'application/json\';opts.body=JSON.stringify(opts.body)}\n const r=await fetch(path,{...opts,headers,cache:\'no-store\'});let data;\n try{data=await r.json()}catch{data={detail:\'Lỗi kết nối máy chủ\'}}\n if(!r.ok){if(r.status===401){clearModuleSession();window.parent.postMessage({type:\'cesd-session-expired\'},location.origin);throw Error(\'Phiên đăng nhập hết hạn. Hãy đăng nhập lại tại trang KPI chính.\')}throw Error(typeof data.detail===\'string\'?data.detail:\'Yêu cầu không thành công (\'+r.status+\')\')}\n return data;\n}\nfunction clearModuleSession(){S.token=\'\';S.user=null;$(\'loginHint\').classList.remove(\'hidden\');$(\'appPanel\').classList.add(\'hidden\');$(\'who\').textContent=\'\';}\nasync function refreshAll(){\n try{\n S.user=await api(\'/auth/me\');\n const results=await Promise.all([api(\'/tasks\'),api(\'/directory\'),api(\'/departments-list\'),api(\'/positions-list\'),api(\'/employees\')]);\n [S.tasks,S.directory,S.departments,S.positions,S.employees]=results;\n $(\'who\').textContent=S.user.full_name+\' (\'+S.user.role+\')\';$(\'loginHint\').classList.add(\'hidden\');$(\'appPanel\').classList.remove(\'hidden\');\n $(\'adminForms\').classList.toggle(\'hidden\',!isAdmin());$(\'tab-trash\').classList.toggle(\'hidden\',!isAdmin());\n renderTasks();renderPositions();if(isAdmin())await renderTrash();showTab(\'tasks\');\n }catch(e){showMessage(e.message,\'err\')}\n}\nfunction showTab(tab){for(let id of [\'tasks\',\'positions\',\'trash\']){$(\'view-\'+id).classList.toggle(\'hidden\',id!==tab);$(\'tab-\'+id).classList.toggle(\'active\',id===tab)}}\nfunction renderTasks(){\n if(!S.tasks.length){$(\'tasksArea\').innerHTML=\'<p class="muted">Chưa có nhiệm vụ được phân công.</p>\';return}\n $(\'tasksArea\').innerHTML=S.tasks.map(t=>{\n const canDelete=isAdmin()||t.assigner_id===S.user.id;\n const as=t.assignments.map(a=>{\n const mine=a.employee_id===S.user.id;\n const canUpdate=mine&&[\'not_started\',\'in_progress\',\'needs_revision\'].includes(a.status);\n const canResolve=(isAdmin()||t.assigner_id===S.user.id||S.user.role===\'manager\')&&a.status===\'declined\';\n let html=`<div class="assignee"><div class="line"><strong>${esc(person(a.employee_id))}</strong><span class="pill">${esc(labelStatus[a.effective_status]||a.status)}</span><small>Tiến độ: ${Number(a.progress_percent)||0}%</small></div>`;\n if(a.decline_reason)html+=`<p class="notice err">Lý do từ chối: ${esc(a.decline_reason)}</p>`;\n if(canUpdate){html+=`<form onsubmit="submitProgress(event,\'${esc(a.id)}\')"><div class="grid"><div><label>Tiến độ (%)</label><input type="number" name="progress_percent" min="0" max="100" value="${Number(a.progress_percent)||0}" required></div><div><label>File báo cáo (tối đa 5 MB)</label><input type="file" name="file" accept=".pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.txt,.csv,.png,.jpg,.jpeg,.odt,.ods"></div></div><label>Nội dung cập nhật</label><textarea name="note" placeholder="Đã thực hiện, kết quả, khó khăn, kế hoạch tiếp theo..."></textarea><div class="actions"><button type="submit">Nhân viên: Lưu tiến độ / Nộp báo cáo</button><button type="button" class="warning" onclick="decline(\'${esc(a.id)}\')">Từ chối nhiệm vụ</button></div></form>`}\n if(canResolve){const opts=S.directory.filter(x=>x.id!==a.employee_id).map(x=>`<option value="${esc(x.id)}">${esc(x.full_name)}</option>`).join(\'\');html+=`<div class="actions"><button class="mutebtn" onclick="reopen(\'${esc(a.id)}\')">Mở lại cho người này</button></div><div class="inlineform"><select id="new-${esc(a.id)}"><option value="">-- Chọn nhân sự thay thế --</option>${opts}</select><button onclick="reassign(\'${esc(t.id)}\',\'${esc(a.id)}\')">Giao cho người khác</button></div>`}\n html+=`<details><summary onclick="loadHistory(\'${esc(a.id)}\')">Lịch sử cập nhật tiến độ</summary><div id="history-${esc(a.id)}" class="status">Nhấn để tải...</div></details></div>`;\n return html;\n }).join(\'\');\n return `<div class="task"><div class="line"><h3>${esc(t.title)}</h3><span class="pill">${esc(t.code)}</span></div><p class="muted">${esc(dept(t.department_id))} · Hạn: ${esc(t.due_date)} · Người giao: ${esc(person(t.assigner_id))}</p>${t.content?`<p>${esc(t.content)}</p>`:\'\'}${as}${canDelete?`<div class="actions"><button class="danger" onclick="deleteTask(\'${esc(t.id)}\')">Xóa nhiệm vụ (vào thùng rác)</button></div>`:\'\'}</div>`;\n }).join(\'\');\n}\nasync function submitProgress(e,aid){e.preventDefault();const f=new FormData(e.currentTarget);const file=f.get(\'file\');if(file&&(!file.name||file.size===0))f.delete(\'file\');if(!String(f.get(\'note\')||\'\').trim()&&!f.has(\'file\')){showMessage(\'Hãy nhập nội dung hoặc chọn file báo cáo.\',\'err\');return}if(f.has(\'file\')&&file.size>5*1024*1024){showMessage(\'File vượt quá 5 MB.\',\'err\');return}const b=e.submitter;b.disabled=true;try{await api(\'/assignments/\'+aid+\'/progress-reports\',{method:\'POST\',body:f});showMessage(\'Đã lưu một lần cập nhật mới và file báo cáo (nếu có).\',\'ok\');await refreshAll()}catch(err){showMessage(err.message,\'err\')}finally{b.disabled=false}}\nasync function loadHistory(aid){const h=$(\'history-\'+aid);if(!h)return;h.textContent=\'Đang tải...\';try{let rows=await api(\'/assignments/\'+aid+\'/progress-history\');h.innerHTML=rows.length?rows.map(x=>`<div class="entry"><small>${esc(new Date(x.created_at).toLocaleString(\'vi-VN\'))} · ${esc(x.author_name)}</small><b> · ${x.progress_percent}%</b><p>${esc(x.note)}</p>${x.files.map(f=>`<button class="mutebtn" onclick="downloadProgress(\'${esc(f.id)}\',\'${esc(f.file_name)}\')">↓ ${esc(f.file_name)}</button>`).join(\'\')}</div>`).join(\'\'):\'Chưa có lịch sử tiến độ trước khi nâng cấp.\'}catch(err){h.textContent=err.message}}\nasync function downloadProgress(id,name){try{let r=await fetch(\'/progress-files/\'+encodeURIComponent(id),{headers:{Authorization:\'Bearer \'+S.token}});if(!r.ok)throw Error(\'Không tải được file (\'+r.status+\')\');let url=URL.createObjectURL(await r.blob()),a=document.createElement(\'a\');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),2000)}catch(e){showMessage(e.message,\'err\')}}\nasync function decline(aid){let reason=prompt(\'Nhập lý do từ chối nhiệm vụ (tối thiểu 5 ký tự):\');if(reason===null)return;try{await api(\'/assignments/\'+aid+\'/decline\',{method:\'POST\',body:{reason}});showMessage(\'Đã ghi nhận từ chối và lưu lý do. Người giao việc có thể giao lại.\',\'ok\');await refreshAll()}catch(e){showMessage(e.message,\'err\')}}\nasync function reopen(aid){let reason=prompt(\'Nhập lý do mở lại nhiệm vụ:\');if(reason===null)return;try{await api(\'/assignments/\'+aid+\'/reopen\',{method:\'POST\',body:{reason}});showMessage(\'Đã mở lại nhiệm vụ.\',\'ok\');await refreshAll()}catch(e){showMessage(e.message,\'err\')}}\nasync function reassign(tid,aid){let id=$(\'new-\'+aid).value;if(!id){showMessage(\'Chọn nhân sự thay thế trước.\',\'err\');return}let reason=prompt(\'Nhập lý do giao lại:\');if(reason===null)return;try{await api(\'/tasks/\'+tid+\'/reassign\',{method:\'POST\',body:{declined_assignment_id:aid,new_employee_id:id,reason}});showMessage(\'Đã giao lại nhiệm vụ và lưu lịch sử.\',\'ok\');await refreshAll()}catch(e){showMessage(e.message,\'err\')}}\nasync function deleteTask(tid){if(!confirm(\'Bạn muốn chuyển nhiệm vụ này vào thùng rác? Dữ liệu lịch sử sẽ được giữ lại.\'))return;const reason=prompt(\'Nhập lý do xóa nhiệm vụ:\');if(reason===null)return;try{await api(\'/tasks/\'+tid,{method:\'DELETE\',body:{reason}});showMessage(\'Đã chuyển nhiệm vụ vào thùng rác.\',\'ok\');await refreshAll()}catch(e){showMessage(e.message,\'err\')}}\nasync function renderTrash(){try{let rows=await api(\'/tasks/deleted\');$(\'trashArea\').innerHTML=rows.length?rows.map(x=>`<div class="task"><b>${esc(x.code)} · ${esc(x.title)}</b><p class="muted">${esc(x.reason)} · ${esc(x.deleted_at)}</p><button onclick="restoreTask(\'${esc(x.id)}\')">Khôi phục</button></div>`).join(\'\'):\'<p>Thùng rác trống.</p>\'}catch(e){$(\'trashArea\').textContent=e.message}}\nasync function restoreTask(id){try{await api(\'/tasks/\'+id+\'/restore\',{method:\'POST\'});showMessage(\'Đã khôi phục nhiệm vụ.\',\'ok\');await refreshAll();showTab(\'trash\')}catch(e){showMessage(e.message,\'err\')}}\nfunction renderPositions(){$(\'departmentsArea\').innerHTML=S.departments.map(x=>`<div class="entry"><strong>${esc(x.name)}</strong><br><small>${esc(x.code)}</small></div>`).join(\'\');$(\'positionsArea\').innerHTML=S.positions.map(x=>`<div class="entry"><strong>${esc(x.name)}</strong><br><small>${esc(x.code)}</small></div>`).join(\'\');$(\'employeeDepartment\').innerHTML=S.departments.map(x=>`<option value="${esc(x.id)}">${esc(x.name)}</option>`).join(\'\');$(\'employeePosition\').innerHTML=S.positions.map(x=>`<option value="${esc(x.id)}">${esc(x.name)}</option>`).join(\'\')}\nfor(const [id,path] of [[\'departmentForm\',\'/departments\'],[\'positionForm\',\'/positions\'],[\'employeeForm\',\'/employees\']]){$(id).addEventListener(\'submit\',async e=>{e.preventDefault();const data=Object.fromEntries(new FormData(e.currentTarget).entries());try{await api(path,{method:\'POST\',body:data});e.currentTarget.reset();showMessage(\'Đã cập nhật dữ liệu.\',\'ok\');await refreshAll();showTab(\'positions\')}catch(err){showMessage(err.message,\'err\')}})}\n\n// Chỉ nhận JWT từ trang chủ CÙNG ORIGIN và đúng frame cha.\nwindow.addEventListener(\'message\', e=>{\n if(e.origin!==location.origin || e.source!==window.parent || !e.data)return;\n if(e.data.type===\'cesd-auth-token\'){\n   const received=typeof e.data.token===\'string\'?e.data.token:\'\';\n   if(!received){clearModuleSession();return;}\n   if(received!==S.token || !S.user){S.token=received;refreshAll();}\n }\n});\nfunction signalHeight(){\n const h=Math.max(document.body.scrollHeight,document.documentElement.scrollHeight);\n if(window.parent!==window)window.parent.postMessage({type:\'cesd-module-height\',height:h},location.origin);\n}\nif(window.ResizeObserver)new ResizeObserver(signalHeight).observe(document.body);\nwindow.addEventListener(\'load\',signalHeight);\nwindow.parent.postMessage({type:\'cesd-module-ready\'},location.origin);\n\n</script></body></html>\n'

@app.get('/cesd-workflow-embedded', response_class=HTMLResponse, include_in_schema=False)
def embedded_workflow():
    return HTMLResponse(INTEGRATED_WORKFLOW_PAGE, headers={
        'Cache-Control': 'no-store', 'X-Frame-Options': 'SAMEORIGIN',
        'Content-Security-Policy': "frame-ancestors 'self'",
    })

@app.get('/cesd-workflow', include_in_schema=False)
def workflow_legacy_redirect():
    return RedirectResponse('/#cong-viec', status_code=302)
