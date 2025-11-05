# app/models.py
from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.sql import func


# Flask-Login 需要这个函数来知道如何加载用户
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    # 告诉 SQLAlchemy 'id' 属性对应 'user_id' 列
    id = db.Column('user_id', db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum('internal', 'partner'), nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=func.now())

    analytics = db.relationship('IpAnalytics', back_populates='user')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # 覆盖 UserMixin 的 get_id，确保返回的是 user_id
    def get_id(self):
        return str(self.id)


class IpAsset(db.Model):
    __tablename__ = 'ip_assets'
    id = db.Column('ip_id', db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(100), default=None)
    description = db.Column(db.Text, default=None)
    image_url = db.Column(db.String(255), default=None)
    author = db.Column(db.String(100), default=None)
    ownership = db.Column(db.String(255), default=None)
    reg_number = db.Column(db.String(100), unique=True, default=None)
    reg_date = db.Column(db.Date, default=None)
    license_type_options = db.Column(db.String(255), default=None)
    value_level = db.Column(db.Enum('S', 'A', 'B', 'C'), default=None)
    internal_status = db.Column(db.String(50), default='可许可')
    cooperation_count = db.Column(db.Integer, default=0)

    contracts = db.relationship('Contract', back_populates='ip_asset')
    analytics = db.relationship('IpAnalytics', back_populates='ip_asset')


class Contract(db.Model):
    __tablename__ = 'contracts'
    id = db.Column('contract_id', db.Integer, primary_key=True)
    ip_id = db.Column(db.Integer, db.ForeignKey('ip_assets.ip_id'), nullable=False)
    partner_name = db.Column(db.String(255), nullable=False)
    region = db.Column(db.String(255), default=None)
    media = db.Column(db.String(255), default=None)
    usage_type = db.Column(db.String(255), default=None)
    license_type = db.Column(db.Enum('独占许可', '排他许可', '普通许可'), nullable=False)
    term_start = db.Column(db.Date, nullable=False)
    term_end = db.Column(db.Date, nullable=False)
    fee_standard = db.Column(db.Text, default=None)
    payment_cycle = db.Column(db.Text, default=None)
    breach_terms = db.Column(db.Text, default=None)

    ip_asset = db.relationship('IpAsset', back_populates='contracts')


class IpAnalytics(db.Model):
    __tablename__ = 'ip_analytics'
    id = db.Column('an_id', db.Integer, primary_key=True)
    ip_id = db.Column(db.Integer, db.ForeignKey('ip_assets.ip_id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=True)

    ip_asset = db.relationship('IpAsset', back_populates='analytics')
    user = db.relationship('User', back_populates='analytics')