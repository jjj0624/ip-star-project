# app/__init__.py
from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = 'main.login' # 'main' 是蓝图名, 'login' 是路由函数名
login_manager.login_message = '请先登录以访问此页面。'
login_manager.login_message_category = 'info'

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    login_manager.init_app(app)

    # 注册蓝图
    from app.routes import bp as main_bp
    app.register_blueprint(main_bp)

    return app