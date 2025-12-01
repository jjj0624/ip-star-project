import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')

    SQLALCHEMY_DATABASE_URI = (
        f"mysql+pymysql://{os.environ.get('DATABASE_USERNAME')}"
        f":{os.environ.get('DATABASE_PASSWORD')}"
        f"@{os.environ.get('DATABASE_HOST')}"
        f"/{os.environ.get('DATABASE_NAME')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- 新增下面这段配置 ---
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_recycle': 280,      # 每 280 秒（< 5分钟）回收一次连接，防止超时
        'pool_pre_ping': True     # 关键配置！每次查询前自动检测连接是否存活，如果断开则重连
    }