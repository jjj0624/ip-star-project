# config.py
import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))  # 加载 .env 文件


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')

    # 构建数据库连接 URI
    SQLALCHEMY_DATABASE_URI = (
        f"mysql+pymysql://{os.environ.get('DATABASE_USERNAME')}"  # <--- 把 'mysqlclient' 改成 'pymysql'
        f":{os.environ.get('DATABASE_PASSWORD')}"
        f"@{os.environ.get('DATABASE_HOST')}"
        f"/{os.environ.get('DATABASE_NAME')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False