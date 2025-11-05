# run.py
from app import create_app, db
from app.models import User, IpAsset, Contract, IpAnalytics

app = create_app()

# 这个上下文处理器让你可以在 'flask shell' 中直接访问 db 和模型
# 非常方便调试
@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User, 'IpAsset': IpAsset,
            'Contract': Contract, 'IpAnalytics': IpAnalytics}

if __name__ == '__main__':
    app.run(debug=True) # debug=True 模式会在你修改代码后自动重启