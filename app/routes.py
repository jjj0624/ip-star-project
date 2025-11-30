# app/routes.py
import os
import secrets
from datetime import date
from docx import Document
from flask import (render_template, flash, redirect, url_for, request,
                   Blueprint, abort, current_app, jsonify)
from flask_login import current_user, login_user, logout_user, login_required
from app import db
from app.models import User, IpAsset, Contract, IpAnalytics
from app.forms import LoginForm, RegistrationForm, IpAssetForm, ContractForm
from sqlalchemy import func, desc
from functools import wraps

bp = Blueprint('main', __name__)


# --- 权限装饰器 ---
def internal_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'internal': abort(403)
        return f(*args, **kwargs)

    return decorated_function


def partner_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'partner': abort(403)
        return f(*args, **kwargs)

    return decorated_function


# --- 基础页面 ---
@bp.route('/')
@bp.route('/index')
@login_required
def index():
    if current_user.role == 'internal':
        return redirect(url_for('main.internal_dashboard'))
    elif current_user.role == 'partner':
        return redirect(url_for('main.portal_dashboard'))
    else:
        return redirect(url_for('main.login'))


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('main.index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('无效用户名或密码', 'danger');
            return redirect(url_for('main.login'))
        login_user(user, remember=form.remember_me.data)
        return redirect(url_for('main.index'))
    return render_template('login.html', title='登录', form=form)


@bp.route('/logout')
def logout():
    logout_user();
    return redirect(url_for('main.login'))


@bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, role=form.role.data)
        user.set_password(form.password.data)
        db.session.add(user);
        db.session.commit()
        return redirect(url_for('main.login'))
    return render_template('register.html', title='注册', form=form)


# --- 内控端看板 (全量展示 + 详情 Modal + 图表) ---
@bp.route('/internal/dashboard')
@login_required
@internal_required
def internal_dashboard():
    # 1. 收益图表数据
    rev_stats = db.session.query(IpAsset.name, IpAsset.current_revenue) \
        .order_by(desc(IpAsset.current_revenue)).limit(5).all()
    rev_x = [r[0] for r in rev_stats]
    rev_y = [float(r[1]) for r in rev_stats]

    # 2. 点击图表数据
    click_stats = db.session.query(IpAsset.name, func.count(IpAnalytics.id)) \
        .join(IpAnalytics).group_by(IpAsset.name) \
        .order_by(func.count(IpAnalytics.id).desc()).limit(5).all()
    click_x = [c[0] for c in click_stats]
    click_y = [c[1] for c in click_stats]

    ips = IpAsset.query.all()
    contracts = Contract.query.order_by(desc(Contract.term_start)).all()

    # 传递表单以防模板报错(尽管这里只做展示)
    ip_form = IpAssetForm()
    contract_form = ContractForm()
    tencent_embed_url = os.environ.get('TENCENT_EMBED_URL_INTERNAL')

    return render_template('internal_dashboard.html', title='内控台账',
                           ips=ips, contracts=contracts,
                           rev_x=rev_x, rev_y=rev_y,
                           click_x=click_x, click_y=click_y,
                           ip_form=ip_form, contract_form=contract_form,
                           tencent_embed_url=tencent_embed_url)


# --- 伙伴端门户 (极简 + 合作案例) ---
@bp.route('/portal/dashboard')
@login_required
@partner_required
def portal_dashboard():
    # 1. 合作案例 (只取有案例图的合同)
    cases = Contract.query.filter(Contract.case_image_url != None) \
        .order_by(desc(Contract.contract_id)).limit(8).all()

    # 2. IP 列表 (不含状态逻辑)
    query = request.args.get('q', '')
    base_query = IpAsset.query
    if query: base_query = base_query.filter(IpAsset.name.like(f'%{query}%'))
    ips = base_query.all()

    tencent_embed_url = os.environ.get('TENCENT_EMBED_URL_PARTNER')
    return render_template('portal_dashboard.html', title='IP 授权门户',
                           ips=ips, cases=cases, search_query=query,
                           tencent_embed_url=tencent_embed_url)


@bp.route('/portal/ip/<int:ip_id>')
@login_required
@partner_required
def ip_detail(ip_id):
    ip = IpAsset.query.get_or_404(ip_id)
    # 记录点击
    try:
        db.session.add(IpAnalytics(ip_id=ip.id, user_id=current_user.id)); db.session.commit()
    except:
        pass
    return render_template('ip_detail.html', ip=ip)


# --- 简单的添加/删除功能 (保留原逻辑，略微简化) ---
@bp.route('/ip/delete/<int:ip_id>', methods=['POST'])
@login_required
@internal_required
def delete_ip(ip_id):
    try:
        ip = IpAsset.query.get(ip_id)
        db.session.delete(ip);
        db.session.commit()
        flash('已删除', 'success')
    except:
        flash('删除失败，可能有关联合同', 'danger')
    return redirect(url_for('main.internal_dashboard'))


# =======================================================
# --- AI 插件接口 (对应腾讯云智能体) ---
# =======================================================

@bp.route('/api/get_database_info', methods=['POST'])
def api_get_database_info():
    """
    [内控AI] 获取全量数据，用于生成报表。
    注意：为了适配腾讯云插件，这里改为 POST (或者 GET 也可以，但 JSON配置要对应)
    """
    try:
        # 1. IP 全貌
        ips = IpAsset.query.all()
        report = ["【IP 资产全量数据】"]
        for ip in ips:
            report.append(f"IP名称: {ip.name} | 级别: {ip.value_level} | 标签: {ip.tags}")
            report.append(f"  目前收益: {ip.current_revenue}万 | 状态: {ip.internal_status}")
            report.append(f"  权属: {ip.ownership} | 登记号: {ip.reg_number}")
            report.append(f"  商标情况: {ip.trademark_info}")
            report.append(f"  授权期: {ip.license_period}")
            report.append("----------------")

        # 2. 合同全貌
        contracts = Contract.query.all()
        report.append("\n【合同台账全量数据】")
        for c in contracts:
            report.append(f"合同对象: {c.partner_name} (品牌: {c.partner_brand})")
            report.append(f"  关联IP: {c.ip_asset.name} | 类型: {c.license_type}")
            report.append(f"  地域: {c.region} | 方式: {c.license_method}")
            report.append(f"  有效期: {c.term_start} 至 {c.term_end}")
            report.append(f"  费用标准: {c.fee_standard}")
            report.append("----------------")

        return jsonify({"status": "success", "info_report": "\n".join(report)})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/generate_contract_doc', methods=['POST'])
def api_generate_contract_doc():
    """
    [内控AI] 生成 Word 合同初稿
    """
    data = request.get_json() or {}
    # 获取参数，提供默认值
    partner_name = data.get('partner_name', '未命名方')
    ip_name = data.get('ip_name', '未命名IP')
    money = data.get('money', '待定')

    try:
        # 生成 Word
        doc = Document()
        doc.add_heading('IP 授权许可合同 (AI初稿)', 0)

        doc.add_paragraph(f'甲方：星核文化科技发展有限公司')
        doc.add_paragraph(f'乙方：{partner_name}')
        doc.add_paragraph(f'日期：{date.today()}')

        doc.add_heading('一、 授权事项', level=1)
        doc.add_paragraph(f'甲方同意将 IP “{ip_name}” 授权给乙方使用。')

        doc.add_heading('二、 费用条款', level=1)
        doc.add_paragraph(f'双方约定许可费用为：{money}。')

        doc.add_heading('三、 法律效力', level=1)
        doc.add_paragraph('本文件为 AI 生成的初稿，经法务审核签字后生效。')

        # 保存
        filename = f"Contract_{secrets.token_hex(4)}.docx"
        save_dir = os.path.join(current_app.root_path, 'static', 'generated_docs')
        if not os.path.exists(save_dir): os.makedirs(save_dir)

        doc.save(os.path.join(save_dir, filename))

        # 返回完整 URL
        download_url = url_for('static', filename=f'generated_docs/{filename}', _external=True)

        return jsonify({
            "status": "success",
            "message": "合同已生成",
            "download_url": download_url
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500