import os
import secrets
from PIL import Image  # 用于图片处理
from flask import (render_template, flash, redirect, url_for, request,
                   Blueprint, abort, jsonify, current_app)
from flask_login import current_user, login_user, logout_user, login_required
from app import db
from app.models import User, IpAsset, Contract, IpAnalytics
from app.forms import LoginForm, RegistrationForm, IpAssetForm, ContractForm
from sqlalchemy import not_, or_
from datetime import date, timedelta
from functools import wraps
from werkzeug.utils import secure_filename  # 用于安全地获取文件名

# 创建一个蓝图
bp = Blueprint('main', __name__)


# --- 辅助装饰器 ---

# 用于限制只有 'internal' 角色的用户才能访问
def internal_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'internal':
            abort(403)  # 403 Forbidden
        return f(*args, **kwargs)

    return decorated_function


# 用于限制只有 'partner' 角色的用户才能访问
def partner_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'partner':
            abort(403)  # 403 Forbidden
        return f(*args, **kwargs)

    return decorated_function


# --- 辅助函数 ---

def save_picture(form_picture):
    """处理上传的图片文件：压缩、保存并返回文件名"""
    random_hex = secrets.token_hex(8)
    # 获取文件扩展名
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext  # 随机文件名

    # 构造保存路径
    # current_app.root_path 是项目根目录 (ip_star_project)
    picture_path = os.path.join(current_app.root_path, 'app/static/images', picture_fn)

    # 压缩图片
    output_size = (800, 800)  # 限制最大尺寸
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    # 返回相对路径，用于存储在数据库
    return os.path.join('images', picture_fn)


def get_licensing_status(ip):
    """根据IP的合同计算其当前的许可状态"""
    today = date.today()
    # 检查是否存在任何"正在生效"的"独占"或"排他"许可
    is_locked = db.session.query(Contract.id).filter(
        Contract.ip_id == ip.id,
        Contract.license_type.in_(['独占许可', '排他许可']),
        Contract.term_start <= today,
        Contract.term_end >= today
    ).first()  # .first() 是一种优化，只要找到一个就立刻返回

    if is_locked:
        return "不可许可"
    else:
        return "可许可"


# --- 首页与认证路由 ---

@bp.route('/')
@bp.route('/index')
@login_required
def index():
    # 根据用户角色重定向到各自的主页
    if current_user.role == 'internal':
        return redirect(url_for('main.internal_dashboard'))
    elif current_user.role == 'partner':
        return redirect(url_for('main.portal_dashboard'))
    else:
        return redirect(url_for('main.login'))


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('无效的用户名或密码', 'danger')
            return redirect(url_for('main.login'))
        login_user(user, remember=form.remember_me.data)
        flash('登录成功！', 'success')
        return redirect(url_for('main.index'))
    return render_template('login.html', title='登录', form=form)


@bp.route('/logout')
def logout():
    logout_user()
    flash('您已成功退出登录。', 'info')
    return redirect(url_for('main.login'))


@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, role=form.role.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('恭喜，您已注册成功！请登录。', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html', title='注册', form=form)


# --- (1) 内控端路由 ---

@bp.route('/internal/dashboard')
@login_required
@internal_required
def internal_dashboard():
    # 准备表单
    ip_form = IpAssetForm()
    contract_form = ContractForm()
    # 为合同表单的 IP 下拉列表填充选项
    contract_form.ip_id.choices = [(ip.id, ip.name) for ip in IpAsset.query.order_by(IpAsset.name).all()]

    # --- IP 资产台账筛选 ---
    ip_name_query = request.args.get('ip_name', '')
    ip_category_query = request.args.get('ip_category', '')
    ip_query = IpAsset.query
    if ip_name_query:
        ip_query = ip_query.filter(IpAsset.name.like(f'%{ip_name_query}%'))
    if ip_category_query:
        ip_query = ip_query.filter(IpAsset.category == ip_category_query)
    all_ips_raw = ip_query.order_by(IpAsset.id.desc()).all()
    # 动态计算 IP 状态
    all_ips = []
    for ip in all_ips_raw:
        ip.current_status = get_licensing_status(ip)  # 动态添加属性
        all_ips.append(ip)

    # --- 合同台账筛选 ---
    contract_ip_query = request.args.get('contract_ip', '')
    contract_partner_query = request.args.get('contract_partner', '')
    contract_query = Contract.query
    if contract_ip_query:
        # 通过 IP 名称反向查询
        contract_query = contract_query.join(IpAsset).filter(IpAsset.name.like(f'%{contract_ip_query}%'))
    if contract_partner_query:
        contract_query = contract_query.filter(Contract.partner_name.like(f'%{contract_partner_query}%'))
    all_contracts = contract_query.order_by(Contract.id.desc()).all()

    # 获取所有唯一的类别用于筛选下拉框
    categories = [c[0] for c in db.session.query(IpAsset.category).distinct().all() if c[0]]

    return render_template('internal_dashboard.html',
                           title='内控管理台',
                           ips=all_ips,
                           contracts=all_contracts,
                           categories=categories,
                           ip_form=ip_form,
                           contract_form=contract_form,
                           search_ip_name=ip_name_query,
                           search_ip_category=ip_category_query,
                           search_contract_ip=contract_ip_query,
                           search_contract_partner=contract_partner_query)


@bp.route('/internal/ip/add', methods=['POST'])
@login_required
@internal_required
def add_ip():
    form = IpAssetForm()
    if form.validate_on_submit():
        # 处理图片上传
        picture_file_path = 'images/default.png'  # 默认图片
        if form.image_file.data:
            picture_file_path = save_picture(form.image_file.data)
            # 确保路径在 Windows 和 Linux 之间兼容 (用 /)
            picture_file_path = picture_file_path.replace('\\', '/')

        new_ip = IpAsset(
            name=form.name.data,
            category=form.category.data,
            description=form.description.data,
            image_url=picture_file_path,
            author=form.author.data,
            ownership=form.ownership.data,
            reg_number=form.reg_number.data,
            reg_date=form.reg_date.data,
            license_type_options=form.license_type_options.data,
            value_level=form.value_level.data,
            internal_status=form.internal_status.data
            # cooperation_count 默认为 0
        )
        try:
            db.session.add(new_ip)
            db.session.commit()
            flash('新 IP 资产添加成功！', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'添加失败，发生错误：{e}', 'danger')
    else:
        # 处理表单验证失败
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{getattr(form, field).label.text} 字段错误: {error}', 'danger')
    return redirect(url_for('main.internal_dashboard'))


@bp.route('/internal/contract/add', methods=['POST'])
@login_required
@internal_required
def add_contract():
    form = ContractForm()
    # 再次动态填充
    form.ip_id.choices = [(ip.id, ip.name) for ip in IpAsset.query.order_by(IpAsset.name).all()]

    if form.validate_on_submit():
        new_contract = Contract(
            ip_id=form.ip_id.data,
            partner_name=form.partner_name.data,
            region=form.region.data,
            media=form.media.data,
            usage_type=form.usage_type.data,
            license_type=form.license_type.data,
            term_start=form.term_start.data,
            term_end=form.term_end.data,
            fee_standard=form.fee_standard.data,
            payment_cycle=form.payment_cycle.data,
            breach_terms=form.breach_terms.data
        )
        try:
            db.session.add(new_contract)
            db.session.commit()
            flash('新合同添加成功！', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'添加失败，发生错误：{e}', 'danger')
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{getattr(form, field).label.text} 字段错误: {error}', 'danger')
    return redirect(url_for('main.internal_dashboard'))


@bp.route('/internal/ip/delete/<int:ip_id>', methods=['POST'])
@login_required
@internal_required
def delete_ip(ip_id):
    ip_to_delete = IpAsset.query.get_or_404(ip_id)
    try:
        # （注意：如果合同表设置了 RESTRICT，这里需要先删除关联合同）
        # 鉴于我们设置了 RESTRICT，我们应该先检查
        if ip_to_delete.contracts:
            flash('删除失败！该 IP 尚有关联合同，请先删除相关合同。', 'danger')
            return redirect(url_for('main.internal_dashboard'))

        # (如果需要，在这里添加删除 app/static/images 中
        # 的旧图片文件的逻辑)

        db.session.delete(ip_to_delete)
        db.session.commit()
        flash('IP 资产删除成功。', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'删除失败，发生错误：{e}', 'danger')
    return redirect(url_for('main.internal_dashboard'))


@bp.route('/internal/contract/delete/<int:contract_id>', methods=['POST'])
@login_required
@internal_required
def delete_contract(contract_id):
    contract_to_delete = Contract.query.get_or_404(contract_id)
    try:
        db.session.delete(contract_to_delete)
        db.session.commit()
        flash('合同删除成功。', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'删除失败，发生错误：{e}', 'danger')
    return redirect(url_for('main.internal_dashboard'))


# --- (2) 伙伴端路由 ---

@bp.route('/portal/dashboard')
@login_required
@partner_required
def portal_dashboard():
    # --- 获取所有筛选参数 ---
    search_query = request.args.get('q', '')
    category_query = request.args.get('category', '')
    level_query = request.args.get('value_level', '')

    today = date.today()

    # 1. 找到所有当前 "不可许可" 的 IP ID
    locked_ip_ids_query = db.session.query(Contract.ip_id).distinct().filter(
        Contract.license_type.in_(['独占许可', '排他许可']),
        Contract.term_start <= today,
        Contract.term_end >= today
    )
    locked_ip_ids = [item[0] for item in locked_ip_ids_query.all()]

    # 2. 查询所有可许可的 IP 作为基础
    base_query = IpAsset.query.filter(
        not_(IpAsset.id.in_(locked_ip_ids))
    )

    # 3. --- 应用所有筛选条件 ---
    if search_query:
        # 只搜索 IP 名称
        base_query = base_query.filter(IpAsset.name.like(f'%{search_query}%'))

    if category_query:
        base_query = base_query.filter(IpAsset.category == category_query)

    if level_query:
        base_query = base_query.filter(IpAsset.value_level == level_query)

    # 4. 按合作次数排序并执行
    licensable_ips = base_query.order_by(IpAsset.cooperation_count.desc()).all()

    # 5. --- 获取用于下拉框的选项 ---
    categories = [c[0] for c in db.session.query(IpAsset.category).distinct().filter(IpAsset.category != None)]
    # 固定商业价值的顺序
    value_levels = ['S', 'A', 'B', 'C']

    return render_template('portal_dashboard.html',
                           title='IP 授权门户',
                           ips=licensable_ips,
                           # --- 把选项和当前值传给模板 ---
                           categories=categories,
                           value_levels=value_levels,
                           search_query=search_query,
                           selected_category=category_query,
                           selected_level=level_query)


@bp.route('/portal/ip/<int:ip_id>')
@login_required
@partner_required
def ip_detail(ip_id):
    ip = IpAsset.query.get_or_404(ip_id)

    # 关键：把点击统计逻辑放在这里！
    # 只有当用户真正点击“查看详情”时，才记录一次点击
    try:
        new_click = IpAnalytics(ip_id=ip.id, user_id=current_user.id)
        db.session.add(new_click)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error logging click: {e}")  # 在后台打印错误

    return render_template('ip_detail.html', ip=ip, title=ip.name)


# --- (3) AI 专用 API 路由 ---
# 这些路由由腾讯云智能体在后台调用

@bp.route('/api/get_report')
def api_get_report():
    """
    (内控端) AI工具：一键生成报表
    为了演示，这里返回模拟数据 (Mock Data)。
    在真实项目中，这里应该执行复杂的数据库查询。
    """
    try:
        # --- 模拟IP点击量数据 ---
        # 真实查询: db.session.query(IpAsset.name, func.count(IpAnalytics.id))...
        ip_clicks = [
            {"name": "墨卿", "clicks": 120},
            {"name": "星核仔", "clicks": 95},
            {"name": "林小满", "clicks": 80},
        ]

        # --- 模拟IP许可收益排行 ---
        # 真实查询: 涉及复杂的 fee_standard 解析和 payment_cycle 计算
        revenue_ranking = [
            {"name": "墨卿", "revenue": "约 250,000 元 (含分成)"},
            {"name": "星核仔", "revenue": "800,000 元 (保底)"},
            {"name": "蓝星豆", "revenue": "500,000 元 (保底)"},
        ]

        # --- 真实查询：在一个季度内即将到期的IP ---
        today = date.today()
        ninety_days_later = today + timedelta(days=90)
        expiring_contracts = db.session.query(Contract.partner_name, IpAsset.name, Contract.term_end) \
            .join(IpAsset, Contract.ip_id == IpAsset.id) \
            .filter(
            Contract.term_end >= today,
            Contract.term_end <= ninety_days_later
        ).all()

        expiring_list = [
            f"{c.partner_name} (IP: {c.name}) - 到期日: {c.term_end.strftime('%Y-%m-%d')}"
            for c in expiring_contracts
        ]

        # --- 模拟：一个月内需要付费的公司 ---
        # 真实查询: 涉及复杂的 payment_cycle 解析
        due_payments = [
            {"partner": "晨天文具制造有限公司", "due_date": "2025-11-15", "amount": "约 75,000 元 (第二期)"},
            {"partner": "宇溯游戏开发有限公司", "due_date": "2025-11-20", "amount": "季度流水分成"},
        ]

        # 返回 JSON
        return jsonify({
            "status": "success",
            "ip_click_data": ip_clicks,
            "ip_revenue_ranking": revenue_ranking,
            "expiring_in_90_days": expiring_list,
            "payments_due_in_30_days": due_payments
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/query_breach_terms')
def api_query_breach_terms():
    """
    (内控端) AI工具：对方违约急救指南
    根据关键词查询合同表中的 'breach_terms' 字段。
    """
    # 从 AI 工具的 API 调用中获取查询参数 'q'
    query = request.args.get('q', '')

    if not query:
        return jsonify({
            "status": "error",
            "message": "查询失败，必须提供关键词 (参数 'q')。"
        }), 400

    try:
        # 模糊搜索：
        # 搜索 "相对方名称" 或 "违约责任" 字段中包含查询关键词的合同
        search_term = f'%{query}%'

        contracts_found = db.session.query(Contract.partner_name, Contract.breach_terms) \
            .filter(
            or_(
                Contract.partner_name.like(search_term),
                Contract.breach_terms.like(search_term)
            )
        ).all()

        if not contracts_found:
            return jsonify({
                "status": "success",
                "count": 0,
                "results": []
            })

        results = [
            {
                "partner_name": c.partner_name,
                "breach_terms": c.breach_terms
            } for c in contracts_found
        ]

        return jsonify({
            "status": "success",
            "count": len(results),
            "results": results
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500