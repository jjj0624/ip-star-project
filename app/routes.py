import os
import secrets
import json
from datetime import date, timedelta
from PIL import Image
from flask import (render_template, flash, redirect, url_for, request,
                   Blueprint, abort, current_app, jsonify)
from flask_login import current_user, login_user, logout_user, login_required
from app import db
from app.models import User, IpAsset, Contract, IpAnalytics
from app.forms import LoginForm, RegistrationForm, IpAssetForm, ContractForm
from sqlalchemy import not_, or_, func
from functools import wraps

bp = Blueprint('main', __name__)


# --- 辅助装饰器 ---
def internal_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'internal':
            abort(403)
        return f(*args, **kwargs)

    return decorated_function


def partner_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'partner':
            abort(403)
        return f(*args, **kwargs)

    return decorated_function


# --- 辅助函数 ---
def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(current_app.root_path, 'static/images', picture_fn)
    output_size = (800, 800)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    return os.path.join('images', picture_fn).replace('\\', '/')


# [新功能] 自动评估 IP 商业价值
def update_ip_value_level(ip_id):
    ip = IpAsset.query.get(ip_id)
    if not ip:
        return
    # 统计该 IP 的合同数量
    contract_count = Contract.query.filter_by(ip_id=ip_id).count()

    # 评级规则：0-1: C, 2-3: B, 4-5: A, 6+: S
    if contract_count >= 6:
        new_level = 'S'
    elif contract_count >= 4:
        new_level = 'A'
    elif contract_count >= 2:
        new_level = 'B'
    else:
        new_level = 'C'

    if ip.value_level != new_level:
        ip.value_level = new_level
        # 这里不 commit，由调用方 commit
        print(f"IP {ip.name} 商业价值已自动更新为 {new_level} (合同数: {contract_count})")


# [新功能] 升级版许可状态判断 (支持地域)
def get_licensing_status(ip_asset):
    today = date.today()
    # 查找所有生效的独占/排他合同
    active_contracts = Contract.query.filter(
        Contract.ip_id == ip_asset.id,
        Contract.license_type.in_(['独占许可', '排他许可']),
        Contract.term_start <= today,
        Contract.term_end >= today
    ).all()

    if not active_contracts:
        return "可以许可"

    # 如果存在限制性合同，检查地域
    regions = [c.region for c in active_contracts if c.region]

    # 如果有合同没有明确地域，或者涵盖了“全球”、“全国”，则视为完全不可许可
    for r in regions:
        if "全球" in r or "全国" in r or "中国大陆" in r:  # 简单判断
            return "不可许可"

    if regions:
        # 列表去重并连接
        unique_regions = list(set(regions))
        return f"可在 {'、'.join(unique_regions)} 以外许可"

    return "不可许可"


# --- 首页与认证 ---
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


# --- 内控端路由 ---
@bp.route('/internal/dashboard', methods=['GET'])
@login_required
@internal_required
def internal_dashboard():
    ip_form = IpAssetForm()
    contract_form = ContractForm()
    contract_form.ip_id.choices = [(ip.id, ip.name) for ip in IpAsset.query.order_by(IpAsset.name).all()]

    # IP 筛选
    ip_name_query = request.args.get('ip_name', '')
    ip_category_query = request.args.get('ip_category', '')
    ip_query = IpAsset.query
    if ip_name_query:
        ip_query = ip_query.filter(IpAsset.name.like(f'%{ip_name_query}%'))
    if ip_category_query:
        ip_query = ip_query.filter(IpAsset.category == ip_category_query)
    all_ips = ip_query.order_by(IpAsset.id.desc()).all()

    # 计算状态
    ip_statuses = {ip.id: get_licensing_status(ip) for ip in all_ips}

    # 合同筛选
    contract_ip_name = request.args.get('contract_ip_name', '')
    contract_partner = request.args.get('contract_partner', '')
    contract_query = Contract.query.join(IpAsset)
    if contract_ip_name:
        contract_query = contract_query.filter(IpAsset.name.like(f'%{contract_ip_name}%'))
    if contract_partner:
        contract_query = contract_query.filter(Contract.partner_name.like(f'%{contract_partner}%'))
    all_contracts = contract_query.order_by(Contract.id.desc()).all()

    categories = [c[0] for c in db.session.query(IpAsset.category).distinct().all() if c[0]]
    tencent_embed_url = os.environ.get('TENCENT_EMBED_URL_INTERNAL')

    # --- [新功能] 数据可视化准备 ---
    # 1. IP 类别占比 (Pie)
    cat_stats = db.session.query(IpAsset.category, func.count(IpAsset.id)).group_by(IpAsset.category).all()
    pie_data = [{'name': c[0] or '未分类', 'value': c[1]} for c in cat_stats]

    # 2. IP 点击量 Top 5 (Bar)
    click_stats = db.session.query(IpAsset.name, func.count(IpAnalytics.id)).join(IpAnalytics).group_by(
        IpAsset.name).order_by(func.count(IpAnalytics.id).desc()).limit(5).all()
    bar_x = [c[0] for c in click_stats]
    bar_y = [c[1] for c in click_stats]

    return render_template('internal_dashboard.html',
                           title='内控管理台',
                           ip_form=ip_form,
                           contract_form=contract_form,
                           ips=all_ips,
                           ip_statuses=ip_statuses,
                           contracts=all_contracts,
                           categories=categories,
                           search_ip_name=ip_name_query,
                           search_ip_category=ip_category_query,
                           search_contract_ip=contract_ip_name,
                           search_contract_partner=contract_partner,
                           tencent_embed_url=tencent_embed_url,
                           # 传递图表数据
                           pie_data=pie_data,
                           bar_x=bar_x,
                           bar_y=bar_y
                           )


@bp.route('/internal/ip/add', methods=['POST'])
@login_required
@internal_required
def add_ip():
    form = IpAssetForm()
    if form.validate_on_submit():
        picture_file_path = 'images/default.png'
        if form.image_file.data:
            picture_file_path = save_picture(form.image_file.data)

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
            value_level='C'  # 初始默认为 C，后续由合同数量决定
        )
        try:
            db.session.add(new_ip)
            db.session.commit()
            flash(f'IP "{new_ip.name}" 添加成功！初始商业价值为 C 级。', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'添加失败: {e}', 'danger')
        return redirect(url_for('main.internal_dashboard'))

    flash('添加 IP 失败，请检查表单。', 'danger')
    return redirect(url_for('main.internal_dashboard'))


@bp.route('/internal/contract/add', methods=['POST'])
@login_required
@internal_required
def add_contract():
    form = ContractForm()
    form.ip_id.choices = [(ip.id, ip.name) for ip in IpAsset.query.all()]

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
            # [新功能] 自动更新 IP 价值
            update_ip_value_level(new_contract.ip_id)
            db.session.commit()
            flash('新合同添加成功！IP 商业价值已根据规则重新评估。', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'添加失败: {e}', 'danger')
        return redirect(url_for('main.internal_dashboard'))

    flash('添加合同失败，请检查表单。', 'danger')
    return redirect(url_for('main.internal_dashboard'))


@bp.route('/internal/ip/delete/<int:ip_id>', methods=['POST'])
@login_required
@internal_required
def delete_ip(ip_id):
    ip = IpAsset.query.get_or_404(ip_id)
    if ip.contracts:
        flash('删除失败！该 IP 尚有关联合同。', 'danger')
        return redirect(url_for('main.internal_dashboard'))
    try:
        if ip.image_url and 'default.png' not in ip.image_url:
            p = os.path.join(current_app.root_path, 'static', ip.image_url)
            if os.path.exists(p): os.remove(p)
        db.session.delete(ip)
        db.session.commit()
        flash('IP 删除成功。', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'删除失败: {e}', 'danger')
    return redirect(url_for('main.internal_dashboard'))


@bp.route('/internal/contract/delete/<int:contract_id>', methods=['POST'])
@login_required
@internal_required
def delete_contract(contract_id):
    c = Contract.query.get_or_404(contract_id)
    ip_id = c.ip_id
    try:
        db.session.delete(c)
        # [新功能] 删除合同后也要重新评估价值
        update_ip_value_level(ip_id)
        db.session.commit()
        flash('合同删除成功。IP 商业价值已重新评估。', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'删除失败: {e}', 'danger')
    return redirect(url_for('main.internal_dashboard'))


# --- 伙伴端路由 ---
@bp.route('/portal/dashboard')
@login_required
@partner_required
def portal_dashboard():
    search_query = request.args.get('q', '')
    category_query = request.args.get('category', '')
    level_query = request.args.get('value_level', '')

    # [修改] 不再过滤 "不可许可" 的 IP，全部展示
    base_query = IpAsset.query

    if search_query:
        base_query = base_query.filter(IpAsset.name.like(f'%{search_query}%'))
    if category_query:
        base_query = base_query.filter(IpAsset.category == category_query)
    if level_query:
        base_query = base_query.filter(IpAsset.value_level == level_query)

    ips = base_query.order_by(IpAsset.cooperation_count.desc()).all()

    # 为前端展示计算状态（用于显示 "暂时无法许可" 标签）
    ip_statuses = {ip.id: get_licensing_status(ip) for ip in ips}

    categories = [c[0] for c in db.session.query(IpAsset.category).distinct().filter(IpAsset.category != None)]
    value_levels = ['S', 'A', 'B', 'C']
    tencent_embed_url = os.environ.get('TENCENT_EMBED_URL_PARTNER')

    return render_template('portal_dashboard.html',
                           title='IP 授权门户',
                           ips=ips,
                           ip_statuses=ip_statuses,  # 传递状态
                           categories=categories,
                           value_levels=value_levels,
                           search_query=search_query,
                           selected_category=category_query,
                           selected_level=level_query,
                           tencent_embed_url=tencent_embed_url)


@bp.route('/portal/ip/<int:ip_id>')
@login_required
@partner_required
def ip_detail(ip_id):
    ip = IpAsset.query.get_or_404(ip_id)

    # [修改] 接收筛选参数，以便“返回列表”时保持状态
    prev_q = request.args.get('q', '')
    prev_cat = request.args.get('category', '')
    prev_lvl = request.args.get('value_level', '')

    status = get_licensing_status(ip)
    # 这里不再跳转回去，而是允许查看详情，但在模板里提示

    try:
        new_click = IpAnalytics(ip_id=ip.id, user_id=current_user.id)
        db.session.add(new_click)
        db.session.commit()
    except Exception as e:
        db.session.rollback()

    return render_template('ip_detail.html',
                           ip=ip,
                           title=ip.name,
                           status=status,
                           # 传递回之前的参数
                           prev_q=prev_q, prev_cat=prev_cat, prev_lvl=prev_lvl)


# --- AI API ---

# API 1: 报表 (润色版)
@bp.route('/api/get_report')
def api_get_report():
    try:
        # 1. 点击量 Top 5
        clicks = db.session.query(IpAsset.name, func.count(IpAnalytics.id)) \
            .join(IpAnalytics).group_by(IpAsset.name) \
            .order_by(func.count(IpAnalytics.id).desc()).limit(5).all()

        click_text = "| 排名 | IP 名称 | 点击热度 |\n|---|---|---|\n"
        if not clicks: click_text += "| - | 暂无数据 | 0 |\n"
        for i, (name, count) in enumerate(clicks):
            click_text += f"| {i + 1} | {name} | {count} |\n"

        # 2. 90天内到期
        today = date.today()
        future = today + timedelta(days=90)
        expiring = Contract.query.filter(Contract.term_end >= today, Contract.term_end <= future).all()

        expiring_text = ""
        if not expiring:
            expiring_text = "> ✅ **安心提示**：未来 90 天内没有即将到期的合同。"
        else:
            expiring_text = "| 相对方 | IP | 到期日 |\n|---|---|---|\n"
            for c in expiring:
                expiring_text += f"| {c.partner_name} | {c.ip_asset.name} | {c.term_end} |\n"

        return jsonify({
            "status": "success",
            "ip_clicks_report": click_text,
            "expiring_report": expiring_text
        })
    except Exception as e:
        return jsonify({"status": "error", "ip_clicks_report": str(e), "expiring_report": str(e)}), 500


# API 2: 违约条款 (不变)
@bp.route('/api/query_breach_terms')
def api_query_breach_terms():
    q = request.args.get('q')
    if not q: return jsonify({"status": "error", "count": 0, "report": "无关键词"}), 400
    try:
        res = Contract.query.filter(
            or_(Contract.partner_name.like(f'%{q}%'), Contract.breach_terms.like(f'%{q}%'))).all()
        if not res: return jsonify({"status": "success", "count": 0, "report": "未找到相关条款。"})

        report = ""
        for c in res:
            report += f"**合同对象**：{c.partner_name}\n**相关条款**：{c.breach_terms}\n\n---\n\n"
        return jsonify({"status": "success", "count": len(res), "report": report})
    except Exception as e:
        return jsonify({"status": "error", "count": 0, "report": str(e)}), 500


# API 3: 可许可IP (不变，但逻辑已包含地域，此处简单返回列表)
@bp.route('/api/get_licensable_ips')
def api_get_licensable_ips():
    # AI 用的简单列表，这里暂不处理复杂的地域逻辑，返回所有未被完全锁定的
    # 简单起见，返回所有 IP 及其当前状态描述
    try:
        ips = IpAsset.query.all()
        report = ""
        count = 0
        for ip in ips:
            status = get_licensing_status(ip)
            if "不可许可" not in status:
                count += 1
                report += f"### {ip.name} ({ip.category})\n"
                report += f"- **级别**: {ip.value_level}\n"
                report += f"- **状态**: {status}\n"
                report += f"- **介绍**: {ip.description}\n\n"

        if count == 0: report = "暂无完全可用的 IP。"
        return jsonify({"status": "success", "count": count, "ips_report": report})
    except Exception as e:
        return jsonify({"status": "error", "count": 0, "ips_report": str(e)}), 500


# API 4: 费用参考 (不变)
@bp.route('/api/get_fee_guidance')
def api_get_fee_guidance():
    name = request.args.get('ip_name')
    if not name: return jsonify({"status": "error", "value_level": "未知"}), 400
    ip = IpAsset.query.filter(IpAsset.name == name).first()
    if not ip: return jsonify({"status": "error", "value_level": "未找到"})
    return jsonify({"status": "success", "ip_name": ip.name, "value_level": ip.value_level})


# [新功能] API 5: 获取数据库概览 (给内控 AI 用)
@bp.route('/api/get_database_info')
def api_get_database_info():
    """返回当前数据库中有哪些 IP 和 合同的摘要列表"""
    try:
        # 1. IP 列表
        ips = IpAsset.query.all()
        ip_list_text = "**【IP 资产列表】**\n"
        for ip in ips:
            ip_list_text += f"- {ip.name} ({ip.category}, {ip.value_level}级)\n"

        # 2. 合同列表
        contracts = Contract.query.all()
        contract_list_text = "\n**【合同列表】**\n"
        for c in contracts:
            contract_list_text += f"- 与 {c.partner_name} 的 {c.license_type} (IP: {c.ip_asset.name})\n"

        full_report = ip_list_text + contract_list_text
        return jsonify({"status": "success", "info_report": full_report})
    except Exception as e:
        return jsonify({"status": "error", "info_report": str(e)}), 500