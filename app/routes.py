import os
import secrets
from datetime import date, timedelta
from PIL import Image  # 用于图片处理
from flask import (render_template, flash, redirect, url_for, request,
                   Blueprint, abort, current_app, jsonify)
from flask_login import current_user, login_user, logout_user, login_required
from app import db
from app.models import User, IpAsset, Contract, IpAnalytics
from app.forms import LoginForm, RegistrationForm, IpAssetForm, ContractForm
from sqlalchemy import not_, or_, func, and_
from werkzeug.utils import secure_filename
from functools import wraps

# 创建一个蓝图
bp = Blueprint('main', __name__)


# --- 自定义装饰器 ---
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


# --- 首页与重定向 ---
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


# --- 认证路由 ---
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

# 帮助函数：保存上传的图片
def save_picture(form_picture):
    # 生成随机文件名
    random_hex = secrets.token_hex(8)
    # 获取文件扩展名 (如 .png)
    _, f_ext = os.path.splitext(form_picture.filename)
    # 组合新文件名 (如 8a2b3c4d.png)
    picture_fn = random_hex + f_ext
    # 拼接保存的绝对路径 (app/static/images/...)
    picture_path = os.path.join(current_app.root_path, 'static/images', picture_fn)

    # 压缩图片并保存
    output_size = (800, 800)  # 设置一个合理的尺寸
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    # 返回相对路径 (images/...)，用于存入数据库
    return os.path.join('images', picture_fn)


# 帮助函数：计算许可状态 (多处复用)
def get_licensing_status(ip_asset):
    today = date.today()
    # 查询此 IP 是否有任何“生效中”的“独占”或“排他”许可
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

    for r in regions:
        # [修改点] 只有 "全球" 视为完全不可许可
        if "全球" in r:
            return "不可许可"

    if regions:
        # 列表去重并连接
        unique_regions = list(set(regions))
        return f"可在 {'、'.join(unique_regions)} 以外许可"

    return "不可许可"


# [自动评估 IP 商业价值]
def update_ip_value_level(ip_id):
    ip = IpAsset.query.get(ip_id)
    if not ip:
        return
    contract_count = Contract.query.filter_by(ip_id=ip_id).count()

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


@bp.route('/internal/dashboard', methods=['GET'])
@login_required
@internal_required
def internal_dashboard():
    # --- 1. 表单初始化 ---
    ip_form = IpAssetForm()
    contract_form = ContractForm()
    # 动态填充合同表单中的 IP 下拉菜单
    contract_form.ip_id.choices = [
        (ip.id, ip.name) for ip in IpAsset.query.order_by(IpAsset.name).all()
    ]

    # --- 2. IP 资产查询与筛选 ---
    ip_name_query = request.args.get('ip_name', '')
    ip_category_query = request.args.get('ip_category', '')

    ip_query = IpAsset.query
    if ip_name_query:
        ip_query = ip_query.filter(IpAsset.name.like(f'%{ip_name_query}%'))
    if ip_category_query:
        ip_query = ip_query.filter(IpAsset.category == ip_category_query)

    all_ips = ip_query.order_by(IpAsset.id.desc()).all()

    # (关键) 为每个 IP 计算其当前的许可状态
    ip_statuses = {ip.id: get_licensing_status(ip) for ip in all_ips}

    # --- 3. 合同台账查询与筛选 ---
    contract_ip_name = request.args.get('contract_ip_name', '')
    contract_partner = request.args.get('contract_partner', '')

    contract_query = Contract.query.join(IpAsset)  # 关联 IP 表以便按名称搜索
    if contract_ip_name:
        contract_query = contract_query.filter(IpAsset.name.like(f'%{contract_ip_name}%'))
    if contract_partner:
        contract_query = contract_query.filter(Contract.partner_name.like(f'%{contract_partner}%'))

    all_contracts = contract_query.order_by(Contract.id.desc()).all()

    # --- 4. 筛选下拉框数据 ---
    categories = db.session.query(IpAsset.category).distinct().all()

    # --- 5. 获取 AI 嵌入网址 ---
    tencent_embed_url = os.environ.get('TENCENT_EMBED_URL_INTERNAL')
    if not tencent_embed_url:
        flash('AI 助手加载失败：未在服务器上配置 TENCENT_EMBED_URL_INTERNAL 环境变量。', 'danger')

    # --- 6. 数据可视化数据 ---
    cat_stats = db.session.query(IpAsset.category, func.count(IpAsset.id)).group_by(IpAsset.category).all()
    pie_data = [{'name': c[0] or '未分类', 'value': c[1]} for c in cat_stats]

    click_stats = db.session.query(IpAsset.name, func.count(IpAnalytics.id)).join(IpAnalytics).group_by(
        IpAsset.name).order_by(func.count(IpAnalytics.id).desc()).limit(5).all()
    bar_x = [c[0] for c in click_stats]
    bar_y = [c[1] for c in click_stats]

    return render_template('internal_dashboard.html',
                           title='内控管理台',
                           # 表单
                           ip_form=ip_form,
                           contract_form=contract_form,
                           # IP 表格
                           ips=all_ips,
                           ip_statuses=ip_statuses,
                           # 合同表格
                           contracts=all_contracts,
                           # 筛选数据
                           categories=[c[0] for c in categories if c[0]],
                           # 用于保持筛选框的值
                           search_ip_name=ip_name_query,
                           search_ip_category=ip_category_query,
                           search_contract_ip=contract_ip_name,
                           search_contract_partner=contract_partner,
                           # (V7 新增!)
                           tencent_embed_url=tencent_embed_url,
                           pie_data=pie_data, bar_x=bar_x, bar_y=bar_y
                           )


# --- (1.1) 内控端：添加 IP ---
@bp.route('/ip/add', methods=['POST'])
@login_required
@internal_required
def add_ip():
    # (这个路由只接受 POST，所以我们重新创建表单)
    ip_form = IpAssetForm()
    contract_form = ContractForm()  # (虽然不用，但模板需要它)

    if ip_form.validate_on_submit():
        # (关键) 处理图片上传
        if ip_form.image_file.data:
            image_db_path = save_picture(ip_form.image_file.data)
        else:
            image_db_path = None  # 或者一个默认图片路径

        new_ip = IpAsset(
            name=ip_form.name.data,
            category=ip_form.category.data,
            description=ip_form.description.data,
            image_url=image_db_path,  # (关键) 保存相对路径
            author=ip_form.author.data,
            ownership=ip_form.ownership.data,
            reg_number=ip_form.reg_number.data,
            reg_date=ip_form.reg_date.data,
            license_type_options=ip_form.license_type_options.data,
            value_level='C'  # 默认为 C
        )
        try:
            db.session.add(new_ip)
            db.session.commit()
            flash(f'IP 资产 "{new_ip.name}" 添加成功！', 'success')
        except Exception as e:
            db.session.rollback()
            # (处理唯一键冲突，比如登记号重复)
            if "UNIQUE constraint failed" in str(e) or "Duplicate entry" in str(e):
                flash(f'添加失败：登记号 "{new_ip.reg_number}" 可能已经存在。', 'danger')
            else:
                flash(f'添加 IP 时发生未知错误: {e}', 'danger')

        return redirect(url_for('main.internal_dashboard'))

    # 如果表单验证失败
    flash('添加 IP 失败，请检查表单中的错误。', 'danger')
    return redirect(url_for('main.internal_dashboard'))


# --- (1.2) 内控端：删除 IP ---
@bp.route('/ip/delete/<int:ip_id>', methods=['POST'])
@login_required
@internal_required
def delete_ip(ip_id):
    ip_to_delete = IpAsset.query.get_or_404(ip_id)

    # (安全检查：如果 IP 仍有关联合同，则阻止删除)
    if ip_to_delete.contracts:
        flash(f'无法删除 IP "{ip_to_delete.name}"，因为它仍有关联合同。请先删除相关合同。', 'danger')
        return redirect(url_for('main.internal_dashboard'))

    try:
        # (删除图片文件 - 可选但推荐)
        if ip_to_delete.image_url and 'default' not in ip_to_delete.image_url:
            image_path = os.path.join(current_app.root_path, 'static', ip_to_delete.image_url)
            if os.path.exists(image_path):
                os.remove(image_path)

        db.session.delete(ip_to_delete)
        db.session.commit()
        flash(f'IP 资产 "{ip_to_delete.name}" 已被删除。', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'删除 IP 时发生错误: {e}', 'danger')

    return redirect(url_for('main.internal_dashboard'))


# --- (1.3) 内控端：添加合同 ---
@bp.route('/contract/add', methods=['POST'])
@login_required
@internal_required
def add_contract():
    ip_form = IpAssetForm()  # (虽然不用，但模板需要它)
    contract_form = ContractForm()
    # (关键) 必须在验证之前再次填充 IP 下拉菜单
    contract_form.ip_id.choices = [
        (ip.id, ip.name) for ip in IpAsset.query.order_by(IpAsset.name).all()
    ]

    if contract_form.validate_on_submit():
        new_contract = Contract(
            ip_id=contract_form.ip_id.data,
            partner_name=contract_form.partner_name.data,
            region=contract_form.region.data,
            media=contract_form.media.data,
            usage_type=contract_form.usage_type.data,
            license_type=contract_form.license_type.data,
            term_start=contract_form.term_start.data,
            term_end=contract_form.term_end.data,
            fee_standard=contract_form.fee_standard.data,
            payment_cycle=contract_form.payment_cycle.data,
            breach_terms=contract_form.breach_terms.data
        )
        try:
            db.session.add(new_contract)
            update_ip_value_level(new_contract.ip_id)  # 更新价值
            db.session.commit()
            flash(f'为 "{new_contract.ip_asset.name}" 添加的新合同（ID: {new_contract.id}）成功！', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'添加合同时发生未知错误: {e}', 'danger')

        return redirect(url_for('main.internal_dashboard'))

    # 如果表单验证失败
    flash('添加合同失败，请检查表单中的错误。', 'danger')
    return redirect(url_for('main.internal_dashboard'))


# --- (1.4) 内控端：删除合同 ---
@bp.route('/contract/delete/<int:contract_id>', methods=['POST'])
@login_required
@internal_required
def delete_contract(contract_id):
    contract_to_delete = Contract.query.get_or_404(contract_id)
    ip_id = contract_to_delete.ip_id
    try:
        db.session.delete(contract_to_delete)
        update_ip_value_level(ip_id)  # 更新价值
        db.session.commit()
        flash(f'合同（ID: {contract_to_delete.id}）已被删除。', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'删除合同时发生错误: {e}', 'danger')

    return redirect(url_for('main.internal_dashboard'))


# --- (2) 伙伴端路由 (核心逻辑) ---
@bp.route('/portal/dashboard')
@login_required
@partner_required
def portal_dashboard():
    # --- 新增：获取所有筛选参数 ---
    search_query = request.args.get('q', '')
    category_query = request.args.get('category', '')
    level_query = request.args.get('value_level', '')

    # [修改] 不再过滤，全部显示，由前端处理遮罩
    base_query = IpAsset.query

    if search_query:
        base_query = base_query.filter(IpAsset.name.like(f'%{search_query}%'))
    if category_query:
        base_query = base_query.filter(IpAsset.category == category_query)
    if level_query:
        base_query = base_query.filter(IpAsset.value_level == level_query)

    # 4. 按合作次数排序并执行
    licensable_ips = base_query.order_by(IpAsset.cooperation_count.desc()).all()

    # 计算状态传给前端
    ip_statuses = {ip.id: get_licensing_status(ip) for ip in licensable_ips}

    # 5. --- 新增：获取用于下拉框的选项 ---
    categories = [c[0] for c in db.session.query(IpAsset.category).distinct().filter(IpAsset.category != None)]
    # (关键修改) 按 S, A, B, C 顺序硬编码
    value_levels = ['S', 'A', 'B', 'C']

    # --- 6. (V7 新增!) 获取 AI 嵌入网址 ---
    tencent_embed_url = os.environ.get('TENCENT_EMBED_URL_PARTNER')
    if not tencent_embed_url:
        flash('AI 助手加载失败：未在服务器上配置 TENCENT_EMBED_URL_PARTNER 环境变量。', 'danger')

    return render_template('portal_dashboard.html',
                           title='IP 授权门户',
                           ips=licensable_ips,
                           ip_statuses=ip_statuses,
                           # --- 新增：把选项和当前值传给模板 ---
                           categories=categories,
                           value_levels=value_levels,
                           search_query=search_query,
                           selected_category=category_query,
                           selected_level=level_query,
                           # (V7 新增!)
                           tencent_embed_url=tencent_embed_url
                           )


# --- (2.1) 伙伴端：IP 详情页与点击跟踪 ---
@bp.route('/portal/ip/<int:ip_id>')
@login_required
@partner_required
def ip_detail(ip_id):
    ip = IpAsset.query.get_or_404(ip_id)

    # 接收筛选参数以便返回
    prev_q = request.args.get('q', '')
    prev_cat = request.args.get('category', '')
    prev_lvl = request.args.get('value_level', '')

    status = get_licensing_status(ip)

    # 记录点击
    try:
        new_click = IpAnalytics(ip_id=ip.id, user_id=current_user.id)
        db.session.add(new_click)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error logging click: {e}")  # 在后台打印错误

    return render_template('ip_detail.html',
                           ip=ip,
                           title=ip.name,
                           status=status,
                           prev_q=prev_q, prev_cat=prev_cat, prev_lvl=prev_lvl)


# ==========================================================
# --- (3) AI 专用 API 路由 (内控端) ---
# ==========================================================

# --- API 3.1: 报表 (V5) ---
@bp.route('/api/get_report')
def api_get_report():
    try:
        # === 1. (真实) IP 点击量排行 ===
        click_query = db.session.query(
            IpAsset.name,
            func.count(IpAnalytics.id).label('total_clicks')
        ).join(
            IpAnalytics, IpAsset.id == IpAnalytics.ip_id
        ).group_by(
            IpAsset.name
        ).order_by(
            func.count(IpAnalytics.id).desc()
        ).limit(5)  # 只显示前 5 名

        clicks_results = click_query.all()

        if not clicks_results:
            clicks_report = "IP 点击量报表 (真实数据):\n- 暂无点击数据。"
        else:
            clicks_report_lines = ["IP 点击量报表 (真实数据):"]
            for name, clicks in clicks_results:
                clicks_report_lines.append(f"- {name}: {clicks} 次点击")
            clicks_report = "\n".join(clicks_report_lines)

        # === 2. (真实) 90天内即将到期的合同 ===
        today = date.today()
        ninety_days_later = today + timedelta(days=90)

        expiring_query = Contract.query.join(IpAsset).filter(
            Contract.term_end >= today,
            Contract.term_end <= ninety_days_later
        ).order_by(Contract.term_end.asc())

        expiring_results = expiring_query.all()

        if not expiring_results:
            expiring_report = "90天内即将到期的合同报表 (真实数据):\n- 90天内没有即将到期的合同。"
        else:
            expiring_report_lines = ["90天内即将到期的合同报表 (真实数据):"]
            for contract in expiring_results:
                expiring_report_lines.append(
                    f"- 相对方: {contract.partner_name} (IP: {contract.ip_asset.name}) - 到期日: {contract.term_end.strftime('%Y-%m-%d')}"
                )
            expiring_report = "\n".join(expiring_report_lines)

        return jsonify({
            "status": "success",
            "ip_clicks_report": clicks_report,
            "expiring_report": expiring_report
        })

    except Exception as e:
        print(f"Error in /api/get_report: {e}")
        return jsonify({
            "status": "error",
            "ip_clicks_report": "生成报表时发生内部错误。",
            "expiring_report": "生成报表时发生内部错误。"
        }), 500


# --- API 3.2: 违约条款 (V2) ---
@bp.route('/api/query_breach_terms')
def api_query_breach_terms():
    query = request.args.get('q')
    if not query:
        return jsonify({
            "status": "error",
            "count": 0,
            "report": "查询失败：您必须提供一个查询关键词 (q)。"
        }), 400

    try:
        search_query = f"%{query}%"
        results = Contract.query.filter(
            or_(
                Contract.partner_name.like(search_query),
                Contract.breach_terms.like(search_query)
            )
        ).all()

        count = len(results)
        if count == 0:
            report = f"数据库查询报告：\n- 未找到与“{query}”相关的合同条款。"
        else:
            report_lines = [f"数据库查询报告：\n- 找到 {count} 条与“{query}”相关的合同条款："]
            for i, contract in enumerate(results):
                report_lines.append(f"\n{i + 1}. 相对方: {contract.partner_name} (合同 ID: {contract.id})")
                report_lines.append(f"   相关条款: {contract.breach_terms}")
            report = "\n".join(report_lines)

        return jsonify({
            "status": "success",
            "count": count,
            "report": report
        })

    except Exception as e:
        print(f"Error in /api/query_breach_terms: {e}")
        return jsonify({
            "status": "error",
            "count": 0,
            "report": f"查询时发生内部错误: {e}"
        }), 500


# --- API 3.3: (新!) 数据库全量信息 (给内控 AI 用) ---
@bp.route('/api/get_database_info')
def api_get_database_info():
    """
    [全知全能版] 返回数据库中所有 IP 资产和合同的详细信息。
    供内控端 AI 在被问及概况时调用。
    """
    try:
        # 1. 获取所有 IP 详情
        ips = IpAsset.query.all()
        ip_lines = ["*** IP 资产库详情 ***\n"]
        for ip in ips:
            status = get_licensing_status(ip)
            ip_lines.append(f"【IP ID: {ip.id}】{ip.name}")
            ip_lines.append(f"  - 类别: {ip.category}")
            ip_lines.append(f"  - 级别: {ip.value_level}")
            ip_lines.append(f"  - 作者: {ip.author}")
            ip_lines.append(f"  - 登记号: {ip.reg_number}")
            ip_lines.append(f"  - 许可状态: {status}")
            ip_lines.append(f"  - 创作说明: {ip.description[:50]}...")  # 截取前50字
            ip_lines.append("")  # 空行分隔

        # 2. 获取所有 合同 详情
        contracts = Contract.query.all()
        contract_lines = ["\n*** 许可合同库详情 ***\n"]
        for c in contracts:
            contract_lines.append(f"【合同 ID: {c.id}】{c.partner_name}")
            contract_lines.append(f"  - 授权 IP: {c.ip_asset.name}")
            contract_lines.append(f"  - 许可类型: {c.license_type}")
            contract_lines.append(f"  - 许可地域: {c.region or '未指定'}")
            contract_lines.append(f"  - 许可媒介: {c.media}")
            contract_lines.append(f"  - 有效期: {c.term_start} 至 {c.term_end}")
            contract_lines.append(f"  - 费用标准: {c.fee_standard}")
            contract_lines.append(f"  - 结算周期: {c.payment_cycle}")
            contract_lines.append(f"  - 违约责任: {c.breach_terms[:50]}...")  # 截取
            contract_lines.append("")

        # 3. 拼接完整报告
        full_report = "\n".join(ip_lines + contract_lines)

        return jsonify({
            "status": "success",
            "info_report": full_report
        })

    except Exception as e:
        return jsonify({"status": "error", "info_report": str(e)}), 500


# ==========================================================
# --- (4) AI 专用 API 路由 (伙伴端) ---
# ==========================================================

# --- API 4.1: (V6 - 伙伴端) ---
@bp.route('/api/get_licensable_ips')
def api_get_licensable_ips():
    """
    为 (伙伴端) AI 提供当前所有“可授权”的 IP 列表。
    返回扁平化的纯文本报告。
    """
    try:
        today = date.today()

        # 获取所有IP，然后逐个判断
        all_ips = IpAsset.query.order_by(IpAsset.cooperation_count.desc()).all()

        report = ""
        count = 0
        for ip in all_ips:
            status = get_licensing_status(ip)
            # 只有“完全不可许可”的才隐藏，其他的都展示
            if status != "不可许可":
                count += 1
                report += f"### {ip.name} ({ip.category})\n"
                report += f"- **级别**: {ip.value_level}\n"
                report += f"- **状态**: {status}\n"  # 让 AI 知道是否受限
                report += f"- **介绍**: {ip.description}\n\n"

        if count == 0: report = "当前所有 IP 均处于全球独占或排他许可期，暂无可推荐的 IP。"
        return jsonify({"status": "success", "count": count, "ips_report": report})

    except Exception as e:
        print(f"Error in /api/get_licensable_ips: {e}")
        return jsonify({
            "status": "error",
            "count": 0,
            "ips_report": f"获取可授权 IP 列表时发生内部错误: {e}"
        }), 500


# --- API 4.2: (V6 - 伙伴端) ---
@bp.route('/api/get_fee_guidance')
def api_get_fee_guidance():
    """
    为 (伙伴端) AI 提供特定 IP 的“商业价值级别”，用于测算费用。
    接受一个 'ip_name' query 参数。
    """
    query_name = request.args.get('ip_name')
    if not query_name:
        return jsonify({
            "status": "error",
            "ip_name": "",
            "value_level": "未知"
        }), 400

    try:
        # (真实) 查询数据库
        ip = IpAsset.query.filter(func.lower(IpAsset.name) == func.lower(query_name)).first()

        if not ip:
            return jsonify({
                "status": "error",
                "ip_name": query_name,
                "value_level": "未找到"
            })

        return jsonify({
            "status": "success",
            "ip_name": ip.name,
            "value_level": ip.value_level  # 返回 "S", "A", "B", 或 "C"
        })

    except Exception as e:
        print(f"Error in /api/get_fee_guidance: {e}")
        return jsonify({
            "status": "error",
            "ip_name": query_name,
            "value_level": f"内部错误: {e}"
        }), 500