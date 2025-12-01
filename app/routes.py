import os
import secrets
from datetime import date, timedelta
from docx import Document
from flask import (render_template, flash, redirect, url_for, request,
                   Blueprint, abort, current_app, jsonify)
from flask_login import current_user, login_user, logout_user, login_required
from app import db
from app.models import User, IpAsset, Contract, IpAnalytics
from app.forms import LoginForm, RegistrationForm, IpAssetForm, ContractForm
from sqlalchemy import func, desc, or_
from functools import wraps

bp = Blueprint('main', __name__)


# --- 辅助函数 ---
def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(current_app.root_path, 'static/images', picture_fn)
    os.makedirs(os.path.dirname(picture_path), exist_ok=True)
    form_picture.save(picture_path)
    return os.path.join('images', picture_fn)


def save_pdf(form_pdf):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_pdf.filename)
    pdf_fn = random_hex + f_ext
    pdf_path = os.path.join(current_app.root_path, 'static/pdfs', pdf_fn)
    os.makedirs(os.path.dirname(pdf_path), exist_ok=True)
    form_pdf.save(pdf_path)
    return os.path.join('pdfs', pdf_fn)


def get_licensing_status(ip_asset):
    today = date.today()
    active_contracts = Contract.query.filter(
        Contract.ip_id == ip_asset.id,
        Contract.license_type.in_(['独占许可', '排他许可']),
        Contract.term_start <= today,
        Contract.term_end >= today
    ).all()
    if not active_contracts: return "✅ 暂无限制，可全球许可"
    regions = [c.region for c in active_contracts if c.region]
    for r in regions:
        if "全球" in r: return "🔒 不可许可 (已有全球独占)"
    if regions:
        unique_regions = list(set(regions))
        region_str = "、".join(unique_regions)
        return f"⚠️ 除 {region_str} 外可许可"
    return "✅ 可许可"


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


# --- 页面路由 (保持不变) ---
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
def logout(): logout_user(); return redirect(url_for('main.login'))


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


@bp.route('/internal/dashboard')
@login_required
@internal_required
def internal_dashboard():
    rev_stats = db.session.query(IpAsset.name, IpAsset.current_revenue).order_by(desc(IpAsset.current_revenue)).limit(
        5).all()
    rev_x = [r[0] for r in rev_stats];
    rev_y = [float(r[1]) for r in rev_stats]
    click_stats = db.session.query(IpAsset.name, func.count(IpAnalytics.id)).join(IpAnalytics).group_by(
        IpAsset.name).order_by(func.count(IpAnalytics.id).desc()).limit(5).all()
    click_x = [c[0] for c in click_stats];
    click_y = [c[1] for c in click_stats]

    ip_q_name = request.args.get('ip_name', '');
    ip_q_author = request.args.get('ip_author', '')
    ip_query = IpAsset.query
    if ip_q_name: ip_query = ip_query.filter(IpAsset.name.like(f'%{ip_q_name}%'))
    if ip_q_author: ip_query = ip_query.filter(IpAsset.author.like(f'%{ip_q_author}%'))
    ips = ip_query.all()
    ip_statuses = {ip.id: get_licensing_status(ip) for ip in ips}

    ct_q_partner = request.args.get('ct_partner', '');
    ct_q_ip = request.args.get('ct_ip', '');
    ct_q_type = request.args.get('ct_type', '')
    ct_query = Contract.query.join(IpAsset)
    if ct_q_partner: ct_query = ct_query.filter(Contract.partner_name.like(f'%{ct_q_partner}%'))
    if ct_q_ip: ct_query = ct_query.filter(IpAsset.name.like(f'%{ct_q_ip}%'))
    if ct_q_type: ct_query = ct_query.filter(Contract.license_type == ct_q_type)
    contracts = ct_query.order_by(desc(Contract.id)).all()

    ip_form = IpAssetForm();
    contract_form = ContractForm()
    contract_form.ip_id.choices = [(i.id, i.name) for i in IpAsset.query.all()]
    tencent_embed_url = os.environ.get('TENCENT_EMBED_URL_INTERNAL')

    return render_template('internal_dashboard.html', title='内控台账', ips=ips, ip_statuses=ip_statuses,
                           contracts=contracts, rev_x=rev_x, rev_y=rev_y, click_x=click_x, click_y=click_y,
                           ip_form=ip_form, contract_form=contract_form, search_ip_name=ip_q_name,
                           search_ip_author=ip_q_author, search_ct_partner=ct_q_partner, search_ct_ip=ct_q_ip,
                           search_ct_type=ct_q_type, tencent_embed_url=tencent_embed_url)


@bp.route('/portal/dashboard')
@login_required
@partner_required
def portal_dashboard():
    query = request.args.get('q', '')
    base_query = IpAsset.query
    if query: base_query = base_query.filter(or_(IpAsset.name.like(f'%{query}%'), IpAsset.tags.like(f'%{query}%')))
    ips = base_query.all()
    cases = Contract.query.filter(Contract.case_image_url != None).order_by(desc(Contract.id)).limit(8).all()
    tencent_embed_url = os.environ.get('TENCENT_EMBED_URL_PARTNER')
    return render_template('portal_dashboard.html', title='合作伙伴端', ips=ips, cases=cases, search_query=query,
                           tencent_embed_url=tencent_embed_url)


@bp.route('/portal/ip/<int:ip_id>')
@login_required
@partner_required
def ip_detail(ip_id):
    ip = IpAsset.query.get_or_404(ip_id)
    try:
        db.session.add(IpAnalytics(ip_id=ip.id, user_id=current_user.id)); db.session.commit()
    except:
        pass
    return render_template('ip_detail.html', ip=ip)


# --- 增删操作 (路由保持不变) ---
@bp.route('/ip/add', methods=['POST'])
@login_required
@internal_required
def add_ip():
    form = IpAssetForm()
    if form.validate_on_submit():
        img = save_picture(form.image_file.data) if form.image_file.data else None
        new_ip = IpAsset(name=form.name.data, tags=form.tags.data, description=form.description.data, image_url=img,
                         author=form.author.data, ownership=form.ownership.data, reg_number=form.reg_number.data,
                         reg_date=form.reg_date.data, trademark_info=form.trademark_info.data,
                         license_period=form.license_period.data, contact_email=form.contact_email.data,
                         license_type_options=form.license_type_options.data, value_level=form.value_level.data,
                         current_revenue=form.current_revenue.data or 0)
        db.session.add(new_ip);
        db.session.commit();
        flash('IP 添加成功', 'success')
    else:
        flash('添加失败', 'danger')
    return redirect(url_for('main.internal_dashboard'))


@bp.route('/ip/delete/<int:ip_id>', methods=['POST'])
@login_required
@internal_required
def delete_ip(ip_id):
    ip = IpAsset.query.get_or_404(ip_id)
    if ip.contracts:
        flash('无法删除：请先删除关联的合同', 'danger')
    else:
        db.session.delete(ip); db.session.commit(); flash('IP 已删除', 'success')
    return redirect(url_for('main.internal_dashboard'))


@bp.route('/contract/add', methods=['POST'])
@login_required
@internal_required
def add_contract():
    form = ContractForm()
    form.ip_id.choices = [(i.id, i.name) for i in IpAsset.query.all()]
    if form.validate_on_submit():
        img = save_picture(form.case_image_file.data) if form.case_image_file.data else None
        pdf = save_pdf(form.pdf_file.data) if form.pdf_file.data else None
        nc = Contract(ip_id=form.ip_id.data, partner_name=form.partner_name.data, partner_brand=form.partner_brand.data,
                      region=form.region.data, media=form.media.data, license_method=form.license_method.data,
                      license_category=form.license_category.data, usage_type=form.usage_type.data,
                      license_type=form.license_type.data, term_start=form.term_start.data, term_end=form.term_end.data,
                      fee_standard=form.fee_standard.data, payment_cycle=form.payment_cycle.data,
                      breach_terms=form.breach_terms.data, case_image_url=img, pdf_url=pdf)
        db.session.add(nc);
        db.session.commit();
        flash('合同添加成功', 'success')
    else:
        flash('添加失败', 'danger')
    return redirect(url_for('main.internal_dashboard'))


@bp.route('/contract/delete/<int:contract_id>', methods=['POST'])
@login_required
@internal_required
def delete_contract(contract_id):
    c = Contract.query.get_or_404(contract_id)
    db.session.delete(c);
    db.session.commit();
    flash('合同已删除', 'success')
    return redirect(url_for('main.internal_dashboard'))


# ==================================================================
# --- 伙伴端专用 API (Partner APIs) ---
# ==================================================================

@bp.route('/api/partner/get_licensable_ips', methods=['POST'])
def partner_get_licensable_ips():
    """
    [伙伴端] 模块1: 获取可授权IP列表 (推荐用)
    不返回任何收益数据和合同数据，只返回名称、标签、类别、描述、级别。
    """
    try:
        ips = IpAsset.query.all()
        report = []
        for ip in ips:
            # 简单拼接一个字符串供 AI 理解，或者返回结构化 JSON
            info = f"IP名称: {ip.name} | 标签: {ip.tags} | 描述: {ip.description} | 级别: {ip.value_level} | 状态: {ip.internal_status}"
            report.append(info)

        return jsonify({
            "status": "success",
            "count": len(ips),
            "ips_report": "\n".join(report)
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/partner/get_fee_guidance', methods=['POST'])
def partner_get_fee_guidance():
    """
    [伙伴端] 模块2: 费用智能测算
    根据 IP 名称查询商业价值级别。
    """
    data = request.get_json() or {}
    ip_name = data.get('ip_name')
    if not ip_name:
        return jsonify({"status": "error", "message": "Missing ip_name"}), 400

    try:
        ip = IpAsset.query.filter(IpAsset.name == ip_name).first()
        if not ip:
            return jsonify({"status": "error", "message": "IP not found", "value_level": "未知"})

        return jsonify({
            "status": "success",
            "ip_name": ip.name,
            "value_level": ip.value_level,  # S/A/B/C
            "advice": f"该IP为 {ip.value_level} 级资产，请结合客户行业规模进行区间估算。"
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ==================================================================
# --- 内控端专用 API (Internal APIs) ---
# ==================================================================

@bp.route('/api/internal/get_database_info', methods=['POST'])
def internal_get_database_info():
    """
    [内控端] 模块1: 上帝视角全量查询
    """
    try:
        ips = IpAsset.query.all()
        report = ["【IP 资产全量数据】"]
        for ip in ips:
            status = get_licensing_status(ip)
            report.append(f"ID:{ip.id} | 名称:{ip.name} | 级别:{ip.value_level} | 标签:{ip.tags}")
            report.append(f"  收益:{ip.current_revenue}万 | 状态:{status} | 授权期:{ip.license_period}")
            report.append(f"  权属:{ip.ownership} | 商标:{ip.trademark_info}")
            report.append("---")

        contracts = Contract.query.all()
        report.append("\n【合同台账全量数据】")
        for c in contracts:
            report.append(f"ID:{c.id} | 相对方:{c.partner_name} | IP:{c.ip_asset.name} | 类型:{c.license_type}")
            report.append(f"  有效期:{c.term_start} 至 {c.term_end} | 费用:{c.fee_standard}")
            report.append(f"  条款:{c.breach_terms} | 支付:{c.payment_cycle}")
            report.append("---")

        return jsonify({"status": "success", "info_report": "\n".join(report)})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/internal/get_report', methods=['POST'])
def internal_get_report():
    """
    [内控端] 模块2: 一键生成报表 (点击/收益/到期)
    """
    try:
        # 1. 收益排行
        rev_stats = db.session.query(IpAsset.name, IpAsset.current_revenue).order_by(
            desc(IpAsset.current_revenue)).limit(5).all()
        revenue_report = "【IP当前收益排行 (Top 5)】\n" + "\n".join(
            [f"{i + 1}. {r[0]}: {r[1]}万元" for i, r in enumerate(rev_stats)])

        # 2. 点击热度
        click_stats = db.session.query(IpAsset.name, func.count(IpAnalytics.id)).join(IpAnalytics).group_by(
            IpAsset.name).order_by(func.count(IpAnalytics.id).desc()).limit(5).all()
        click_report = "【IP点击热度排行 (Top 5)】\n" + "\n".join(
            [f"{i + 1}. {c[0]}: {c[1]}次" for i, c in enumerate(click_stats)])

        # 3. 90天内到期预警
        today = date.today()
        ninety_days = today + timedelta(days=90)
        expiring = Contract.query.filter(Contract.term_end >= today, Contract.term_end <= ninety_days).order_by(
            Contract.term_end).all()
        if expiring:
            expire_report = "【90天内到期合同预警】\n" + "\n".join(
                [f"- {c.partner_name} ({c.ip_asset.name}): {c.term_end} 到期" for c in expiring])
        else:
            expire_report = "【到期预警】\n未来90天内暂无即将到期的合同。"

        return jsonify({
            "status": "success",
            "revenue_report": revenue_report,
            "click_report": click_report,
            "expire_report": expire_report
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/internal/generate_contract_doc', methods=['POST'])
def internal_generate_contract_doc():
    """
    [内控端] 模块3: 生成合同初稿 (11项要素)
    """
    data = request.get_json() or {}
    try:
        doc = Document()
        doc.add_heading('IP 授权许可合同 (草案)', 0)

        # 提取 11 项要素
        p_name = data.get('partner_name', '______')  # 相对方
        ip_name = data.get('ip_name', '______')  # IP名称
        region = data.get('region', '中国大陆')  # 地域
        media = data.get('media', '全媒体')  # 媒介
        usage = data.get('usage_type', '商品授权')  # 使用方式
        c_type = data.get('license_type', '普通许可')  # 类型
        term = data.get('term', '1年')  # 期限
        start_d = data.get('start_date', str(date.today()))  # 开始时间
        fee = data.get('fee', '待定')  # 费用
        cycle = data.get('payment_cycle', '一次性')  # 周期
        breach = data.get('breach_terms', '依法协商')  # 违约责任

        doc.add_paragraph(f'甲方：星核文化科技发展有限公司\n乙方：{p_name}\n日期：{date.today()}')

        doc.add_heading('一、 授权内容', level=1)
        doc.add_paragraph(f'1. 授权标的：IP “{ip_name}”')
        doc.add_paragraph(f'2. 授权地域：{region}')
        doc.add_paragraph(f'3. 授权媒介：{media}')
        doc.add_paragraph(f'4. 使用方式：{usage}')
        doc.add_paragraph(f'5. 许可类型：{c_type}')

        doc.add_heading('二、 期限与费用', level=1)
        doc.add_paragraph(f'1. 授权期限：{term} (自 {start_d} 起)')
        doc.add_paragraph(f'2. 许可费用：{fee}')
        doc.add_paragraph(f'3. 结算周期：{cycle}')

        doc.add_heading('三、 违约责任', level=1)
        doc.add_paragraph(f'{breach}')

        doc.add_heading('四、 附则', level=1)
        doc.add_paragraph('本合同一式两份，双方签字盖章后生效。')

        fn = f"Contract_Draft_{secrets.token_hex(4)}.docx"
        sd = os.path.join(current_app.root_path, 'static', 'generated_docs')
        if not os.path.exists(sd): os.makedirs(sd)
        doc.save(os.path.join(sd, fn))

        return jsonify({
            "status": "success",
            "download_url": url_for('static', filename=f'generated_docs/{fn}', _external=True)
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500