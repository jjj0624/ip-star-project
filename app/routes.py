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
from sqlalchemy import func, desc, or_
from functools import wraps

bp = Blueprint('main', __name__)


# --- 辅助函数：保存图片 ---
def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(current_app.root_path, 'static/images', picture_fn)
    # 确保目录存在
    os.makedirs(os.path.dirname(picture_path), exist_ok=True)
    form_picture.save(picture_path)
    return os.path.join('images', picture_fn)


# --- 辅助函数：保存PDF ---
def save_pdf(form_pdf):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_pdf.filename)
    pdf_fn = random_hex + f_ext
    pdf_path = os.path.join(current_app.root_path, 'static/pdfs', pdf_fn)
    os.makedirs(os.path.dirname(pdf_path), exist_ok=True)
    form_pdf.save(pdf_path)
    return os.path.join('pdfs', pdf_fn)


# --- 辅助函数：计算详细许可状态 ---
def get_licensing_status(ip_asset):
    today = date.today()
    # 查询生效中的独占/排他合同
    active_contracts = Contract.query.filter(
        Contract.ip_id == ip_asset.id,
        Contract.license_type.in_(['独占许可', '排他许可']),
        Contract.term_start <= today,
        Contract.term_end >= today
    ).all()

    if not active_contracts:
        return "✅ 暂无限制，可全球许可"

    regions = [c.region for c in active_contracts if c.region]

    # 如果有“全球”独占，直接锁死
    for r in regions:
        if "全球" in r:
            return "🔒 不可许可 (已有全球独占)"

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


# --- 内控端看板 ---
@bp.route('/internal/dashboard')
@login_required
@internal_required
def internal_dashboard():
    # 1. 统计数据
    rev_stats = db.session.query(IpAsset.name, IpAsset.current_revenue).order_by(desc(IpAsset.current_revenue)).limit(
        5).all()
    rev_x = [r[0] for r in rev_stats]
    rev_y = [float(r[1]) for r in rev_stats]

    click_stats = db.session.query(IpAsset.name, func.count(IpAnalytics.id)).join(IpAnalytics).group_by(
        IpAsset.name).order_by(func.count(IpAnalytics.id).desc()).limit(5).all()
    click_x = [c[0] for c in click_stats]
    click_y = [c[1] for c in click_stats]

    # 2. IP查询
    ip_q_name = request.args.get('ip_name', '')
    ip_q_author = request.args.get('ip_author', '')
    ip_query = IpAsset.query
    if ip_q_name: ip_query = ip_query.filter(IpAsset.name.like(f'%{ip_q_name}%'))
    if ip_q_author: ip_query = ip_query.filter(IpAsset.author.like(f'%{ip_q_author}%'))
    ips = ip_query.all()

    # 计算状态
    ip_statuses = {ip.id: get_licensing_status(ip) for ip in ips}

    # 3. 合同查询
    ct_q_partner = request.args.get('ct_partner', '')
    ct_q_ip = request.args.get('ct_ip', '')
    ct_query = Contract.query.join(IpAsset)
    if ct_q_partner: ct_query = ct_query.filter(Contract.partner_name.like(f'%{ct_q_partner}%'))
    if ct_q_ip: ct_query = ct_query.filter(IpAsset.name.like(f'%{ct_q_ip}%'))
    contracts = ct_query.order_by(desc(Contract.id)).all()

    # 表单实例化
    ip_form = IpAssetForm()
    contract_form = ContractForm()
    # 动态填充合同表单的 IP 选项
    contract_form.ip_id.choices = [(i.id, i.name) for i in IpAsset.query.all()]

    tencent_embed_url = os.environ.get('TENCENT_EMBED_URL_INTERNAL')

    return render_template('internal_dashboard.html', title='内控台账',
                           ips=ips, ip_statuses=ip_statuses, contracts=contracts,
                           rev_x=rev_x, rev_y=rev_y, click_x=click_x, click_y=click_y,
                           ip_form=ip_form, contract_form=contract_form,
                           search_ip_name=ip_q_name, search_ip_author=ip_q_author,
                           search_ct_partner=ct_q_partner, search_ct_ip=ct_q_ip,
                           tencent_embed_url=tencent_embed_url)


# --- 伙伴端门户 ---
@bp.route('/portal/dashboard')
@login_required
@partner_required
def portal_dashboard():
    # 1. IP 检索
    query = request.args.get('q', '')
    base_query = IpAsset.query
    if query: base_query = base_query.filter(or_(IpAsset.name.like(f'%{query}%'), IpAsset.tags.like(f'%{query}%')))
    ips = base_query.all()

    # 2. 合作案例
    cases = Contract.query.filter(Contract.case_image_url != None).order_by(desc(Contract.id)).limit(8).all()

    tencent_embed_url = os.environ.get('TENCENT_EMBED_URL_PARTNER')
    return render_template('portal_dashboard.html', title='合作伙伴端',
                           ips=ips, cases=cases, search_query=query,
                           tencent_embed_url=tencent_embed_url)


@bp.route('/portal/ip/<int:ip_id>')
@login_required
@partner_required
def ip_detail(ip_id):
    ip = IpAsset.query.get_or_404(ip_id)
    # 记录点击
    try:
        db.session.add(IpAnalytics(ip_id=ip.id, user_id=current_user.id))
        db.session.commit()
    except:
        pass
    return render_template('ip_detail.html', ip=ip)


# --- 增删改查路由 ---
@bp.route('/ip/add', methods=['POST'])
@login_required
@internal_required
def add_ip():
    form = IpAssetForm()
    if form.validate_on_submit():
        img_path = save_picture(form.image_file.data) if form.image_file.data else None
        new_ip = IpAsset(
            name=form.name.data, tags=form.tags.data, description=form.description.data,
            image_url=img_path, author=form.author.data, ownership=form.ownership.data,
            reg_number=form.reg_number.data, reg_date=form.reg_date.data,
            trademark_info=form.trademark_info.data, license_period=form.license_period.data,
            contact_email=form.contact_email.data, license_type_options=form.license_type_options.data,
            value_level=form.value_level.data, current_revenue=form.current_revenue.data or 0
        )
        db.session.add(new_ip)
        try:
            db.session.commit()
            flash('IP 添加成功', 'success')
        except Exception as e:
            db.session.rollback();
            flash(f'添加失败: {e}', 'danger')
    else:
        flash('表单验证失败，请检查输入', 'danger')
    return redirect(url_for('main.internal_dashboard'))


@bp.route('/ip/delete/<int:ip_id>', methods=['POST'])
@login_required
@internal_required
def delete_ip(ip_id):
    ip = IpAsset.query.get_or_404(ip_id)
    if ip.contracts:
        flash('删除失败：请先删除关联的合同', 'danger')
    else:
        db.session.delete(ip);
        db.session.commit()
        flash('IP 已删除', 'success')
    return redirect(url_for('main.internal_dashboard'))


@bp.route('/contract/add', methods=['POST'])
@login_required
@internal_required
def add_contract():
    form = ContractForm()
    # 重新填充选项以通过验证
    form.ip_id.choices = [(i.id, i.name) for i in IpAsset.query.all()]
    if form.validate_on_submit():
        case_img = save_picture(form.case_image_file.data) if form.case_image_file.data else None
        pdf_path = save_pdf(form.pdf_file.data) if form.pdf_file.data else None

        nc = Contract(
            ip_id=form.ip_id.data, partner_name=form.partner_name.data, partner_brand=form.partner_brand.data,
            region=form.region.data, media=form.media.data, license_method=form.license_method.data,
            license_category=form.license_category.data, usage_type=form.usage_type.data,
            license_type=form.license_type.data, term_start=form.term_start.data, term_end=form.term_end.data,
            fee_standard=form.fee_standard.data, payment_cycle=form.payment_cycle.data,
            breach_terms=form.breach_terms.data, case_image_url=case_img, pdf_url=pdf_path
        )
        db.session.add(nc);
        db.session.commit()
        flash('合同添加成功', 'success')
    else:
        flash('合同表单验证失败', 'danger')
    return redirect(url_for('main.internal_dashboard'))


@bp.route('/contract/delete/<int:contract_id>', methods=['POST'])
@login_required
@internal_required
def delete_contract(contract_id):
    c = Contract.query.get_or_404(contract_id)
    db.session.delete(c);
    db.session.commit()
    flash('合同已删除', 'success')
    return redirect(url_for('main.internal_dashboard'))


# --- AI API 接口 (保持之前版本) ---
@bp.route('/api/get_database_info', methods=['POST'])
def api_get_database_info():
    try:
        ips = IpAsset.query.all()
        report = ["【IP 资产全量数据】"]
        for ip in ips:
            status = get_licensing_status(ip)  # 使用新逻辑
            report.append(f"IP名称: {ip.name} | 级别: {ip.value_level} | 标签: {ip.tags}")
            report.append(f"  目前收益: {ip.current_revenue}万 | 状态: {status}")
            report.append(f"  权属: {ip.ownership} | 登记号: {ip.reg_number}")
            report.append(f"  商标: {ip.trademark_info} | 授权期: {ip.license_period}")
            report.append("----------------")

        contracts = Contract.query.all()
        report.append("\n【合同台账全量数据】")
        for c in contracts:
            report.append(f"合同对象: {c.partner_name} | IP: {c.ip_asset.name} | 类型: {c.license_type}")
            report.append(f"  有效期: {c.term_start} 至 {c.term_end} | 费用: {c.fee_standard}")
            report.append("----------------")
        return jsonify({"status": "success", "info_report": "\n".join(report)})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route('/api/generate_contract_doc', methods=['POST'])
def api_generate_contract_doc():
    data = request.get_json() or {}
    p_name = data.get('partner_name', '未命名方')
    ip_name = data.get('ip_name', '未命名IP')
    money = data.get('money', '待定')
    try:
        doc = Document()
        doc.add_heading('IP 授权许可合同 (AI初稿)', 0)
        doc.add_paragraph(f'甲方：星核文化科技发展有限公司\n乙方：{p_name}\n日期：{date.today()}')
        doc.add_heading('一、 授权事项', level=1)
        doc.add_paragraph(f'甲方同意将 IP “{ip_name}” 授权给乙方使用。')
        doc.add_heading('二、 费用条款', level=1)
        doc.add_paragraph(f'双方约定许可费用为：{money}。')

        fn = f"Contract_{secrets.token_hex(4)}.docx"
        s_dir = os.path.join(current_app.root_path, 'static', 'generated_docs')
        if not os.path.exists(s_dir): os.makedirs(s_dir)
        doc.save(os.path.join(s_dir, fn))

        return jsonify(
            {"status": "success", "download_url": url_for('static', filename=f'generated_docs/{fn}', _external=True)})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500