from flask import (render_template, flash, redirect, url_for, request,
                   Blueprint, abort, current_app)
from flask_login import current_user, login_user, logout_user, login_required
from app import db
from app.models import User, IpAsset, Contract, IpAnalytics
from app.forms import LoginForm, RegistrationForm, IpAssetForm, ContractForm
from sqlalchemy import not_
from datetime import date
from functools import wraps
import os
from werkzeug.utils import secure_filename

# 创建一个蓝图
bp = Blueprint('main', __name__)


# --- 自定义装饰器 (无变化) ---
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


# --- 首页与重定向 (无变化) ---
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


# --- 认证路由 (无变化) ---
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


# --- (1) 内控端路由 (无变化) ---
@bp.route('/internal/dashboard')
@login_required
@internal_required
def internal_dashboard():
    # 1. 获取所有筛选参数
    ip_name_query = request.args.get('ip_name', '')
    ip_category_query = request.args.get('ip_category', '')
    contract_partner_query = request.args.get('contract_partner', '')
    contract_ip_query = request.args.get('contract_ip', '')

    # 2. 计算"不可许可"的 IP set
    today = date.today()
    locked_ip_ids_query = db.session.query(Contract.ip_id).distinct().filter(
        Contract.license_type.in_(['独占许可', '排他许可']),
        Contract.term_start <= today,
        Contract.term_end >= today
    )
    locked_ip_set = {item[0] for item in locked_ip_ids_query.all()}

    # 3. IP 查询
    ip_query = IpAsset.query
    if ip_name_query:
        ip_query = ip_query.filter(IpAsset.name.like(f'%{ip_name_query}%'))
    if ip_category_query:
        ip_query = ip_query.filter(IpAsset.category == ip_category_query)

    all_ips = ip_query.order_by(IpAsset.id).all()

    # 4. 为每个 IP 附加许可状态
    for ip in all_ips:
        ip.computed_status = '不可许可' if ip.id in locked_ip_set else '可许可'

    # 5. 合同查询
    contract_query = Contract.query.join(IpAsset)
    if contract_partner_query:
        contract_query = contract_query.filter(Contract.partner_name.like(f'%{contract_partner_query}%'))
    if contract_ip_query:
        contract_query = contract_query.filter(IpAsset.name.like(f'%{contract_ip_query}%'))

    all_contracts = contract_query.order_by(Contract.id).all()

    # 6. 获取用于筛选下拉框的类别
    categories = db.session.query(IpAsset.category).distinct().all()

    # 7. 准备添加表单
    ip_form = IpAssetForm()
    contract_form = ContractForm()
    contract_form.ip_id.choices = [(ip.id, ip.name) for ip in all_ips]

    return render_template('internal_dashboard.html',
                           title='内控管理台',
                           ips=all_ips,
                           contracts=all_contracts,
                           categories=[c[0] for c in categories if c[0]],
                           ip_form=ip_form,
                           contract_form=contract_form,
                           search_ip_name=ip_name_query,
                           search_ip_category=ip_category_query,
                           search_contract_partner=contract_partner_query,
                           search_contract_ip=contract_ip_query)


# --- (2) 伙伴端路由 (已修正) ---
@bp.route('/portal/dashboard')
@login_required
@partner_required
def portal_dashboard():
    search_query = request.args.get('q', '')
    category_query = request.args.get('category', '')
    level_query = request.args.get('value_level', '')

    today = date.today()

    locked_ip_ids_query = db.session.query(Contract.ip_id).distinct().filter(
        Contract.license_type.in_(['独占许可', '排他许可']),
        Contract.term_start <= today,
        Contract.term_end >= today
    )
    locked_ip_ids = [item[0] for item in locked_ip_ids_query.all()]

    base_query = IpAsset.query.filter(
        not_(IpAsset.id.in_(locked_ip_ids))
    )

    if search_query:
        base_query = base_query.filter(
            IpAsset.name.like(f'%{search_query}%')
        )

    if category_query:
        base_query = base_query.filter(IpAsset.category == category_query)

    if level_query:
        base_query = base_query.filter(IpAsset.value_level == level_query)

    licensable_ips = base_query.order_by(IpAsset.cooperation_count.desc()).all()

    categories = [c[0] for c in db.session.query(IpAsset.category).distinct().filter(IpAsset.category != None)]

    # --- 关键修改：我们在这里手动定义顺序 ---
    value_levels = ['S', 'A', 'B', 'C']
    # --- 结束修改 ---

    return render_template('portal_dashboard.html',
                           title='IP 授权门户',
                           ips=licensable_ips,
                           categories=categories,
                           value_levels=value_levels,
                           search_query=search_query,
                           selected_category=category_query,
                           selected_level=level_query)


# --- (3) 伙伴端-IP详情页 (无变化) ---
@bp.route('/portal/ip/<int:ip_id>')
@login_required
@partner_required
def ip_detail(ip_id):
    ip = IpAsset.query.get_or_404(ip_id)
    try:
        new_click = IpAnalytics(ip_id=ip.id, user_id=current_user.id)
        db.session.add(new_click)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error logging click: {e}")
    return render_template('ip_detail.html', ip=ip, title=ip.name)


# --- (4) 新增路由：处理添加/删除 (无变化) ---

@bp.route('/ip/add', methods=['POST'])
@login_required
@internal_required
def add_ip():
    form = IpAssetForm()

    all_ips_for_contract_form = IpAsset.query.all()
    contract_form = ContractForm()
    contract_form.ip_id.choices = [(ip.id, ip.name) for ip in all_ips_for_contract_form]

    if form.validate_on_submit():
        file = form.image_file.data
        filename = secure_filename(file.filename)
        save_path = os.path.join(current_app.root_path, 'static/images', filename)
        try:
            file.save(save_path)
            image_db_path = f'images/{filename}'
        except Exception as e:
            flash(f'文件保存失败: {e}', 'danger')
            return redirect(url_for('main.internal_dashboard'))

        new_ip = IpAsset(
            name=form.name.data,
            category=form.category.data,
            description=form.description.data,
            image_url=image_db_path,
            author=form.author.data,
            ownership=form.ownership.data,
            reg_number=form.reg_number.data,
            reg_date=form.reg_date.data,
            license_type_options=form.license_type_options.data,
            value_level=form.value_level.data
        )
        db.session.add(new_ip)
        try:
            db.session.commit()
            flash('IP 资产添加成功！', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'添加失败: {e}', 'danger')

        return redirect(url_for('main.internal_dashboard'))

    else:
        # 表单验证失败
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'字段 "{getattr(form, field).label.text}" 错误: {error}', 'danger')

        # 重新渲染页面
        ip_name_query = request.args.get('ip_name', '')
        ip_category_query = request.args.get('ip_category', '')
        contract_partner_query = request.args.get('contract_partner', '')
        contract_ip_query = request.args.get('contract_ip', '')
        today = date.today()
        locked_ip_ids_query = db.session.query(Contract.ip_id).distinct().filter(
            Contract.license_type.in_(['独占许可', '排他许可']),
            Contract.term_start <= today,
            Contract.term_end >= today
        )
        locked_ip_set = {item[0] for item in locked_ip_ids_query.all()}
        ip_query = IpAsset.query
        if ip_name_query:
            ip_query = ip_query.filter(IpAsset.name.like(f'%{ip_name_query}%'))
        if ip_category_query:
            ip_query = ip_query.filter(IpAsset.category == ip_category_query)
        all_ips = ip_query.order_by(IpAsset.id).all()
        for ip in all_ips:
            ip.computed_status = '不可许可' if ip.id in locked_ip_set else '可许可'
        contract_query = Contract.query.join(IpAsset)
        if contract_partner_query:
            contract_query = contract_query.filter(Contract.partner_name.like(f'%{contract_partner_query}%'))
        if contract_ip_query:
            contract_query = contract_query.filter(IpAsset.name.like(f'%{contract_ip_query}%'))
        all_contracts = contract_query.order_by(Contract.id).all()
        categories = db.session.query(IpAsset.category).distinct().all()

        return render_template('internal_dashboard.html',
                               title='内控管理台',
                               ips=all_ips,
                               contracts=all_contracts,
                               categories=[c[0] for c in categories if c[0]],
                               ip_form=form,
                               contract_form=contract_form,
                               search_ip_name=ip_name_query,
                               search_ip_category=ip_category_query,
                               search_contract_partner=contract_partner_query,
                               search_contract_ip=contract_ip_query)


@bp.route('/ip/delete/<int:ip_id>', methods=['POST'])
@login_required
@internal_required
def delete_ip(ip_id):
    ip = IpAsset.query.get_or_404(ip_id)
    try:
        db.session.delete(ip)
        db.session.commit()
        flash('IP 资产删除成功。', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'删除失败：该 IP 仍有关联合同，请先删除合同。({e})', 'danger')
    return redirect(url_for('main.internal_dashboard'))


@bp.route('/contract/add', methods=['POST'])
@login_required
@internal_required
def add_contract():
    form = ContractForm()
    all_ips = IpAsset.query.all()
    form.ip_id.choices = [(ip.id, ip.name) for ip in all_ips]

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
        db.session.add(new_contract)
        try:
            db.session.commit()
            flash('合同添加成功！', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'添加失败: {e}', 'danger')

        return redirect(url_for('main.internal_dashboard'))

    else:
        # 表单验证失败
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'字段 "{getattr(form, field).label.text}" 错误: {error}', 'danger')

        ip_form = IpAssetForm()
        ip_name_query = request.args.get('ip_name', '')
        ip_category_query = request.args.get('ip_category', '')
        contract_partner_query = request.args.get('contract_partner', '')
        contract_ip_query = request.args.get('contract_ip', '')
        today = date.today()
        locked_ip_ids_query = db.session.query(Contract.ip_id).distinct().filter(
            Contract.license_type.in_(['独占许可', '排他许可']),
            Contract.term_start <= today,
            Contract.term_end >= today
        )
        locked_ip_set = {item[0] for item in locked_ip_ids_query.all()}
        ip_query = IpAsset.query
        if ip_name_query:
            ip_query = ip_query.filter(IpAsset.name.like(f'%{ip_name_query}%'))
        if ip_category_query:
            ip_query = ip_query.filter(IpAsset.category == ip_category_query)
        for ip in all_ips:
            ip.computed_status = '不可许可' if ip.id in locked_ip_set else '可许可'
        contract_query = Contract.query.join(IpAsset)
        if contract_partner_query:
            contract_query = contract_query.filter(Contract.partner_name.like(f'%{contract_partner_query}%'))
        if contract_ip_query:
            contract_query = contract_query.filter(IpAsset.name.like(f'%{contract_ip_query}%'))
        all_contracts = contract_query.order_by(Contract.id).all()
        categories = db.session.query(IpAsset.category).distinct().all()

        return render_template('internal_dashboard.html',
                               title='内控管理台',
                               ips=all_ips,
                               contracts=all_contracts,
                               categories=[c[0] for c in categories if c[0]],
                               ip_form=ip_form,
                               contract_form=form,
                               search_ip_name=ip_name_query,
                               search_ip_category=ip_category_query,
                               search_contract_partner=contract_partner_query,
                               search_contract_ip=contract_ip_query)


@bp.route('/contract/delete/<int:contract_id>', methods=['POST'])
@login_required
@internal_required
def delete_contract(contract_id):
    contract = Contract.query.get_or_404(contract_id)
    try:
        db.session.delete(contract)
        db.session.commit()
        flash('合同删除成功。', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'删除失败: {e}', 'danger')
    return redirect(url_for('main.internal_dashboard'))

