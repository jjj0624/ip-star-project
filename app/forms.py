# app/forms.py
from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed
from wtforms import (StringField, PasswordField, SubmitField, SelectField,
                     BooleanField, TextAreaField, DateField, FileField, DecimalField)
from wtforms.validators import DataRequired, EqualTo, ValidationError, Length, Optional
from app.models import User


class LoginForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired(message='请输入用户名。')])
    password = PasswordField('密码', validators=[DataRequired(message='请输入密码。')])
    remember_me = BooleanField('记住我')
    submit = SubmitField('登录')


class RegistrationForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired(), Length(min=3, max=100)])
    password = PasswordField('密码', validators=[DataRequired(), Length(min=6)])
    password2 = PasswordField('确认密码', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('身份', choices=[('partner', '合作伙伴'), ('internal', '内部员工')], validators=[DataRequired()])
    submit = SubmitField('注册')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('该用户名已被占用。')


class IpAssetForm(FlaskForm):
    name = StringField('IP 名称', validators=[DataRequired()])
    category = StringField('类别 (废弃字段,可填无)', validators=[Optional()])  # 兼容旧逻辑
    tags = StringField('标签 (用分号分隔)', validators=[Optional()])  # 新增
    description = TextAreaField('创作说明')

    image_file = FileField('上传图样', validators=[
        FileAllowed(['png', 'jpg', 'jpeg'], '只允许上传图片！')
    ])

    author = StringField('作者')
    ownership = StringField('权属')
    reg_number = StringField('登记号')
    reg_date = DateField('登记日期', validators=[Optional()])
    trademark_info = TextAreaField('商标信息', validators=[Optional()])  # 新增
    license_period = StringField('可授权期限', validators=[Optional()])  # 新增
    contact_email = StringField('联系邮箱', validators=[Optional()])  # 新增

    license_type_options = StringField('可提供的许可类型')
    value_level = SelectField('价值级别', choices=[('S', 'S'), ('A', 'A'), ('B', 'B'), ('C', 'C')],
                              validators=[Optional()])
    current_revenue = DecimalField('目前收益 (万元)', places=2, validators=[Optional()])  # 新增

    submit = SubmitField('保存 IP 资产')


class ContractForm(FlaskForm):
    ip_id = SelectField('选择 IP', coerce=int, validators=[DataRequired()])
    partner_name = StringField('相对方名称', validators=[DataRequired()])
    partner_brand = StringField('相对方品牌', validators=[Optional()])  # 新增

    region = StringField('许可地域')
    media = StringField('许可媒介')
    license_method = StringField('许可方式', validators=[Optional()])  # 新增
    license_category = StringField('许可类别', validators=[Optional()])  # 新增
    usage_type = StringField('使用方式')

    license_type = SelectField('许可类型',
                               choices=[('独占许可', '独占许可'), ('排他许可', '排他许可'), ('普通许可', '普通许可')])
    term_start = DateField('开始日期', validators=[DataRequired()])
    term_end = DateField('结束日期', validators=[DataRequired()])

    fee_standard = TextAreaField('费用标准')
    payment_cycle = TextAreaField('结算周期')
    breach_terms = TextAreaField('违约责任 (可选)', validators=[Optional()])

    # 新增文件上传
    case_image_file = FileField('合作案例图 (可选)', validators=[FileAllowed(['png', 'jpg', 'jpeg'])])
    pdf_file = FileField('合同原件PDF (可选)', validators=[FileAllowed(['pdf'])])

    submit = SubmitField('保存合同')