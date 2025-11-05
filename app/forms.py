from flask_wtf import FlaskForm
# --- 关键修改：从 flask_wtf.file 导入 FileAllowed ---
from flask_wtf.file import FileAllowed
# 导入 FileField
from wtforms import (StringField, PasswordField, SubmitField, SelectField,
                     BooleanField, TextAreaField, DateField, FileField)
# --- 关键修改：从下面的列表中移除了 FileAllowed ---
from wtforms.validators import (DataRequired, EqualTo, ValidationError,
                                Length, Optional)
from app.models import User


class LoginForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired(message='请输入用户名。')])
    password = PasswordField('密码', validators=[DataRequired(message='请输入密码。')])
    remember_me = BooleanField('记住我')
    submit = SubmitField('登录')


class RegistrationForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired(message='请输入用户名。'), Length(min=3, max=100)])
    password = PasswordField('密码', validators=[DataRequired(message='请输入密码。'), Length(min=6)])
    password2 = PasswordField(
        '确认密码',
        validators=[DataRequired(message='请再次输入密码。'), EqualTo('password', message='两次输入的密码不一致。')])
    role = SelectField('您的身份',
                       choices=[('partner', '合作伙伴'), ('internal', '内部员工')],
                       validators=[DataRequired(message='请选择您的身份。')])
    submit = SubmitField('注册')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('该用户名已被占用，请使用其他用户名。')


# --- IP 资产表单 (表单字段无变化, 导入已修正) ---
class IpAssetForm(FlaskForm):
    name = StringField('IP 名称', validators=[DataRequired()])
    category = StringField('类别')
    description = TextAreaField('创作说明')

    # FileAllowed 现在可以被正确找到了
    image_file = FileField('上传图样', validators=[
        DataRequired(message="请选择一个图片文件。"),
        FileAllowed(['png', 'jpg', 'jpeg'], '只允许上传 .png 和 .jpg 图片！')
    ])

    author = StringField('作者')
    ownership = StringField('权属')
    reg_number = StringField('登记号', validators=[Optional(), Length(max=100)])
    reg_date = DateField('登记日期 (YYYY-MM-DD)', validators=[Optional()])
    license_type_options = StringField('可提供的许可类型')
    value_level = SelectField('商业价值级别', choices=[('S', 'S'), ('A', 'A'), ('B', 'B'), ('C', 'C')],
                              validators=[Optional()])
    submit = SubmitField('添加 IP 资产')


# --- 合同表单 (无变化) ---
class ContractForm(FlaskForm):
    ip_id = SelectField('选择 IP', coerce=int, validators=[DataRequired()])
    partner_name = StringField('相对方名称', validators=[DataRequired()])
    region = StringField('许可地域')
    media = StringField('许可媒介')
    usage_type = StringField('许可使用方式')
    license_type = SelectField('许可类型',
                               choices=[('独占许可', '独占许可'), ('排他许可', '排他许可'), ('普通许可', '普通许可')],
                               validators=[DataRequired()])
    term_start = DateField('许可期限开始 (YYYY-MM-DD)', validators=[DataRequired()])
    term_end = DateField('许可期限结束 (YYYY-MM-DD)', validators=[DataRequired()])
    fee_standard = TextAreaField('许可费标准')
    payment_cycle = TextAreaField('结算周期')
    breach_terms = TextAreaField('违约责任')
    submit = SubmitField('添加合同')

