from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, IntegerField, StringField, validators, SelectField, EmailField
import re


# Create Registration Form
class RegisterForm(FlaskForm):
    """Create new user accounts"""
    # Aden: Create ReCaptcha field for login page
    recaptcha = RecaptchaField()
    # username = StringField('', [validators.DataRequired(), validators.length(min=3, max=25)], render_kw={'placeholder': 'Username'})
    # password = PasswordField('', [validators.DataRequired(), validators.length(min=3, max=100)],
    #                          render_kw={'placeholder': 'Password'})
    # Aden: Adding Mobile Phone and Activation field to register page for Twilio 2FA
    # mobile = StringField('', [validators.length(min=8, max=11)], render_kw={
    #                      'placeholder': 'Mobile'})
    activation = SelectField("2FA", choices=[("yes", "yes"), ("no", "no")])

    # def validate_password(self, field):
    #     if not re.search("[a-z]", field.data):
    #         raise validators.ValidationError("Minimum 1 lowercase.")
    #     elif not re.search("[A-Z]", field.data):
    #         raise validators.ValidationError("Minimum 1 uppercase.")
    #     elif not re.search("[0-9]", field.data):
    #         raise validators.ValidationError("Minimum 1 numerical digit.")
    #     elif not re.search("[@%+/!#$^?:,()]", field.data):
    #         raise validators.ValidationError("Minimum 1 special character.")
    #     elif re.search("\s", field.data):
    #         raise validators.ValidationError("No whitespace.")


class LoginForm(FlaskForm):
    """login form fields"""
    # Aden: Create ReCaptcha field for login page
    recaptcha = RecaptchaField()
    # username = StringField('', [validators.length(min=1, max=100)], render_kw={
    #                        'autofocus': True, 'placeholder': 'Username'})
    # password = PasswordField('', [validators.length(min=3, max=100)], render_kw={
    #                          'placeholder': 'Password'})


class File(FlaskForm):
    """form for file"""
    key = PasswordField('key', render_kw={"placeholder": "password"})


# Aden: Create 2FA form for user to enter 6-digits OTP
class Form2fa(FlaskForm):  # Create 2fa Form
    code2fa = StringField('', [validators.DataRequired(),validators.length(min=6, max=6)], render_kw={
        'autofocus': True, 'placeholder': '2fa code'})
