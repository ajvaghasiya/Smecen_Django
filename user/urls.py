
from django.urls import path
from .views import signup, login, fleiologin, send_otp_code, resendOTP, verify_otp_code, change_password, forgot_password_send_mail, password_reset_confirmView, logout_user, state_view,user_deletion
from django.contrib.auth import views


urlpatterns = [
    path("signup", signup, name="signup"),  # New user Signup URL
    path('login', login, name="login"),  # Login User URL
    path('logout', logout_user, name='logout'), #Logout URL
    path('fleio', fleiologin, name='fleio'), #flieo Login URL
    path('send_otp_code', send_otp_code,name="send_otp_code"),  # send OTP for user URL
    path("resendotp", resendOTP, name="resendotp"), #resenf OPT Code
    path("verify_otp_code", verify_otp_code,name="verify_otp_code"),  # Verify OTP URL
    path('password_change', change_password, name="password_change"), #password change
    path('reset', forgot_password_send_mail, name="password_reset"), #password reset view
    path('reset/<uidb64>/<token>', password_reset_confirmView,name="password_reset_confirmView"), #password reset confirm view
    path("states", state_view, name="states"),
    path("user-deletion", user_deletion, name="user-deletion"),
]
