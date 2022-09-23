from django.http.response import HttpResponseRedirect
from django.shortcuts import render, redirect
from .models import User, Country, State
from django.contrib.auth import authenticate, logout
from django.contrib.auth import login as auth_login
import requests
import re
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.mail import send_mail
from twilio.rest import Client
import random
from smtplib import SMTPException
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.template.loader import render_to_string
from django.contrib.auth import update_session_auth_hash
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.hashers import check_password
from django.core.validators import validate_email
from django.core import serializers
import json
from django.contrib import auth
from rest_framework.decorators import api_view


# User Signup View
@csrf_exempt
def signup(request):
    COUNTRIESs = Country.objects.all().order_by('country')
    # If User Is Authenticated Return to Home Page
    if request.user.is_authenticated:
        return redirect('home')

    if request.method == "POST":

        # Pattern For Password Format
        pattern = r"^(?=.*[\d])(?=.*[A-Z])(?=.*[a-z])(?=.*[!#$@%&])[\w\d!#$@%&]{8,20}$"

        # Check For Password Format
        if request.POST['password1'] == request.POST['password2'] and len(request.POST['password1']) >= 8 and len(request.POST['password2']) >= 8 and re.match(pattern, request.POST['password1']):

            # Check If User Email Already Exist
            if User.objects.filter(email=request.POST['email']).exists():
                return JsonResponse({"error": 'Email Already Exits'}, status=409)

            else:
                if "sms" in request.POST and request.POST['sms'] == True:
                    sms = True
                else:
                    sms = False

                # Create Username to concat Using User FirstName and LastName
                username = request.POST['first_name'] + \
                    " " + request.POST['last_name']

                # Create User Payload
                userdata = User(email=request.POST['email'], company_name=request.POST['company_name'],
                                first_name=request.POST['first_name'], middle_name=request.POST['middle_name'], last_name=request.POST['last_name'], street_address=request.POST['street_address'], street_address2=request.POST['street_address2'], city=request.POST['city'], state=request.POST['state'], zip=request.POST['zip'], country=request.POST['country'], telephone_number=request.POST['telephone_number'], sms=sms, username=username)

                # Set Hash User Password
                userdata.set_password(request.POST['password1'])

                # Set User is_active False for Verification
                userdata.is_active = False

                # Get Captcha Response
                captcha_response = request.POST['g-recaptcha-response']

                # Get Google Recaptcha Secret key
                secret_key = settings.GOOGLE_RECAPTCHA_SECRET_KEY

                # Captcha Payload
                captcha_payload = {
                    'secret': secret_key,
                    'response': captcha_response
                }

                # Verify Captcha Response
                captcha_verify = requests.post(
                    "https://www.google.com/recaptcha/api/siteverify", data=captcha_payload).json()

                # Check if Captcha not Success
                if not captcha_verify['success']:
                    return JsonResponse({"error": "Invalid reCAPTCHA Please try again..."}, status=400)
                else:
                    # API For create New User in Fleio Portal
                    signupurl = "https://portal.ideadc.com/backend/api/signup-ideadc"

                    # User Payload For Create New User In Fleio
                    data = {"email": request.POST['email'], "first_name": request.POST['first_name'],
                            "last_name": request.POST['last_name'], "password": request.POST['password1'], "rememberMe": "true"}

                    try:
                        # Calling API
                        fleio_signup = requests.post(signupurl, data=data)

                        if fleio_signup.status_code == 400:
                            response = fleio_signup.json().get("email", None)

                            if response:

                                # Forgot Password API
                                forgotpasswordAPI = "https://portal.ideadc.com/backend/api/reset-password-ideadc/"

                                # User Payload For Forgto Password
                                data = {"email": request.POST['email'], "new_password": request.POST['password1'],
                                        "confirm_password": request.POST['password1']}

                                # Update The User Password If Email Already Used in Fleio
                                requests.post(url=forgotpasswordAPI, data=data)
                        if fleio_signup.status_code == 200:
                            # Token create for Client Create
                            token_API = "https://portal.ideadc.com/backend/api/fleio-ideadc-token/"

                            header = {
                                'Content-Type': "application/json"
                            }
                            data = {
                                "email": request.POST['email'],
                            }
                            gettoken = requests.post(
                                token_API, data=json.dumps(data), headers=header)
                            response = gettoken.json().get("token", None)

                            if response:
                                # Calling Api Cleint Create
                                client_API = "https://portal.ideadc.com/backend/api/clients"

                                header = {
                                    'Authorization': f'Token {response}',
                                    'Content-Type': "application/json"
                                }
                                country = Country.objects.get(
                                    country=request.POST["country"])

                                client_payload = {"address1": request.POST['street_address'], "city": request.POST["city"], "country": country.sortname, "create_auto_order_service": "true", "currency": "EUR", "email": request.POST['email'],
                                                  "first_name": request.POST['first_name'], "last_name": request.POST['last_name'], "phone": request.POST['telephone_number'], "state": request.POST["state"], "zip_code": request.POST["zip"]}
                                try:
                                    requests.post(client_API, data=json.dumps(
                                        client_payload), headers=header)
                                except:
                                    pass

                    except:
                        pass

                    # Save User Data
                    userdata.save()

                    # Save In Session
                    request.session['email'] = request.POST['email']
                    request.session['user_password'] = request.POST['password1']
                    request.session['mobileno'] = request.POST['telephone_number']

                    # Return To Verification Page
                    return redirect("send_otp_code")
        else:
            # Error Show Password Related
            if not request.POST['password1'] == request.POST['password2']:
                return JsonResponse({"error": "Password Doesn't Match."}, status=401)

            elif len(request.POST['password1']) < 8 and len(request.POST['password2']) < 8:
                return JsonResponse({"error": 'Password should be at least 8 characters long.'}, status=400)

            else:
                return JsonResponse({"error": 'Password should have at least: one lower case letter, one upper case letter, one number and one special character !#$@%&.'}, status=400)
    return render(request, 'allauth/account/signup.html', {"COUNTRIES": COUNTRIESs, 'site_key': settings.GOOGLE_RECAPTCHA_SITE_KEY, "URL": settings.URL})


# Login User View
@csrf_exempt
def login(request):
    # If User Is Authenticated Return to Home Page
    if request.user.is_authenticated:
        return redirect('home')

    #  If Request Method Is POST
    if request.method == 'POST':

        # Checking Validate Email
        try:
            validate_email(request.POST['email'])
        except:
            return JsonResponse({"error": "Please enter valid e-mail address"}, status=400)

        try:
            # Get user Details
            user = User.objects.get(email=request.POST['email'])
            if user.is_active == True:

                # Checking Authenticated User
                user = authenticate(request, username=request.POST['email'],
                                    password=request.POST['password'])

                if user is not None:
                    # Login User
                    auth_login(request, user)

                    # Login API Fleio
                    loginapi = "https://portal.ideadc.com/backend/api/login"

                    # Header
                    header = {
                        'Authorization': 'Token 66a11f842436036e31dae3ef38ad31734ec6f351'}

                    # User payload for Login In Fleio
                    payload = {"username": request.POST['email'], "password": request.POST['password'],
                               "remember_me": True, "sfa_params": None}

                    # Calling Login API for Fleio
                    response = requests.post(
                        loginapi, data=payload, headers=header)

                    # Checking Status
                    if response.status_code == 200:
                        pass
                    else:
                        # Create New User If not found in Fleio
                        signupurl = "https://portal.ideadc.com/backend/api/signup-ideadc"
                        data = {"email": request.POST['email'], "first_name": user.first_name,
                                "last_name": user.last_name, "password": request.POST['password'], "rememberMe": "true"}
                        try:
                            requests.post(signupurl, data=data)
                        except:
                            pass

                    # Create A session
                    request.session['email'] = request.POST['email']
                    request.session['user_password'] = request.POST['password']

                    return JsonResponse({"success": 'Successfully User Login.'}, status=200)
                else:
                    return JsonResponse({"error": 'password is incorrect'}, status=401)
            else:
                # If User Not Active Return To Verification Page
                request.session['email'] = user.email
                request.session['mobileno'] = user.telephone_number
                return JsonResponse({"error": 'Verify Your Account'}, status=403)
        except:
            # Showing User Email Not Found
            return JsonResponse({"error": str(request.POST['email'])+' is not registered with us'}, status=400)

    return render(request, 'allauth/account/login.html', {'site_key': settings.GOOGLE_RECAPTCHA_SITE_KEY, "URL": settings.URL})


# Fleio Login View
@login_required
@csrf_exempt
def fleiologin(request):

    if request.method == "GET":
        # Get Fleio Email and Fleio Password
        fleio_email = request.session.get('email')
        fleio_password = request.session.get('user_password')

        # Login API Fleio
        loginapi = "https://portal.ideadc.com/backend/api/login"

        # header
        header = {
            'Authorization': 'Token 66a11f842436036e31dae3ef38ad31734ec6f351'}

        # User Login Payload
        payload = {"username": fleio_email, "password": fleio_password,
                   "remember_me": True, "sfa_params": None}

        # Calling Login API
        response = requests.post(loginapi, data=payload, headers=header)
        # Checking Status
        if response.status_code == 200:
            cookie = response.cookies.get_dict()
            # Setting Cookies in Client Side
            return JsonResponse({"response": cookie}, status=200)
        else:
            response = response.json().get("detail", None)
            if response:
                forgotpasswordAPI = "https://portal.ideadc.com/backend/api/reset-password-ideadc/"

                # User Payload For Forgto Password
                data = {"email": fleio_email, "new_password": fleio_password,
                        "confirm_password": fleio_password}

                # Update The User Password If Email Already Used in Fleio
                updatePassword = requests.post(
                    url=forgotpasswordAPI, data=data)
                if updatePassword.status_code == 200:
                    loginapi = "https://portal.ideadc.com/backend/api/login"
                    # header
                    header = {
                        'Authorization': 'Token 66a11f842436036e31dae3ef38ad31734ec6f351'}

                    # User Login Payload
                    payload = {"username": fleio_email, "password": fleio_password,
                               "remember_me": True, "sfa_params": None}

                    # Calling Login API
                    response = requests.post(
                        loginapi, data=payload, headers=header)
                    # Checking Status
                    if response.status_code == 200:
                        cookie = response.cookies.get_dict()
                        # Setting Cookies in Client Side
                        return JsonResponse({"response": cookie}, status=200)
                else:
                    return JsonResponse({"error": "User not found in fleio"}, status=401)
            else:
                return JsonResponse({"error": "User not found in fleio"}, status=401)

    return render(request, "base.html", {"URL": settings.URL})


# function to generate OTP View
def generateOTP():
    # Generate Randome OTP
    return random.SystemRandom().randint(100000, 999999)


# Send Otp Code View
@csrf_exempt
def send_otp_code(request):

    # In Session Get Mobileno and Email
    mobileno = request.session.get('mobileno')
    email = request.session.get('email')

    # Check User Verify Already
    try:
        user = User.objects.get(email=email)
    except:
        return redirect('login')

    # If User Is Authenticated And Is Verify Return to Home Page
    if user.is_active and request.user.is_authenticated:
        return redirect('home')

    if request.method == "POST":

        # If Request Method is Voice then Calling User
        if request.POST['source'] == 'voice':

            request.session['otp_sms'] = generateOTP()
            outline_code = request.session.get('otp_sms')
            request.session['source'] = "voice"

            # Calling User For OTP
            client = Client(
                settings.TWILIO['TWILIO_ACCOUNT_SID'], settings.TWILIO['TWILIO_AUTH_TOKEN'])
            call = client.calls.create(twiml=f"<Response><Say voice='alice'>Your one-time OTP is {outline_code}</Say><Pause length='1'/><Say>Your one-time OTP is {outline_code}</Say><Pause length='1'/><Say>Goodbye</Say></Response>",
                                       to=f"{mobileno}",
                                       from_=settings.TWILIO['TWILIO_NUMBER']
                                       )
            if call:
                # Sucess Message
                return JsonResponse({"success": 'we have intiated call for you', "userOTP": generateOTP()}, status=200)
            else:
                # Error Message
                return JsonResponse({"error": 'Internal server Error'}, status=500)

        # If Request Method is SMS then Send SMS User
        elif request.POST['source'] == 'sms':
            request.session['otp_sms'] = generateOTP()
            request.session['source'] = "sms"
            otpno = request.session.get('otp_sms')
            message = f"Your one-time OTP is {otpno}"
            client = Client(settings.TWILIO['TWILIO_ACCOUNT_SID'],
                            settings.TWILIO['TWILIO_AUTH_TOKEN'])

            # send OTP To User Throgh SMS
            try:
                response = client.messages.create(
                    body=message, from_=settings.TWILIO['TWILIO_NUMBER'], to=mobileno)
                if response:
                    return JsonResponse({"success": f'OTP has been  successfully send at {mobileno}', "userOTP": generateOTP()}, status=200)
                else:
                    return JsonResponse({"error": 'Internal server Error'}, status=500)
            except:
                return JsonResponse({"error": 'OTP not send'}, status=400)
        else:

            # If Request Method is Email then Send Emil User
            try:
                User.objects.get(email=request.POST['source'])
                request.session['otp_sms'] = generateOTP()
                emailOTP = request.session.get('otp_sms')
                useremail = request.POST["source"]
                request.session['source'] = "email"
                try:
                    sendEmail(useremail, emailOTP)
                    return JsonResponse({"success": f'OTP has been  successfully sent at {useremail}', "userOTP": generateOTP()}, status=200)
                except SMTPException as e:
                    return JsonResponse({"error": f'There was an error sending an email{e}'}, status=400)
            except:
                return JsonResponse({"error": str(email) + 'is not registered with us'}, status=400)
    return render(request, 'allauth/account/verifyaccount.html', {'mobileno': mobileno, 'emailuser': email, "URL": settings.URL})


# Function to Submit OTP And Verify View
@csrf_exempt
def verify_otp_code(request):
    # Get Session Values
    getsource = request.session.get('source')
    email = request.session.get('email')
    user_password = request.session.get('user_password')
    # Checking User Active and is_authenticated
    try:
        user = User.objects.get(email=email)
    except:
        pass

    # If User Is Authenticated Return to Home Page
    if request.user.is_authenticated and user.is_active:
        return redirect('home')

    if request.method == "POST":

        try:
            user = User.objects.get(email=request.session.get('email'))
            # Check OTP is not NONE
            if request.session.get('otp_sms') != None:
                if int(request.POST['otp']) == int(request.session.get('otp_sms')):

                    # Set User is Active
                    user.is_active = True

                    # User save
                    user.save()
                    request.session['otp_sms'] = None

                    # Checking User Is Authenticated
                    user = authenticate(request, username=email,
                                        password=user_password)
                    if user is not None:
                        # Auto User Login After OTP Successfully Verified
                        auth_login(request, user)
                        return JsonResponse({"success": 'Account Successfully Verified'}, status=202)
                else:
                    # Error Message Incorrect OTP
                    return JsonResponse({"error": 'The OTP entered is incorrect!'}, status=401)
            else:
                # Error Message If Not OTP
                return JsonResponse({"error": 'Your OTP is expired, please resend your OTP'}, status=429)
        except:
            # Error Message User not Found
            return JsonResponse({"error": "Your OTP is expired, please resend your OTP"}, status=409)
    return render(request, 'allauth/account/otp.html', {"getsource": getsource})


# Send Email verification- View
def sendEmail(email, emailOTP):
    subject = f'Account Verification'
    html_message = render_to_string(
        'allauth/account/email.html', {"emailOTP": emailOTP, "email": email})
    email_from = settings.EMAIL_FROM
    recipient_list = [email]
    send_mail(subject=subject, message=None, from_email=email_from,
              recipient_list=recipient_list, html_message=html_message)


# Resend OTP Viee
@csrf_exempt
def resendOTP(request):

    mobileno = request.session.get('mobileno')
    if request.method == "POST":

        # If Request Method is Voice then Calling User
        if request.POST["source"] == "email":
            try:
                request.session['otp_sms'] = generateOTP()
                emailOTP = request.session.get('otp_sms')
                email = request.session.get('email')
                sendEmail(email, emailOTP)
                return JsonResponse({"message": f'OTP has been successfully Send to {email}', "userOTP": generateOTP()}, status=200)
            except SMTPException as e:
                return JsonResponse({"message": f'There was an error sending an email{e}'}, status=401)

         # If Request Method is SMS then Send SMS User
        elif request.POST["source"] == "sms":
            request.session['otp_sms'] = generateOTP()
            request.session['source'] = "sms"
            mobileno = request.session.get('mobileno')
            otpno = request.session.get('otp_sms')
            message = f"Your one-time OTP is {otpno}"
            client = Client(settings.TWILIO['TWILIO_ACCOUNT_SID'],
                            settings.TWILIO['TWILIO_AUTH_TOKEN'])
            response = client.messages.create(
                body=message, from_=settings.TWILIO['TWILIO_NUMBER'], to=mobileno)
            if response:
                return JsonResponse({"message": f'OTP has been successfully sent to Mobile Number {mobileno}', "userOTP": generateOTP()}, status=200)
            else:
                return JsonResponse({"message": 'OTP has not been generated successfully'}, status=400)

         # If Request Method is Email then Send Emil User
        else:
            request.session['otp_sms'] = generateOTP()
            outline_code = request.session.get('otp_sms')
            request.session['source'] = "voice"
            client = Client(
                settings.TWILIO['TWILIO_ACCOUNT_SID'], settings.TWILIO['TWILIO_AUTH_TOKEN'])
            call = client.calls.create(twiml=f"<Response><Say voice='alice'>Your one-time password is {outline_code}</Say><Pause length='1'/><Say>Your one-time password is {outline_code}</Say><Pause length='1'/><Say>Goodbye</Say></Response>",
                                       to=f"{mobileno}",
                                       from_=settings.TWILIO['TWILIO_NUMBER']
                                       )
            if call:
                return JsonResponse({"message": 'we have intiated call for you', "userOTP": generateOTP()}, status=200)
            else:
                return JsonResponse({"message": 'Something has been wrong'}, status=500)

    return render(request, 'allauth/account/verifyaccount.html', {"URL": settings.URL})


# Change password View
@login_required
@csrf_exempt
def change_password(request):
    if request.method == 'POST':
        # Check Password Format
        pattern = r"^(?=.*[\d])(?=.*[A-Z])(?=.*[a-z])(?=.*[!#$@%&])[\w\d!#$@%&]{8,14}$"

        # Check Password1 and Password2 length,format
        if request.POST['new_password'] == request.POST['confirm_password'] and len(request.POST['new_password']) >= 8 and len(request.POST['confirm_password']) >= 8 and re.match(pattern, request.POST['new_password']):
            user = User.objects.get(email=request.user.email)

            # Check If Password Already Used User
            new_old_password_same = check_password(
                request.POST['new_password'], user.password)

            old_password_check = check_password(
                request.POST['old_password'], user.password)

            if new_old_password_same:
                return JsonResponse({"error": 'Old and new password must be different'}, status=400)

            if not old_password_check:
                return JsonResponse({"error": 'The old password you have entered is incorrect'}, status=400)

            # User Set New Password
            user.set_password(request.POST["new_password"])
            user.save()

            # Calling Forgot API Fleio
            forgotpasswordAPI = "https://portal.ideadc.com/backend/api/reset-password-ideadc/"
            data = {"email": user.email, "new_password": request.POST["new_password"],
                    "confirm_password": request.POST['confirm_password']}
            try:
                requests.post(forgotpasswordAPI, data=data)
            except:
                pass
            update_session_auth_hash(request, user)
            return JsonResponse({"success": 'Your password was successfully updated!'}, status=200)
        else:
            # Showing Error Password Related
            if not request.POST['new_password'] == request.POST['confirm_password']:
                return JsonResponse({"error": "Password Doesn't Match."}, status=401)
            elif len(request.POST['new_password']) < 8 and len(request.POST['confirm_password']) < 8:
                return JsonResponse({"error": 'Password should be at least 8 characters long.'}, status=400)
            else:
                return JsonResponse({"error": 'Password should have at least: one lower case letter, one upper case letter, one number and one special character !#$@%&.'}, status=400)

    return render(request, 'allauth/account/password_change.html', {"URL": settings.URL})


# Forgot Password Link Send View
@csrf_exempt
def forgot_password_send_mail(request):
    # If User Is Authenticated Return to Home Page
    if request.user.is_authenticated:
        return redirect('home')

    if request.method == 'POST':
        try:
            # Sending Forgot Password Link
            user = User.objects.get(email=request.POST['email'])
            if user:
                html_message = render_to_string('allauth/account/password_reset_email.html', {'email': user.email, 'domain': request.META['HTTP_HOST'], 'site_name': settings.URL, 'uid': urlsafe_base64_encode(
                    force_bytes(user.pk)), 'user': user, 'token': default_token_generator.make_token(user), 'protocol': request.scheme, })
                subject = "Reset Your Password"
                send_mail(subject=subject, message=html_message, from_email=settings.EMAIL_FROM,
                          recipient_list=[user.email], html_message=html_message, fail_silently=False)
                return JsonResponse({"success": 'Reset password link successfully sent to your email address'}, status=200)
            else:
                return JsonResponse({"error": str(request.POST['email'])+' is not registered with us'}, status=409)
        except:
            return JsonResponse({"error": str(request.POST['email'])+' is not registered with us'}, status=409)

    return render(request, "allauth/account/password_reset.html", {"URL": settings.URL})


# Forgot Password Confirm View
@csrf_exempt
def password_reset_confirmView(request, uidb64, token):

    # If User Is Authenticated Return to Home Page
    if request.user.is_authenticated:
        return redirect('home')

    if request.method == "POST":
        try:
            uid = urlsafe_base64_decode(uidb64)
            user = User._default_manager.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            # Password Pattern
            pattern = r"^(?=.*[\d])(?=.*[A-Z])(?=.*[a-z])(?=.*[!#$@%&])[\w\d!#$@%&]{8,14}$"
            # Checking Password Length And Pattern
            if request.POST['password1'] == request.POST['password2'] and len(request.POST['password1']) >= 8 and len(request.POST['password2']) >= 8 and re.match(pattern, request.POST['password1']):
                new_password = request.POST['password1']

                # Set New Password
                user.set_password(new_password)

                # User Save
                user.save()

                # Forgot Password API Fleio
                forgotpasswordAPI = "https://portal.ideadc.com/backend/api/reset-password-ideadc/"
                data = {"email": user.email, "new_password": new_password,
                        "confirm_password": request.POST['password2']}
                try:
                    requests.post(forgotpasswordAPI, data=data)
                except:
                    pass
                return JsonResponse({"success": 'Password reset successfully.'}, status=200)
            else:
                # Showing Error Password Related
                if not request.POST['password1'] == request.POST['password2']:
                    return JsonResponse({"error": "Password Doesn't Match."}, status=409)
                elif len(request.POST['password1']) < 8 and len(request.POST['password2']) < 8:
                    return JsonResponse({"error": 'Password should be at least 8 characters long.'}, status=400)
                else:
                    return JsonResponse({"error": "Password should have at least: one lower case letter, one upper case letter, one number and one special character !#$@%&."}, status=400)
        else:
            return JsonResponse({"error": 'Token expired or invalid. Try to reset the password again.'}, status=401)
    return render(request, 'allauth/account/password_reset_confirm.html', {"URL": settings.URL})


@csrf_exempt
def logout_user(request):
    if request.user.is_authenticated:
        logout(request)
        return JsonResponse({"success": "SuccessFully Logout"}, status=200)
    else:
        return redirect("login")



# function for Return Country Wise State
@csrf_exempt
def state_view(request):
    if request.method == 'POST':
        try:
            country = Country.objects.get(country=request.POST["countryName"])
            StateList = State.objects.filter(country=country)
            return JsonResponse({"StateList": serializers.serialize('json', StateList)}, status=200)
        except:
            return JsonResponse({"error": "Country data loss"}, status=400)

    return JsonResponse({"sucess": "StateList"}, status=200)

# User  errro page View


def error_404_view(request, exception):
    return render(request, 'error_404.html')


@login_required
@csrf_exempt
def user_deletion(request):
    return JsonResponse({"success": "SuccessFully Delete User"}, status=200)
