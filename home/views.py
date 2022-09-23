from django.shortcuts import render
from smtplib import SMTPException
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from user.models import SocialUserToken
import jwt
import requests
from .util import random_generator


# Create your views here.


# Home View
@csrf_exempt
def home(request):
    fleio_email = request.session.get('fleio_email', None)
    fleio_password = request.session.get('fleio_password', None)
    # User Fleioemail and FleioPassword Not
    if request.user.is_authenticated and not fleio_email and not fleio_password:
        try:
            # Get Token
            token = SocialUserToken.objects.get(user=request.user)
            # Decode Token
            decode_data = jwt.decode(
                jwt=token.token, key=settings.SECRET_KEY, algorithms=['HS256'])
            request.session['email'], request.session['user_password'] = decode_data['email'], decode_data['password']
        except SocialUserToken.DoesNotExist:
            # Create Randome Password for If Use login with Socail
            password = random_generator()
            jwt_token = jwt.encode(payload={
                                   "id": request.user.id, "email": request.user.email, "password": password}, key=settings.SECRET_KEY)
            token = SocialUserToken(
                token=jwt_token.decode('utf-8'), user=request.user)
            token.save()
            fleio_payload = {"email": request.user.email, "first_name": request.user.first_name if request.user.first_name else request.user.username,
                             "last_name": request.user.last_name if request.user.last_name else request.user.username, "password": password, "rememberMe": "true"}

            # Fleio Signup API For creating New User in Fleio
            try:
                fleio_signup = requests.post(
                    url="https://portal.ideadc.com/backend/api/signup-ideadc",
                    data=fleio_payload
                )

                if fleio_signup.status_code == 200:
                    request.session['email'], request.session['user_password'] = request.user.email, password
                if fleio_signup.status_code == 400:
                    response = fleio_signup.json().get("email", None)
                    if response:
                        forgotpasswordAPI = "https://portal.ideadc.com/backend/api/reset-password-ideadc/"

                        data = {"email": request.user.email, "new_password": password,
                                "confirm_password": password}

                        update_password = requests.post(
                            url=forgotpasswordAPI, data=data)
            except:
                pass
    return render(request, 'base.html', {'site_key': settings.GOOGLE_RECAPTCHA_SITE_KEY})


# Product Page View
def product(request):
    return render(request, 'home/product.html')


# Pricing Page View
def pricing(request):
    return render(request, 'home/pricing.html')


# Support Page View
def support(request):
    return render(request, 'home/support.html')


# Contact Page View
@csrf_exempt
def contact(request):
    if request.method == 'POST':
        captcha_response = request.POST['g_recaptcha_response']
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
        try:
            subject = "Website Inquiry"
            html_message = render_to_string(
                'home/contact_email.html', {"name": request.POST['name'], "email": request.POST['email'], "message": request.POST['message']})
            send_mail(subject=subject, message=html_message, from_email=settings.EMAIL_FROM,
                      recipient_list=["office@ideadc.com"], fail_silently=False, html_message=html_message)

            message = f'Thank you for getting in touch! We appreciate you contacting us about {request.POST["message"]}. One of our customer happiness members will be getting back to you shortly. While we do our best to answer your queries quickly, it may take about 10 hours to receive a response from us during peak hours.Thanks in advance for your patience.Have a great day!'
            email_from = settings.EMAIL_FROM
            recipient_list = [request.POST['email'], ]
            send_mail(subject, message, email_from, recipient_list)
            return JsonResponse({"success": 'Success! Your message has been sent to us.'}, status=200)
        except SMTPException as e:
            return JsonResponse({"error": f'There was an error sending an email{e}'}, status=400)
    return render(request, 'home/contact-us.html', {"URL": settings.URL})


# Video Page View
def video(request):
    return render(request, 'home/video.html')


# Privacy Policy Page View
def privacy_policy(request):
    return render(request, 'home/privacy-policy.html')
