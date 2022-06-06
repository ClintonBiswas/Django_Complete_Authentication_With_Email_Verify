from django.shortcuts import render, redirect
from django.views.generic import View
from django.contrib import messages
from validate_email import validate_email
from django.contrib.auth.models import User
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes,force_str,DjangoUnicodeDecodeError
from django.core.mail import EmailMessage
from django.conf import settings
from .utils import generate_token

from django.contrib.auth.tokens import PasswordResetTokenGenerator

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
import threading
# Create your views here.
class EmailThread(threading.Thread):
    def __init__(self, email_message):
        self.email_message = email_message
        threading.Thread.__init__(self)
    def run(self):
        self.email_message.send() 

@login_required
def Home(request):
    return render(request, 'home.html')

class RegisterView(View):
    def get(self, request):
        return render(request, 'register.html')
    def post(self, request):
        context = {
            'data':request.POST,
            'has_error': False,
        
        }
        email = request.POST.get('email')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        username = request.POST.get('username')
        fullname = request.POST.get('fullname')

        if len(password) < 6:
            messages.add_message(request, messages.ERROR, 'Password Should be atleast 6 characters long',)
            context['has_error']=True
        if password!=password2:
            messages.add_message(request, messages.ERROR, 'Password Dont matched.',)
            context['has_error']=True

        if not validate_email(email):
            messages.add_message(request, messages.ERROR, 'Please provide a Valid email.',)
            context['has_error']=True

        try:
            if User.objects.get(email=email):
                messages.add_message(request, messages.ERROR, 'This Email Already Registered',)
                context['has_error']=True    
        except Exception as identifier:
            pass

        try:
            if User.objects.get(username=username):
                messages.add_message(request, messages.ERROR, 'This Username Already Registered',)
                context['has_error']=True    
        except Exception as identifier:
            pass
        
        if context['has_error']:
            return render(request, 'register.html', context)
        
        user = User.objects.create_user(username=username, email=email)
        user.set_password(password)
        user.first_name = fullname
        user.last_name = fullname
        user.is_active = False

        user.save()

        current_site = get_current_site(request)
        email_subject = "Active Your Email"
        message = render_to_string('activate.html',
            {
                'user':user,
                'domain':current_site.domain,
                'uid':urlsafe_base64_encode(force_bytes(user.pk)),
                'token':generate_token.make_token(user)
            }
        )
        email_message = EmailMessage(
        email_subject,
        message,
        settings.EMAIL_HOST_USER,
        [email]
        )
        EmailThread(email_message).start()
        messages.add_message(request, messages.SUCCESS, 'Registration is Succesfully. Please activate your email address.',)
        return redirect('register')

class AccountActivate(View):
    def get(self,request,uidb64,token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except Exception as identifier:
            user = None
        
        if user is not None and generate_token.check_token(user, token):
            user.is_active = True
            user.save()
            messages.add_message(request, messages.INFO, 'Account Created Succesfully.',)
            return redirect('login')
        return render(request, 'activate_failed.html', status=401)

class LoginView(View):
    def get(self,request):
        return render(request, 'login.html')
    
    def post(self, request):
        context = {
            'data': request.POST,
            'has_error': False,
        }
        username = request.POST.get('username')
        password = request.POST.get('password')

        if username == '':
            messages.add_message(request, messages.ERROR,'Username is reqired')
            context['has_error']=True
        if password == '':
            messages.add_message(request, messages.ERROR,'Password is reqired')
            context['has_error']=True
        
        user = authenticate(request, username=username, password=password)

        if not user and not context['has_error']:
            messages.add_message(request, messages.ERROR,'Login Details are wrong')
            context['has_error']=True
        
        if context['has_error']:
            return render(request, 'login.html', status=401, context=context)
        
        login(request, user)
        return redirect('home')

        return render(request, 'login.html')

class LogoutView(View):
    def get(self, request):
        logout(request)
        messages.add_message(request, messages.SUCCESS, 'Log out succesfully')
        return redirect('login')

class ResetPasswordView(View):
    def get(self, request):
        return render(request, 'reset-password.html')
    
    def post(self, request):
        email = request.POST.get('email')

        if email == '':
            messages.add_message(request, messages.ERROR, 'Email re required')
            return render(request, 'reset-password.html')
        if not validate_email(email):
            messages.add_message(request, messages.ERROR, 'Provide a valid email addresses')
            return render(request, 'reset-password.html')
        
        user = User.objects.filter(email=email)

        if user.exists():
            current_site = get_current_site(request)
            email_subject = "Reset Your Password"
            message = render_to_string('user-password.html',
                {
                    'domain':current_site.domain,
                    'uid':urlsafe_base64_encode(force_bytes(user[0].pk)),
                    'token':PasswordResetTokenGenerator().make_token(user[0])
                }
            )
            email_message = EmailMessage(
            email_subject,
            message,
            settings.EMAIL_HOST_USER,
            [email]
            )
            EmailThread(email_message).start()
        messages.add_message(request, messages.ERROR, 'We Have sent you an email with instructions on how to reset password.')
        return render(request, 'reset-password.html')

class ResetUserPasswordView(View):
    def get(self, request, uidb64, token):
        context = {
            'uidb64': uidb64,
            'token': token,
        }
        return render(request, 'set-new-password.html', context) 

    def post(self, request, uidb64, token):
        context = {
            'data':request.POST,
            'has_error': False,
            'uidb64': uidb64,
            'token': token,
        }
        password = request.POST.get('password')
        password2 = request.POST.get('password2')

        if password == '':
            messages.add_message(request, messages.ERROR, 'Password is required',)
            context['has_error']=True

        if len(password) < 6:
            messages.add_message(request, messages.ERROR, 'Password Should be atleast 6 characters long',)
            context['has_error']=True
        if password!=password2:
            messages.add_message(request, messages.ERROR, 'Password Dont matched.',)
            context['has_error']=True
        
        if context['has_error'] == True:
            return render(request, 'set-new-password.html',context) 
        
        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)
            user.set_password(password)
            user.save()
            messages.add_message(request, messages.SUCCESS, 'Password Reset Succesfully.',)
            return redirect('login')


        except DjangoUnicodeDecodeError as identifier:
            messages.add_message(request, messages.ERROR, 'Something went wrong',)
            return render(request, 'set-new-password.html',context) 

        return render(request, 'set-new-password.html',context) 


        