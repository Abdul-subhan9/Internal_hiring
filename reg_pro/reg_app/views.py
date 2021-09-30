from django.contrib.auth.backends import UserModel
from django.http.response import HttpResponseRedirect
from django.shortcuts import render
from .forms import SignUpForm
from django.contrib import messages
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import authenticate, login, logout
#from django.contrib.auth import get_fm_model
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.http import HttpResponse
from django.shortcuts import render
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
# Create your views here.


# Registration 
def sign_up(request):
    if request.method == "POST":
        fm = SignUpForm(request.POST)
        if fm.is_valid():
            messages.success(request, 'Account Created Successfully!!')
            user = fm.save()
            user.is_active = False
            user.save()
            current_site = get_current_site(request)
            mail_subject = 'Activate your account.'
            message = render_to_string('reg_app/acc_activate_email.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })
            to_email = fm.cleaned_data.get('email')
            email = EmailMessage(
                mail_subject, message, to=[to_email]
            )
            email.send()
            return HttpResponse('Please confirm your email address to complete the registration')
            
    else:
        fm = SignUpForm()
    return render(request, 'reg_app/sign_up.html', {'form':fm})


def activate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        fm = UserModel._default_manager.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        fm = None
    if fm is not None and default_token_generator.check_token(fm, token):
        fm.is_active = True
        fm.save()
        return HttpResponse("Thank you for your email confirmation. Now you can login your account.<a href='http://127.0.0.1:8000/login/'>")
        
    else:
        return HttpResponse('Activation link is invalid!')


# Login
def user_login(request):
    if not request.user.is_authenticated:
        if request.method == 'POST':
            fm = AuthenticationForm(request=request, data=request.POST)
            if fm.is_valid():
                uname = fm.cleaned_data['fmname']
                upass = fm.cleaned_data['password']
                fm = authenticate(fmname=uname, password=upass)
                if fm is not None:
                    login(request, fm)
                    messages.success(request, 'Logedin Successfully !!!!!')
                    return HttpResponseRedirect('/profile')
        else:
            fm = AuthenticationForm()
        return render(request, 'reg_app/fmlogin.html', {'form':fm})
    else:
        return HttpResponseRedirect('/profile/')


# Profile
def user_profile(request):
    if request.user.is_authenticated:
        return render(request, 'reg_app/profile.html',{'name':request.fm  })
    else:
        return HttpResponseRedirect('/login/')
    


# Logout
def user_logout(request):
    logout(request)
    return HttpResponseRedirect('/login')
