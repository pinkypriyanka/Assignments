#here i am creating the user credtinals with signup for hospitality for registering this username,phone_number,email and password.

CREATE MODELS:
from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=100, blank=True)
    phone_number = models.IntegerField(max_length=100, blank=True)
    email = models.EmailField(max_length=150)
	password=models.CharField(max_length=100,blank=True)
	def __str__(self):
        return self.user.username
	forms.py
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

class SignUpForm(UserCreationForm):
    first_name = forms.CharField(max_length=100, help_text='Last Name')
	phone_number= forms.IntegerField(max_length=100, help_text=' phone_number')
    email = forms.EmailField(max_length=150, help_text='Email')
	password=forms.CharField(max_length=150, help_text='password')
	password1=forms.CharField(max_length=150,help_text='password1')


    class Meta:
        model = User
        fields = ('username', 'username', 'phone_number', 'email','password','password1')

here is an logic for signup by views.py.
VIEWS.PY
def signup_view(request):
    if request.method  == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save()
            user.refresh_from_db()
            user.profile.first_name = form.cleaned_data.get('first_name')
            user.profile.phone_number= form.cleaned_data.get('phone_number')
            user.profile.email = form.cleaned_data.get('email')
			user.profile.password=form.cleaned_data.get('password')
			user.profile.password1-form.cleaned_data.get('password1')
            user.is_active = False
            user.save()
			user.is_active = False
            user.save()
            current_site = get_current_site(request)
            subject = 'Please Activate Your Account'
            message = render_to_string('activation_request.html', 
			{
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': account_activation_token.make_token(user),
            })
            user.email_user(subject, message)
            return redirect('activation_sent')
    else:
        form = SignUpForm()
    return render(request, 'signup.html', {'form': form})
activation_request.html
{% autoescape off %}
Hi {{ user.username }},

#Please click the following link to confirm your registration
http://{{ domain }}{% url 'activate' uidb64=uid token=token %}
{% endautoescape %}

		def activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.profile.signup_confirmation = True
        user.save()
        login(request, user)
        return redirect('home')
    else:
        return render(request, 'activation_invaild.html)
		
from django.contrib.auth import login, authenticate
from django.shortcuts import render, redirect, get_object_or_404, HttpResponseRedirect
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_text
from django.contrib.auth.models import User
from django.db import IntegrityError
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from .tokens import account_activation_token
from django.template.loader import render_to_string
from .forms import SignUpForm
from .tokens import account_activation_token

def home_view(request):
    return render(request, 'home.html')

def activation_sent_view(request):
    return render(request, 'activation_sent.html')
	def signup_view(request):
    if request.method  == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save()
            user.refresh_from_db()
            user.profile.first_name = form.cleaned_data.get('username')
            user.profile.phone_number = form.cleaned_data.get('phone_number')
            user.profile.email = form.cleaned_data.get('email')
			user.profile.password=form.cleaned_data.get('password')
            user.is_active = False
            user.save()
            current_site = get_current_site(request)
            subject = 'Please Activate Your Account'
            message = render_to_string('activation_request.html', {
                'user': user,
                'domain': current_site.domain,
				'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': account_activation_token.make_token(user),
            })
            user.email_user(subject, message)
            return redirect('activation_sent')
    else:
        form = SignUpForm()
    return render(request, 'signup.html', {'form': form})
	URLS.PY
	from django.contrib import admin
from django.urls import path
from django.conf.urls import url
from accounts.views import home_view, signup_view, activation_sent_view, activate

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', home_view, name="home"),
    path('signup/', signup_view, name="signup"),
    path('sent/', activation_sent_view, name="activation_sent"),
    path('activate/<slug:uidb64>/<slug:token>/', activate, name='activate'),
]

#UPDATE USER :
i want to create an API where user can update profile. In my case, a user can update the username and password. To change profile, an API link should be /api/change/usernameOfThatUser. When I use here not existed username in the link, I still get the userProfileChange API page, and the input boxes are not filled with previous data.
SERILAZER.PY
User = get_user_model()

class UserProfileChangeSerializer(ModelSerializer):
    username = CharField(required=False, allow_blank=True, initial="current username")
    class Meta:
        model = User
        fields = [
            'username',
            'password',
        ]
	def update(self, instance, validated_data):
	    instance.username = validated_data.get('username',instance.username)
		print('instance of username',instance.username)
		return instance 
VIEWS.PY
class UserProfileChangeAPIView(UpdateAPIView):
    serializer_class = UserProfileChangeSerializer
    lookup_field = 'username'
	
urls.py
url(r'^change/(?P<username>[\w-]+)$', UserProfileChangeAPIView.as_view(), name='changeProfile'),


#Now i writing code for DELETE USER:

class AuthInfoDeleteView(generics.DestroyAPIView):
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = AccountSerializer
    lookup_field = 'email'
    queryset = Account.objects.all()

    def get_object(self):
        try:
            instance = self.queryset.get(email=self.request.user)
            return instance
        except Account.DoesNotExist:
            raise Http404
EMAIL is stored in self.request.user but i write it in serilizer.py

from django.contrib.auth import update_session_auth_hash
from rest_framework import serializers

from .models import Account, AccountManager


class AccountSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = Account
        fields = ( 'name', 'email', 'phone_number', 'password', )

    def create(self, validated_data):
        return Account.objects.create_user(request_data=validated_data)
		
#Here iam creating the user login with the username and password creditinals.so,here is a rank/views.py

LOGIN:

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect

def user_login(request):
    context = RequestContext(request)
    if request.method == 'POST':
          username = request.POST['username']
          password = request.POST['password']
          user = authenticate(username=username, password=password)
          if user is not None:
              if user.is_active:
                  login(request, user)
                  return HttpResponseRedirect("rank/")
              else:
                  return HttpResponse("You account is disabled.")
          else:
              print  "invalid login details " + username + " " + password
              return render_to_response('login.html', {}, context)
    else:
        return render_to_response('login.html', {}, context
#Here is an user_login view, tests to see if a POST request has been made, if so, it extracts the username and password from the POST, and then tries to authenticate the user, using Django’s authenticate function the user model.

If a User is returned, and is active then, using Django’s login function, the login event is handled .Django also has a logout function which will securely log the user out .

Next Django’s HttpResponseRedirect function is called to redirect the user to the login in page.
 here is an login .html template will use username and password

<HTML>
LOGIN.HTML
<HTML>
<HEADER>
    <TITLE>Rank</TITLE>
</HEADER>
<BODY>
        <FORM id="login_form" method="post" action="/rank/login/">
        {% csrf_token %}
                Username:
                <input type="text" name="username" value="" id="username" size="50" />
            <br />
                Password:
                <input type="password" name="password" value="" id="password" size="50" />
                <br />
        <INPUT type="submit" name="submit" value="submit" />
        </FORM>
</BODY>
</HTML>
Adding an urls.py for the login.view
URLS.PY
rl(r'^login/$', views.user_login, name='login'),
Now, in index.html, add in register and login links:
<P>
<A href="/rango/register/">Register</A> |
<A href="/rango/login/">Login</A>
</P>

here is an authentication for request.user.is_authenticated
def some_view(request):
        if not request.user.is_authenticated():
                return HttpResponseRedirect('/rango/login/')
        else:
		     failed.
Here is an views.py iam using the @login_required decorator function. before your view is executed Django will check and see if an authenticated user is currently logged in.
			 
VIEWS.PY
from django.contrib.auth.decorators import login_required.



@login_required
def restricted(request):
    return HttpResponse('since you are an authenticated user you can view this restricted page')
	
rank/views.py by urls pattern.

url(r'restricted', views.restricted, name='restricted' )

when user is not logged in,using login_url in setting.py.

LOGIN_URL = '/rank/login'


 users can log out secure use Django’s logout function
@login_required
def user_logout(request):
    context = RequestContext(request)
    logout(request)
    return HttpResponseRedirect('/rank/')
	
Now add in the url mapping: url(r’^logout/$’, views.user_logout, name=’logout’),
	
<P>
        {% if user.is_authenticated %}
                Welcome {{ user.username }}  |
                <A href="/rango/restricted/">Restricted Page</A> |
                <A href="/rango/logout/">Logout</A>
        {% else %}
                <A href="/rango/register/">Register</A> |
                <A href="/rango/login/">Login</A>
        {% endif %}
</P>


				




   
