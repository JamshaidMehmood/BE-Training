"""
Authentication views for user login, signup, password reset functionality.
"""
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse

def login_view(request):
    """View to handle login form"""
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        remember = request.POST.get('remember')

        if username and password:
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                if not remember:
                    request.session.set_expiry(0)
                messages.success(request, f'Welcome back, {user.first_name or user.username}!')
                return redirect('home')
            messages.error(request, 'Invalid username or password. Please try again.')
            return render(request, 'authentication/login.html')
        messages.error(request, 'Please fill in all required fields.')

    return render(request, 'authentication/login.html')

def signup_view(request):
    """View to handle signup form"""
    if request.method == 'POST':
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        username = request.POST.get('username')
        email = request.POST.get('email')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        terms = request.POST.get('terms')

        if not all([first_name, last_name, username, email, password1, password2]):
            messages.error(request, 'Please fill in all required fields.')
            return render(request, 'authentication/signup.html')
        if password1 != password2:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'authentication/signup.html')
        if not terms:
            messages.error(request, 'You must agree to the terms and conditions.')
            return render(request, 'authentication/signup.html')

        try:
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password1,
                first_name=first_name,
                last_name=last_name
            )
            messages.success(request, f'Account created successfully! Welcome, {first_name}!')
            login(request, user)
            return redirect('home')
        except Exception as e:
            if 'username' in str(e).lower():
                messages.error(request, 'Username already exists. Please choose a different one.')
            elif 'email' in str(e).lower():
                messages.error(request, 'Email already exists. Please use a different email.')
            else:
                messages.error(request, 'An error occurred. Please try again.')

    return render(request, 'authentication/signup.html')

def logout_view(request):
    """View to handle logout"""
    logout(request)
    messages.info(request, 'You have been logged out successfully.')
    return redirect('login')

def forgot_password_view(request):
    """View to handle forgot password form"""
    if request.method == 'POST':
        email = request.POST.get('email')

        if email:
            try:
                user = User.objects.get(email=email)

                token = default_token_generator.make_token(user)
                uid = urlsafe_base64_encode(force_bytes(user.pk))

                reset_url = request.build_absolute_uri(
                    reverse('reset_password', kwargs={'uidb64': uid, 'token': token})
                )

                subject = 'Password Reset Request'
                message = f"""
                Hello {user.first_name or user.username},

                You requested a password reset for your account. Click the link below to reset your password:

                {reset_url}

                If you didn't request this, please ignore this email.

                Best regards,
                Django Auth Team
                """

                try:
                    send_mail(
                        subject,
                        message,
                        settings.DEFAULT_FROM_EMAIL,
                        [user.email],
                        fail_silently=False,
                    )
                    messages.success(request, 'Password reset link has been sent to your email address.')
                except Exception as e:
                    messages.error(request, 'Failed to send email. Please try again later.')
                    print(f"Email error: {e}")

            except User.DoesNotExist:
                messages.success(request, 'If an account with that email exists, a password reset link has been sent.')
            return render(request, 'authentication/forgot_password.html')
        messages.error(request, 'Please enter your email address.')

    return render(request, 'authentication/forgot_password.html')

def reset_password_view(request, uidb64, token):
    """View to handle password reset form"""
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            new_password1 = request.POST.get('new_password1')
            new_password2 = request.POST.get('new_password2')

            if new_password1 and new_password2:
                if new_password1 == new_password2:
                    if len(new_password1) >= 8:
                        user.set_password(new_password1)
                        user.save()
                        messages.success(request, 'Your password has been reset successfully. You can now log in with your new password.')
                        return redirect('login')
                    messages.error(request, 'Password must be at least 8 characters long.')
                    return render(request, 'authentication/reset_password.html', {'validlink': True})
                messages.error(request, 'Passwords do not match.')
                return render(request, 'authentication/reset_password.html', {'validlink': True})
            messages.error(request, 'Please fill in all password fields.')

        return render(request, 'authentication/reset_password.html', {'validlink': True})
    return render(request, 'authentication/reset_password.html', {'validlink': False})

@login_required
def home_view(request):
    """View to render the home page for authenticated users"""
    context = {
        'user': request.user,
        'is_authenticated': request.user.is_authenticated,
    }
    return render(request, 'authentication/home.html', context)
