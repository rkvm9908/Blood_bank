import random
import threading
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import authenticate, login, logout

def register_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        BloodGroup = request.POST['blood_group']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        if password != confirm_password:
            messages.error(request, "Passwords do not match!")
            return redirect('register')

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists!")
            return redirect('register')

        user = User.objects.create_user(username=username, email=email, password=password,blood_group=BloodGroup)
        user.save()
        messages.success(request, "Registration successful! Please login.")
        return redirect('login')

    return render(request, 'accounts/register.html')


def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            # Redirect based on user type
            if user.is_staff:
                return redirect('admin_dashboard')
            else:
                return redirect('dashboard')
        else:
            messages.error(request, "Invalid credentials!")

    return render(request, 'accounts/login.html')


def logout_view(request):
    logout(request)
    return redirect('login')

import random
from django.core.mail import send_mail

# Store OTP temporarily (for simplicity, session)
def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            messages.error(request, "Email not registered")
            return redirect('forgot_password')

        otp = random.randint(100000, 999999)

        # store in session
        request.session['reset_email'] = email
        request.session['reset_otp'] = str(otp)

        subject = "Blood Bank Password Reset OTP"
        message = f"Your OTP is {otp}. Valid for 5 minutes."

        # 🔥 async email (NO BLOCKING)
        threading.Thread(
            target=send_otp_email,
            args=(subject, message, email)
        ).start()

        messages.success(request, "OTP sent to your email")
        return redirect('verify_otp')

    return render(request, 'accounts/forgot_password.html')


def verify_otp(request):
    if request.method == 'POST':
        entered_otp = request.POST.get('otp')
        session_otp = request.session.get('reset_otp')

        if entered_otp == session_otp:
            messages.success(request, "OTP verified. Set new password.")
            return redirect('reset_password')
        else:
            messages.error(request, "Invalid OTP")
            return redirect('verify_otp')

    return render(request, 'accounts/verify_otp.html')


def reset_password(request):
    if request.method == 'POST':
        password = request.POST.get('password')
        confirm = request.POST.get('confirm')

        if password != confirm:
            messages.error(request, "Passwords do not match")
            return redirect('reset_password')

        email = request.session.get('reset_email')
        user = User.objects.get(email=email)
        user.set_password(password)
        user.save()

        # cleanup session
        request.session.flush()

        messages.success(request, "Password reset successful. Login now.")
        return redirect('login')

    return render(request, 'accounts/reset_password.html')
