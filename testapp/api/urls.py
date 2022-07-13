from django.urls import path

from testapp.api.views import  UserLoginView, UserRegistrationView, EmailVerify, ResetPassword,GoogleLogin,Profile,SiteInfo,UserList

urlpatterns = [
    path('signup', UserRegistrationView.as_view()),
    path('googlesign', GoogleLogin.as_view()),
    path('login', UserLoginView.as_view()),
    path('emailverify', EmailVerify.as_view()),
    path('resetPassword', ResetPassword.as_view()),
    path('profile', Profile.as_view()),
    path('siteInfo', SiteInfo.as_view()),
    path('users', UserList.as_view()),
]