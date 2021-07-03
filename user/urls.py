from django.urls import path
from . import views

app_name = "user"


urlpatterns = [

    path("", views.homepage, name="homepage"),
    path("register/", views.register_request, name="register"),
    path("login/", views.login_request, name="login"),
    path("logout/", views.logout_request, name="logout"),
    path("password_reset/", views.password_reset_request, name="password_reset"),
    path('activate/<uidb64>/<token>/',views.activate, name='activate'),

]