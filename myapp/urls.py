# urls.py
from django.urls import path
from .views import LoginView, SecureView, UpdatePasswordView, NewPasswordRequiredView, SamlCallbackView

urlpatterns = [
    path('', LoginView.as_view(), name='home'),
    path('login/', LoginView.as_view(), name='login'),
    path('secure/', SecureView.as_view(), name='secure'),
    path('update-password/', UpdatePasswordView.as_view(), name='update_password'),
    path('new-password-required/', NewPasswordRequiredView.as_view(), name='new_password_required'),
    path('saml/callback/', SamlCallbackView.as_view(), name='saml_callback'),
]
