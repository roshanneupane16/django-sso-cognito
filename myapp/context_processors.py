from django.conf import settings

def from_settings(request):
    return {
        'COGNITO_DOMAIN': settings.COGNITO_DOMAIN,
        'COGNITO_APP_CLIENT_ID': settings.COGNITO_APP_CLIENT_ID,
        'COGNITO_REDIRECT_URL': settings.COGNITO_REDIRECT_URL,
        'COGNITO_SCOPE': settings.COGNITO_SCOPE,
    }
