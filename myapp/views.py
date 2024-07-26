# views.py
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.utils.decorators import method_decorator
from django.contrib.auth.decorators import login_required
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.core.exceptions import ValidationError
from .authentication import CognitoBackend
import boto3
from django.conf import settings

class LoginView(APIView):
    def get(self, request):
        return render(request, 'login.html')

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        new_password = request.data.get('new_password', None)
        session = request.data.get('session', None)

        try:
            user = authenticate(request, username=username, password=password, new_password=new_password, session=session)
            if user is not None:
                login(request, user)
                
                # Fetch the AWS Cognito tokens
                client = boto3.client('cognito-idp', region_name=settings.COGNITO_REGION)
                response = client.initiate_auth(
                    ClientId=settings.COGNITO_APP_CLIENT_ID,
                    AuthFlow='USER_PASSWORD_AUTH',
                    AuthParameters={
                        'USERNAME': username,
                        'PASSWORD': password,
                    }
                )
                id_token = response['AuthenticationResult']['IdToken']
                access_token = response['AuthenticationResult']['AccessToken']
                refresh_token = response['AuthenticationResult']['RefreshToken']

                return Response({
                    'id_token': id_token,
                    'access_token': access_token,
                    'refresh_token': refresh_token,
                })
        except ValidationError as e:
            if e.code == 'new_password_required':
                return render(request, 'new_password_required.html', {'username': username, 'session': e.params['session']})
            return Response({'error': str(e)}, status=400)

        return Response({'error': 'Invalid credentials'}, status=400)

class SecureView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({'message': 'This is a secure endpoint accessible to authenticated users only.'})

@method_decorator(login_required, name='dispatch')
class UpdatePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return render(request, 'update_password.html')

    def post(self, request):
        username = request.user.username
        old_password = request.POST.get('old_password')
        new_password = request.POST.get('new_password')

        backend = CognitoBackend()
        success = backend.update_password(username, old_password, new_password)

        if success:
            return render(request, 'update_password.html', {'message': 'Password updated successfully'})
        else:
            return render(request, 'update_password.html', {'error': 'Failed to update password'})

class NewPasswordRequiredView(APIView):
    def post(self, request):
        username = request.data.get('username')
        new_password = request.data.get('new_password')
        session = request.data.get('session')

        backend = CognitoBackend()
        try:
            user = authenticate(request, username=username, new_password=new_password, session=session)
            if user is not None:
                print(user)
                return Response({
                    'status': 'successfully reset password'
                })
            return Response({'error': 'Invalid credentials'}, status=400)
        except ValidationError as e:
            return Response({'error': str(e)}, status=400)

class SamlCallbackView(APIView):
    def get(self, request):
        code = request.GET.get('code')

        if not code:
            return Response({'error': 'Missing authorization code'}, status=400)
        
        backend = CognitoBackend()
        try:
            user, access_token, refresh_token = backend.authenticate_saml(request, code)
            if user:
                login(request, user)
                return Response({
                    'access_token': access_token,
                    'refresh_token': refresh_token,
                })
            return Response({'error': 'Invalid SAML response'}, status=400)
        except Exception as e:
            return Response({'error': str(e)}, status=400)
