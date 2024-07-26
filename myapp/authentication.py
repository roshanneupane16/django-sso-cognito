# authentication.py
import logging
import boto3
import jwt
import requests
from django.conf import settings
from django.contrib.auth.models import User
from django.http import HttpResponseBadRequest
from django.contrib.auth import authenticate, login
from django.contrib.auth.backends import BaseBackend
from django.core.exceptions import ValidationError
from botocore.exceptions import ClientError
from jose import jwk, jwt
from jose.utils import base64url_decode


logger = logging.getLogger(__name__)

class CognitoBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None, new_password=None, session=None):
        client = boto3.client('cognito-idp', region_name=settings.COGNITO_REGION)
        try:
            if session and new_password:
                response = client.respond_to_auth_challenge(
                    ClientId=settings.COGNITO_APP_CLIENT_ID,
                    ChallengeName='NEW_PASSWORD_REQUIRED',
                    Session=session,
                    ChallengeResponses={
                        'USERNAME': username,
                        'NEW_PASSWORD': new_password,
                    }
                )
            else:
                response = client.initiate_auth(
                    ClientId=settings.COGNITO_APP_CLIENT_ID,
                    AuthFlow='USER_PASSWORD_AUTH',
                    AuthParameters={
                        'USERNAME': username,
                        'PASSWORD': password,
                    }
                )

            if 'ChallengeName' in response and response['ChallengeName'] == 'NEW_PASSWORD_REQUIRED':
                raise ValidationError(
                    "New password required.",
                    code='new_password_required',
                    params={'session': response['Session']}
                )

            id_token = response['AuthenticationResult']['IdToken']

            decoded_id_token = verify_token(id_token)
                        
            username = decoded_id_token.get('username') or decoded_id_token.get('email')
            if not username:
                logger.error("Username not found in ID token")
                raise ValueError("Username not found in ID token")

            user, created = User.objects.get_or_create(username=username)
            if created:
                user.set_unusable_password()
                user.save()
            return user

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NotAuthorizedException':
                return None
            elif error_code == 'UserNotConfirmedException':
                raise ValidationError("User is not confirmed.")
            elif error_code == 'PasswordResetRequiredException':
                raise ValidationError("Password reset required.")
            elif error_code == 'NewPasswordRequiredException':
                raise ValidationError(
                    "New password required.",
                    code='new_password_required',
                    params={'session': e.response['Session']}
                )

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    def update_password(self, username, old_password, new_password):
        client = boto3.client('cognito-idp', region_name=settings.COGNITO_REGION)
        try:
            # First authenticate the user with old password
            response = client.initiate_auth(
                ClientId=settings.COGNITO_APP_CLIENT_ID,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': username,
                    'PASSWORD': old_password,
                }
            )
            access_token = response['AuthenticationResult']['AccessToken']

            # Now update the password
            client.change_password(
                AccessToken=access_token,
                PreviousPassword=old_password,
                ProposedPassword=new_password
            )
            return True
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['NotAuthorizedException', 'InvalidParameterException']:
                return False
            else:
                raise e

    def authenticate_saml(self, request, code):
        if not code:
            logger.error("SAML authorization code is required")
            raise ValueError("SAML authorization code is required")

        logger.info(f"Received SAML authorization code: {code}")

        token_url = f'https://{settings.COGNITO_DOMAIN}/oauth2/token'
        client_id = settings.COGNITO_APP_CLIENT_ID
        client_secret = settings.COGNITO_APP_CLIENT_SECRET
        redirect_url = settings.COGNITO_REDIRECT_URL

        payload = {
            'grant_type': 'authorization_code',
            'client_id': client_id,
            'client_secret': client_secret,
            'redirect_uri': redirect_url,
            'code': code,
        }

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        response = requests.post(token_url, data=payload, headers=headers)

        if response.status_code != 200:
            logger.error(f"Error exchanging code for tokens: {response.text}")
            raise ValidationError("Error exchanging code for tokens")

        tokens = response.json()
        
        access_token = tokens.get('access_token')
        refresh_token = tokens.get('refresh_token')

        decoded_access_token = verify_token(access_token)

        username = decoded_access_token.get('username')
        if not username:
            logger.error("Username not found in access token")
            raise ValueError("Username not found in access token")

        user, created = User.objects.get_or_create(username=username)
        if created:
            user.set_unusable_password()
            user.save()

        user.backend = 'your_project.authentication.CognitoBackend'

        return user, access_token, refresh_token

# Verify JWT token
def get_jwks():
    jwks_url = f'https://cognito-idp.{settings.COGNITO_REGION}.amazonaws.com/{settings.COGNITO_USER_POOL_ID}/.well-known/jwks.json'
    response = requests.get(jwks_url)
    response.raise_for_status()
    return response.json()

def verify_token(token):
    try:
        jwks = get_jwks()
        headers = jwt.get_unverified_headers(token)
        kid = headers['kid']
        key_index = None
        for i in range(len(jwks['keys'])):
            if kid == jwks['keys'][i]['kid']:
                key_index = i
                break
        if key_index is None:
            logger.error("Public key not found in JWKS")
            raise ValueError("Public key not found in JWKS")

        public_key = jwk.construct(jwks['keys'][key_index])
        message, encoded_signature = str(token).rsplit('.', 1)
        decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))

        if not public_key.verify(message.encode("utf8"), decoded_signature):
            logger.error("Signature verification failed")
            raise ValueError("Signature verification failed")

        decoded_token = jwt.decode(token, public_key, algorithms=['RS256'], audience=settings.COGNITO_APP_CLIENT_ID)
        return decoded_token
    except Exception as e:
        logger.error(f"Error verifying token: {str(e)}")
        raise ValueError("Error verifying token")

# Ensure your SAML callback view extracts the code correctly
def saml_callback(request):
    code = request.GET.get('code')
    if not code:
        logger.error("Missing authorization code in SAML callback")
        return HttpResponseBadRequest("Missing authorization code")
    try:
        user, access_token, refresh_token = CognitoBackend().authenticate_saml(request, code)
        if user:
            login(request, user)
            # further processing...
            return HttpResponse("Successfully logged in")
        else:
            return HttpResponseBadRequest("Authentication failed")
    except ValueError as e:
        logger.error(f"Error in SAML authentication: {e}")
        return HttpResponseBadRequest(str(e))