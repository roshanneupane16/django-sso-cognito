# Django SSO Integration with Okta and AWS Cognito

This project demonstrates how to integrate Single Sign-On (SSO) using Okta as the Identity Provider (IdP) and AWS Cognito as the Service Provider (SP) in a Django application.

## Prerequisites

- Python 3.7+
- Django 3.0+
- AWS Account with Cognito setup
- Okta Account with a configured application

## Installation

1. **Clone the repository:**
    ```bash
    git clone https://github.com/roshanneupane16/django-sso-cognito.git
    cd django-sso-cognito
    ```

2. **Install the dependencies:**
    ```bash
    pip install -r requirements.txt
    python manage.py makemigrations
    python manage.py migrate
    ```

3. **Deploy cloudformation templage:**
    From AWS console, use cloudformation.yaml to deploy Cloudformation template. 

4. **Django Settings:**
    - Update the following configurations in your `myproject/settings.py`:
    ```
    COGNITO_USER_POOL_ID = 'xxxxxxxxx'
    COGNITO_APP_CLIENT_ID = 'xxxxxxxxxxxx'
    COGNITO_REGION = 'xxxxxxxxx'
    COGNITO_DOMAIN = 'xxxxxxxx.amazoncognito.com'
    ```

5. **IDP Setup:**
    - Create an application in Okta (or any other Identity Provider) and configure it to use AWS Cognito as the Service Provider (SP).
        - Use the ACSEndpoint and SPEntityID values provided by the CloudFormation output.
    - Get the Metadata document URL from Okta (or your chosen Identity Provider) and update the CloudFormation parameter with this URL.
        - Redeploy the CloudFormation stack to apply the changes.

## Usage

1. **Run the Django Development Server:**
    ```bash
    python manage.py runserver
    ```

2. **Access the Login Page:**
    - Navigate to `http://localhost:8000` to access the login page.
    - Use the form to login with a username and password or click the "Login with SAML" link to initiate SSO with Okta and AWS Cognito.

3. **SAML Callback:**
    - The SAML callback endpoint handles the response from Okta and exchanges the authorization code for tokens with AWS Cognito.
    - The user is authenticated and logged in based on the information in the tokens.

## Code Overview

### `authentication.py`

This file contains the `CognitoBackend` class which handles the authentication logic for both traditional username/password login and SAML-based SSO.

### `templates/login.html`

This template contains the login form and the SSO link.

### Documentation
Using SP-initated SAML sign-in
https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-saml-idp-authentication.html


