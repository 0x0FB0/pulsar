import os

# DJANGO SETTINGS HERE

DEBUG = False

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

AUTH_USER_MODEL = 'pulsar.PortalUser'

SECRET_KEY = os.environ['D_SECRET_KEY']

ALLOWED_HOSTS = ['127.0.0.1', 'localhost']

STATICFILES_DIRS = (
    os.path.join(BASE_DIR, 'static'),
)
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATIC_URL = '/static/'
LOGIN_REDIRECT_URL = '/pulsar/#/dashboard'

STATICFILES_DIRS = (
)

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': '/portal/logs/django.log',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}

STATICFILES_FINDERS = (
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
)


INSTALLED_APPS = [
    'pulsar.apps.PulsarConfig',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.admindocs',
    'django_celery_results',
    'django_celery_beat',
    'social_django',
    'rest_framework',
    'rest_framework.authtoken',
    'rest_social_auth',
    'django_filters',
]

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.TokenAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_FILTER_BACKENDS': ['django_filters.rest_framework.DjangoFilterBackend']
}

GRAPH_MODELS = {
  'all_applications': True,
  'group_models': True,
}

REGISTRATION_OPEN = False

AUTHENTICATION_BACKENDS = (
    'social_core.backends.google.GoogleOAuth2',
    'social_core.backends.github.GithubOAuth2',
    'social_core.backends.linkedin.LinkedinOAuth2',
    'django.contrib.auth.backends.ModelBackend',
)

# OAUTH SETTINGS HERE

SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = '[GOOGLE_OAUTH_KEY]'
SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = '[GOOGLE_OAUTH_SECRET]'
SOCIAL_AUTH_GITHUB_KEY = '[GITHUB_OAUTH_KEY]'
SOCIAL_AUTH_GITHUB_SECRET = '[GITHUB_OAUTH_SECRET]'
SOCIAL_AUTH_LINKEDIN_OAUTH2_KEY = '[LINKEDIN_OAUTH_KEY]'
SOCIAL_AUTH_LINKEDIN_OAUTH2_SECRET = '[LINKEDIN_OAUTH_SECRET]'

LOGIN_URL = '/accounts/login/'
LOGOUT_URL = '/accounts/logout/'
SOCIAL_AUTH_URL_NAMESPACE = 'social'
LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/'

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

SESSION_EXPIRE_SECONDS = 60 * 30
SESSION_EXPIRE_AFTER_LAST_ACTIVITY = True

ROOT_URLCONF = 'portal.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'portal.wsgi.application'


# DATABASE SETTINGS HERE
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'pulsar',
        'USER': os.environ['MYSQL_USER'],
        'PASSWORD': os.environ['MYSQL_PASSWORD'],
        'HOST': 'db',
        'PORT': '',
    }
}

# Password validations

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# LOCALE AND TIME ZONE SETTINGS
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True


#EMAIL_BACKEND SETTINGS
EMAIL_HOST_USER = 'open.pulsar@gmail.com'
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.acme.inc'
EMAIL_PORT = 587
EMAIL_HOST_USER = 'pulsar-notifications@acme.inc'
EMAIL_HOST_PASSWORD = '[MAILBOX_PASSWORD_HERE]'
EMAIL_USE_TLS = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/2.2/howto/static-files/


LOGIN_REDIRECT_URL = '/'
SESSION_ENGINE = 'django.contrib.sessions.backends.cached_db'
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True


CELERY_BROKER_USE_SSL = True
CELERY_BIN = '/usr/local/bin/celery'
CELERY_APP = 'pulsar'
CELERYD_CHDIR = '/opt/webdev/portal/'
CELERY_BROKER_URL = f'pyamqp://{os.environ["RABBITMQ_DEFAULT_USER"]}:{os.environ["RABBITMQ_DEFAULT_PASS"]}@queue:5671//'
CELERY_RESULT_BACKEND = 'amqp'
CELERY_ACCEPT_CONTENT = ['auth']
CELERY_RESULT_SERIALIZER = 'auth'
CELERY_TIMEZONE = 'Europe/London'
CELERY_TASK_SERIALIZER = 'auth'
CELERY_CACHE_BACKEND = 'django-cache'
CELERY_IGNORE_RESULT = False
CELERY_TRACK_STARTED = True