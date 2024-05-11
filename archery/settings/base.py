# -*- coding: UTF-8 -*-

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
import os
import re
from datetime import timedelta
import requests
import logging
from ..const import CONFIG

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = CONFIG.DEBUG

# LOG LEVEL
LOG_LEVEL = CONFIG.LOG_LEVEL

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = CONFIG.SECRET_KEY

DOMAINS = CONFIG.DOMAINS or "localhost"

ALLOWED_HOSTS = ["*"]
ALLOWED_DOMAINS = DOMAINS.split(",") if DOMAINS else ["localhost:8080"]
ALLOWED_DOMAINS = [host.strip() for host in ALLOWED_DOMAINS]
ALLOWED_DOMAINS = [
    host.replace("http://", "").replace("https://", "")
    for host in ALLOWED_DOMAINS
    if host
]
ALLOWED_DOMAINS = [host.split("/")[0] for host in ALLOWED_DOMAINS if host]
ALLOWED_DOMAINS = [re.sub(":80$|:443$", "", host) for host in ALLOWED_DOMAINS]

DEBUG_HOSTS = ("127.0.0.1", "localhost")
DEBUG_PORT = [
    "9123",
]
if DEBUG:
    DEBUG_PORT.extend(["4200", "9528"])
DEBUG_HOST_PORTS = [
    "{}:{}".format(host, port) for host in DEBUG_HOSTS for port in DEBUG_PORT
]
ALLOWED_DOMAINS.extend(DEBUG_HOST_PORTS)

print(
    "ALLOWED_HOSTS: ",
)
for host in ALLOWED_DOMAINS:
    print("  - " + host.lstrip("."))

# https://docs.djangoproject.com/en/4.0/ref/settings/#csrf-trusted-origins
# CSRF_TRUSTED_ORIGINS=subdomain.example.com,subdomain.example2.com subdomain.example.com
CSRF_TRUSTED_ORIGINS = []
for host_port in ALLOWED_DOMAINS:
    origin = host_port.strip(".")
    if origin.startswith("http"):
        CSRF_TRUSTED_ORIGINS.append(origin)
        continue
    is_local_origin = origin.split(":")[0] in DEBUG_HOSTS
    for schema in ["https", "http"]:
        if is_local_origin and schema == "https":
            continue
        CSRF_TRUSTED_ORIGINS.append("{}://*.{}".format(schema, origin))

CORS_ALLOWED_ORIGINS = [o.replace("*.", "") for o in CSRF_TRUSTED_ORIGINS]

# 解决nginx部署跳转404
USE_X_FORWARDED_HOST = True

# 请求限制
DATA_UPLOAD_MAX_MEMORY_SIZE = 15728640

AVAILABLE_ENGINES = {
    "mysql": {"path": "sql.engines.mysql:MysqlEngine"},
    "cassandra": {"path": "sql.engines.cassandra:CassandraEngine"},
    "clickhouse": {"path": "sql.engines.clickhouse:ClickHouseEngine"},
    "goinception": {"path": "sql.engines.goinception:GoInceptionEngine"},
    "mssql": {"path": "sql.engines.mssql:MssqlEngine"},
    "redis": {"path": "sql.engines.redis:RedisEngine"},
    "pgsql": {"path": "sql.engines.pgsql:PgSQLEngine"},
    "oracle": {"path": "sql.engines.oracle:OracleEngine"},
    "mongo": {"path": "sql.engines.mongo:MongoEngine"},
    "phoenix": {"path": "sql.engines.phoenix:PhoenixEngine"},
    "odps": {"path": "sql.engines.odps:ODPSEngine"},
    "doris": {"path": "sql.engines.doris:DorisEngine"},
}

ENABLED_NOTIFIERS = [
    "sql.notify:DingdingWebhookNotifier",
    "sql.notify:DingdingPersonNotifier",
    "sql.notify:FeishuWebhookNotifier",
    "sql.notify:FeishuPersonNotifier",
    "sql.notify:QywxWebhookNotifier",
    "sql.notify:QywxToUserNotifier",
    "sql.notify:MailNotifier",
    "sql.notify:GenericWebhookNotifier",
]

ENABLED_ENGINES = [
    "mysql",
    "clickhouse",
    "goinception",
    "mssql",
    "redis",
    "pgsql",
    "oracle",
    "mongo",
    "phoenix",
    "odps",
    "cassandra",
    "doris",
]

CURRENT_AUDITOR = "sql.utils.workflow_audit:AuditV2"

# Application definition
INSTALLED_APPS = (
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django_q",
    "sql",
    "sql_api",
    "common",
    "rest_framework",
    "django_filters",
    "drf_spectacular",
)

MIDDLEWARE = (
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.gzip.GZipMiddleware",
    "common.middleware.check_login_middleware.CheckLoginMiddleware",
    "common.middleware.exception_logging_middleware.ExceptionLoggingMiddleware",
)

ROOT_URLCONF = "archery.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [os.path.join(BASE_DIR, "common/templates")],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "common.utils.global_info.global_info",
            ],
        },
    },
]

WSGI_APPLICATION = "archery.wsgi.application"

# Internationalization
LANGUAGE_CODE = "zh-hans"

TIME_ZONE = "Asia/Shanghai"

USE_I18N = True

USE_TZ = False

# 时间格式化
USE_L10N = False
DATETIME_FORMAT = "Y-m-d H:i:s"
DATE_FORMAT = "Y-m-d"

# Static files (CSS, JavaScript, Images)
STATIC_URL = "/static/"
STATIC_ROOT = os.path.join(BASE_DIR, "static")
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, "common/static"),
]
STATICFILES_STORAGE = "common.storage.ForgivingManifestStaticFilesStorage"

# 扩展django admin里users字段用到，指定了sql/models.py里的class users
AUTH_USER_MODEL = "sql.Users"

# 密码校验
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {
            "min_length": 9,
        },
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

SESSION_COOKIE_AGE = CONFIG.SESSION_COOKIE_AGE
SESSION_SAVE_EVERY_REQUEST = CONFIG.SESSION_SAVE_EVERY_REQUEST
SESSION_EXPIRE_AT_BROWSER_CLOSE = CONFIG.SESSION_EXPIRE_AT_BROWSER_CLOSE

# 该项目本身的mysql数据库地址
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": CONFIG.DB_NAME,
        "HOST": CONFIG.DB_HOST,
        "PORT": CONFIG.DB_PORT,
        "USER": CONFIG.DB_USER,
        "PASSWORD": CONFIG.DB_PASSWORD,
        "ATOMIC_REQUESTS": True,
        "DEFAULT_CHARSET": "utf8mb4",
        "CONN_MAX_AGE": 50,
        "OPTIONS": {
            "init_command": "SET sql_mode='STRICT_TRANS_TABLES'",
            "charset": "utf8mb4",
        },
        "TEST": {
            "NAME": "test_archery",
            "CHARSET": "utf8mb4",
        },
    }
}

# 缓存配置
CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": f"redis://{CONFIG.REDIS_HOST}:{CONFIG.REDIS_PORT}/0",
    }
}

# Django-Q
Q_CLUSTER = {
    "name": "archery",
    "workers": CONFIG.Q_CLUSTER_WORKERS,
    "recycle": 500,
    "timeout": CONFIG.Q_CLUSTER_TIMEOUT,
    "compress": True,
    "cpu_affinity": 1,
    "save_limit": 0,
    "queue_limit": 50,
    "label": "Django Q",
    "django_redis": "default",
    "sync": CONFIG.Q_CLUISTER_SYNC,
}

# https://docs.djangoproject.com/en/3.2/ref/settings/#std-setting-DEFAULT_AUTO_FIELD
DEFAULT_AUTO_FIELD = "django.db.models.AutoField"

# API Framework
REST_FRAMEWORK = {
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_RENDERER_CLASSES": ("rest_framework.renderers.JSONRenderer",),
    # 鉴权
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
        "rest_framework.authentication.SessionAuthentication",
    ),
    # 权限
    "DEFAULT_PERMISSION_CLASSES": ("sql_api.permissions.IsInUserWhitelist",),
    # 限速（anon：未认证用户  user：认证用户）
    "DEFAULT_THROTTLE_CLASSES": (
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ),
    "DEFAULT_THROTTLE_RATES": {"anon": "120/min", "user": "600/min"},
    # 过滤
    "DEFAULT_FILTER_BACKENDS": ("django_filters.rest_framework.DjangoFilterBackend",),
    # 分页
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 5,
}

# Swagger UI
SPECTACULAR_SETTINGS = {
    "TITLE": "Archery API",
    "DESCRIPTION": "OpenAPI 3.0",
    "VERSION": "1.0.0",
}

# API Authentication
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(hours=4),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=3),
    "ALGORITHM": "HS256",
    "SIGNING_KEY": SECRET_KEY,
    "AUTH_HEADER_TYPES": ("Bearer",),
}

# OIDC
ENABLE_OIDC = CONFIG.ENABLE_OIDC
if ENABLE_OIDC:
    INSTALLED_APPS += ("mozilla_django_oidc",)
    AUTHENTICATION_BACKENDS = (
        "common.authenticate.oidc_auth.OIDCAuthenticationBackend",
        "django.contrib.auth.backends.ModelBackend",
    )

    # 例如 https://keycloak.example.com/realms/<your realm>/.well-known/openid-configuration
    OIDC_RP_WELLKNOWN_URL = CONFIG.OIDC_RP_WELLKNOWN_URL
    OIDC_RP_CLIENT_ID = CONFIG.OIDC_RP_CLIENT_ID
    OIDC_RP_CLIENT_SECRET = CONFIG.OIDC_RP_CLIENT_SECRET

    response = requests.get(OIDC_RP_WELLKNOWN_URL)
    response.raise_for_status()
    config = response.json()
    OIDC_OP_AUTHORIZATION_ENDPOINT = config["authorization_endpoint"]
    OIDC_OP_TOKEN_ENDPOINT = config["token_endpoint"]
    OIDC_OP_USER_ENDPOINT = config["userinfo_endpoint"]
    OIDC_OP_JWKS_ENDPOINT = config["jwks_uri"]
    OIDC_OP_LOGOUT_ENDPOINT = config["end_session_endpoint"]

    OIDC_RP_SCOPES = CONFIG.OIDC_RP_SCOPES
    OIDC_RP_SIGN_ALGO = CONFIG.OIDC_RP_SIGN_ALGO

    LOGIN_REDIRECT_URL = "/"

# Dingding
ENABLE_DINGDING = CONFIG.ENABLE_DINGDING
if ENABLE_DINGDING:
    INSTALLED_APPS += ("django_auth_dingding",)
    AUTHENTICATION_BACKENDS = (
        "common.authenticate.dingding_auth.DingdingAuthenticationBackend",
        "django.contrib.auth.backends.ModelBackend",
    )
    AUTH_DINGDING_AUTHENTICATION_CALLBACK_URL = (
        CONFIG.AUTH_DINGDING_AUTHENTICATION_CALLBACK_URL
    )
    AUTH_DINGDING_APP_KEY = CONFIG.AUTH_DINGDING_APP_KEY
    AUTH_DINGDING_APP_SECRET = CONFIG.AUTH_DINGDING_APP_SECRET

# LDAP
ENABLE_LDAP = CONFIG.ENABLE_LDAP
if ENABLE_LDAP:
    import ldap
    from django_auth_ldap.config import LDAPSearch

    AUTHENTICATION_BACKENDS = (
        "django_auth_ldap.backend.LDAPBackend",  # 配置为先使用LDAP认证，如通过认证则不再使用后面的认证方式
        "django.contrib.auth.backends.ModelBackend",  # django系统中手动创建的用户也可使用，优先级靠后。注意这2行的顺序
    )

    AUTH_LDAP_SERVER_URI = CONFIG.AUTH_LDAP_SERVER_URI
    AUTH_LDAP_USER_DN_TEMPLATE = CONFIG.AUTH_LDAP_USER_DN_TEMPLATE
    if not AUTH_LDAP_USER_DN_TEMPLATE:
        del AUTH_LDAP_USER_DN_TEMPLATE
        AUTH_LDAP_BIND_DN = CONFIG.AUTH_LDAP_BIND_DN
        AUTH_LDAP_BIND_PASSWORD = CONFIG.AUTH_LDAP_BIND_PASSWORD
        AUTH_LDAP_USER_SEARCH_BASE = CONFIG.AUTH_LDAP_USER_SEARCH_BASE
        AUTH_LDAP_USER_SEARCH_FILTER = CONFIG.AUTH_LDAP_USER_SEARCH_FILTER
        AUTH_LDAP_USER_SEARCH = LDAPSearch(
            AUTH_LDAP_USER_SEARCH_BASE, ldap.SCOPE_SUBTREE, AUTH_LDAP_USER_SEARCH_FILTER
        )
    AUTH_LDAP_ALWAYS_UPDATE_USER = (
        CONFIG.AUTH_LDAP_ALWAYS_UPDATE_USER
    )  # 每次登录从ldap同步用户信息
    AUTH_LDAP_USER_ATTR_MAP = {
        "username": "cn",
        "display": "displayname",
        "email": "mail",
    }

# CAS认证
ENABLE_CAS = CONFIG.ENABLE_CAS
if ENABLE_CAS:
    INSTALLED_APPS += ("django_cas_ng",)
    MIDDLEWARE += ("django_cas_ng.middleware.CASMiddleware",)
    AUTHENTICATION_BACKENDS = (
        "django.contrib.auth.backends.ModelBackend",
        "django_cas_ng.backends.CASBackend",
    )

    # CAS 的地址
    CAS_SERVER_URL = CONFIG.CAS_SERVER_URL
    # CAS 版本
    CAS_VERSION = CONFIG.CAS_VERSION
    # 存入所有 CAS 服务端返回的 User 数据。
    CAS_APPLY_ATTRIBUTES_TO_USER = True
    # 关闭浏览器退出登录
    SESSION_EXPIRE_AT_BROWSER_CLOSE = True
    #  忽略  SSL  证书校验
    CAS_VERIFY_SSL_CERTIFICATE = CONFIG.CAS_VERIFY_SSL_CERTIFICATE
    #  忽略来源验证
    CAS_IGNORE_REFERER = True
    # https请求问题
    CAS_FORCE_SSL_SERVICE_URL = CONFIG.CAS_FORCE_SSL_SERVICE_URL
    CAS_RETRY_TIMEOUT = 1
    CAS_RETRY_LOGIN = True
    CAS_EXTRA_LOGIN_PARAMS = {"renew": True}
    CAS_LOGOUT_COMPLETELY = True

SUPPORTED_AUTHENTICATION = [
    ("LDAP", ENABLE_LDAP),
    ("DINGDING", ENABLE_DINGDING),
    ("OIDC", ENABLE_OIDC),
    ("CAS", ENABLE_CAS),
]
# 计算当前启用的外部认证方式数量
ENABLE_AUTHENTICATION_COUNT = len(
    [enabled for (name, enabled) in SUPPORTED_AUTHENTICATION if enabled]
)
if ENABLE_AUTHENTICATION_COUNT > 0:
    if ENABLE_AUTHENTICATION_COUNT > 1:
        logger.warning(
            "系统外部认证目前支持LDAP、DINGDING、OIDC、CAS四种，认证方式只能启用其中一种，如果启用多个，实际生效的只有一个，优先级LDAP > DINGDING > OIDC > CAS"
        )
    authentication = ""  # 默认为空
    for name, enabled in SUPPORTED_AUTHENTICATION:
        if enabled:
            authentication = name
            break
    logger.info("当前生效的外部认证方式：" + authentication)
    logger.info("认证后端：" + AUTHENTICATION_BACKENDS.__str__())

MEDIA_ROOT = os.path.join(BASE_DIR, "media")
if not os.path.exists(MEDIA_ROOT):
    os.mkdir(MEDIA_ROOT)

PKEY_ROOT = os.path.join(MEDIA_ROOT, "keys")
if not os.path.exists(PKEY_ROOT):
    os.mkdir(PKEY_ROOT)
