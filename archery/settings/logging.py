#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# Author : alenx.hai <alenx.hai@gmail.com>
# @Time    : 2024/5/9 下午5:55
# -*- coding: utf-8 -*-
#
import os

from ..const import PROJECT_DIR, CONFIG

LOG_DIR = os.path.join(PROJECT_DIR, 'data', 'logs')
ARCHERY_LOG_FILE = os.path.join(LOG_DIR, 'archery.log')
DRF_EXCEPTION_LOG_FILE = os.path.join(LOG_DIR, 'drf_exception.log')
UNEXPECTED_EXCEPTION_LOG_FILE = os.path.join(LOG_DIR, 'unexpected_exception.log')
GUNICORN_LOG_FILE = os.path.join(LOG_DIR, 'gunicorn.log')
LOG_LEVEL = CONFIG.LOG_LEVEL

# LOG配置
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "[%(asctime)s][%(threadName)s:%(thread)d][task_id:%(name)s][%(filename)s:%(lineno)d][%(levelname)s]- %(message)s"
        },
    },
    "handlers": {
        "default": {
            "level": "DEBUG",
            "class": "logging.handlers.RotatingFileHandler",
            "filename": "logs/archery.log",
            "maxBytes": 1024 * 1024 * 100,  # 5 MB
            "backupCount": 5,
            "formatter": "verbose",
        },
        "django-q": {
            "level": "DEBUG",
            "class": "logging.handlers.RotatingFileHandler",
            "filename": "logs/qcluster.log",
            "maxBytes": 1024 * 1024 * 100,  # 5 MB
            "backupCount": 5,
            "formatter": "verbose",
        },
        "console": {
            "level": "DEBUG",
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "loggers": {
        "default": {  # default日志
            "handlers": ["console", "default"],
            "level": "WARNING",
        },
        "django-q": {  # django_q模块相关日志
            "handlers": ["console", "django-q"],
            "level": "WARNING",
            "propagate": False,
        },
        "django_auth_ldap": {  # django_auth_ldap模块相关日志
            "handlers": ["console", "default"],
            "level": "WARNING",
            "propagate": False,
        },
        "mozilla_django_oidc": {
            "handlers": ["console", "default"],
            "level": "WARNING",
            "propagate": False,
        },
        # 'django.db': {  # 打印SQL语句，方便开发
        #     'handlers': ['console', 'default'],
        #     'level': 'DEBUG',
        #     'propagate': False
        # },
        # 'django.request': {  # 打印请求错误堆栈信息，方便开发
        #     'handlers': ['console', 'default'],
        #     'level': 'DEBUG',
        #     'propagate': False
        # },
    },
}

if CONFIG.DEBUG_DEV:
    LOGGING['loggers']['django.db'] = {
       'handlers': ['console', 'file'],
       'level': 'DEBUG'
    }

if not os.path.isdir(LOG_DIR):
    os.makedirs(LOG_DIR, mode=0o755)