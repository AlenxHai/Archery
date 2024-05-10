#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# Author : alenx.hai <alenx.hai@gmail.com>
# @Time    : 2024/5/9 下午5:56

"""
配置分类：
1. Django使用的配置文件，写到settings中
2. 程序需要, 用户不需要更改的写到settings中
3. 程序需要, 用户需要更改的写到本config中
"""
import base64
import copy
import errno
import json
import logging
import os
import re
import sys
import types
from importlib import import_module
from urllib.parse import urljoin, urlparse, quote

import yaml
from django.urls import reverse_lazy
from django.utils.translation import gettext_lazy as _


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECT_DIR = os.path.dirname(BASE_DIR)

logger = logging.getLogger('archery.conf')


def import_string(dotted_path):
    try:
        module_path, class_name = dotted_path.rsplit('.', 1)
    except ValueError as err:
        raise ImportError("%s doesn't look like a module path" % dotted_path) from err

    module = import_module(module_path)

    try:
        return getattr(module, class_name)
    except AttributeError as err:
        raise ImportError(
            'Module "%s" does not define a "%s" attribute/class' %
            (module_path, class_name)) from err


def is_absolute_uri(uri):
    """ 判断一个uri是否是绝对地址 """
    if not isinstance(uri, str):
        return False

    result = re.match(r'^http[s]?://.*', uri)
    if result is None:
        return False

    return True


def build_absolute_uri(base, uri):
    """ 构建绝对uri地址 """
    if uri is None:
        return base

    if isinstance(uri, int):
        uri = str(uri)

    if not isinstance(uri, str):
        return base

    if is_absolute_uri(uri):
        return uri

    parsed_base = urlparse(base)
    url = "{}://{}".format(parsed_base.scheme, parsed_base.netloc)
    path = '{}/{}/'.format(parsed_base.path.strip('/'), uri.strip('/'))
    return urljoin(url, path)


class DoesNotExist(Exception):
    pass


class ConfigCrypto:
    secret_keys = [
        'SECRET_KEY', 'DB_PASSWORD', 'REDIS_PASSWORD',
    ]

    def __init__(self, key):
        self.safe_key = self.process_key(key)

    @staticmethod
    def process_key(secret_encrypt_key):
        key = secret_encrypt_key.encode()
        if len(key) >= 16:
            key = key[:16]
        else:
            key += b'\0' * (16 - len(key))
        return key

    def encrypt(self, data):
        data = bytes(data, encoding='utf8')
        return base64.b64encode(data).decode('utf8')

    def decrypt(self, data):
        data = base64.urlsafe_b64decode(bytes(data, encoding='utf8'))
        return data.decode('utf8')

    def decrypt_if_need(self, value, item):
        if item not in self.secret_keys:
            return value

        try:
            plaintext = self.decrypt(value)
            if plaintext:
                value = plaintext
        except Exception as e:
            pass
        return value

    @classmethod
    def get_secret_encryptor(cls):
        # 使用 SM4 加密配置文件敏感信息
        # https://the-x.cn/cryptography/Sm4.aspx
        secret_encrypt_key = os.environ.get('SECRET_ENCRYPT_KEY', '')
        if not secret_encrypt_key:
            return None
        print('Info: try using SM4 to decrypt config secret value')
        return cls(secret_encrypt_key)


class Config(dict):
    defaults = {
        # Django Config, Must set before start
        'SECRET_KEY': '',
        'DEBUG': False,
        'DEBUG_DEV': False,
        'LOG_LEVEL': 'DEBUG',
        'LOG_DIR': os.path.join(PROJECT_DIR, 'data', 'logs'),
        'DB_NAME': 'archery',
        'DB_HOST': '127.0.0.1',
        'DB_PORT': 3306,
        'DB_USER': 'root',
        'DB_PASSWORD': '',
        'REDIS_HOST': '127.0.0.1',
        'REDIS_PORT': 6379,
        'REDIS_PASSWORD': '',

        'SESSION_COOKIE_DOMAIN': None,
        'CSRF_COOKIE_DOMAIN': None,
        'SESSION_COOKIE_NAME_PREFIX': None,
        'SESSION_COOKIE_AGE': 300 * 12,
        'SESSION_EXPIRE_AT_BROWSER_CLOSE': True,
        'LOGIN_URL': reverse_lazy('authentication:login'),

        # Vault
        'VAULT_ENABLED': False,
        'VAULT_HCP_HOST': '',
        'VAULT_HCP_TOKEN': '',
        'VAULT_HCP_MOUNT_POINT': 'archery',

        # 启动前
        'HTTP_BIND_HOST': '0.0.0.0',
        'HTTP_LISTEN_PORT': 9123,

        # 钉钉
        'AUTH_DINGTALK': False,
        'DINGTALK_AGENTID': '',
        'DINGTALK_APPKEY': '',
        'DINGTALK_APPSECRET': '',

        # Cas 认证
        'AUTH_CAS': False,
        'CAS_SERVER_URL': "https://example.com/cas/",
        'CAS_ROOT_PROXIED_AS': 'https://example.com',
        'CAS_LOGOUT_COMPLETELY': True,
        'CAS_VERSION': 3,
        'CAS_USERNAME_ATTRIBUTE': 'cas:user',
        'CAS_APPLY_ATTRIBUTES_TO_USER': False,
        'CAS_RENAME_ATTRIBUTES': {'cas:user': 'username'},
        'CAS_CREATE_USER': True,

        'TIME_ZONE': 'Asia/Shanghai',
        'FORCE_SCRIPT_NAME': '',
        'SESSION_COOKIE_SECURE': False,
        'DOMAINS': '',
        'CSRF_COOKIE_SECURE': False,
        'REFERER_CHECK_ENABLED': False,
        'SESSION_ENGINE': 'cache',
        'SESSION_SAVE_EVERY_REQUEST': True,
        'SERVER_REPLAY_STORAGE': {},
        'SECURITY_DATA_CRYPTO_ALGO': None,

    }

    def __init__(self, *args):
        super().__init__(*args)
        self.secret_encryptor = ConfigCrypto.get_secret_encryptor()



    def convert_type(self, k, v):
        default_value = self.defaults.get(k)
        if default_value is None:
            return v
        tp = type(default_value)
        # 对bool特殊处理
        if tp is bool and isinstance(v, str):
            if v.lower() in ("true", "1"):
                return True
            else:
                return False
        if tp in [list, dict] and isinstance(v, str):
            try:
                v = json.loads(v)
                return v
            except json.JSONDecodeError:
                return v

        try:
            if tp in [list, dict]:
                v = json.loads(v)
            else:
                v = tp(v)
        except Exception:
            pass
        return v

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, dict.__repr__(self))

    def get_from_config(self, item):
        try:
            value = super().__getitem__(item)
        except KeyError:
            value = None
        return value

    def get_from_env(self, item):
        value = os.environ.get(item, None)
        if value is not None:
            value = self.convert_type(item, value)
        return value

    def get(self, item, default=None):
        # 再从配置文件中获取
        value = self.get_from_config(item)
        if value is None:
            value = self.get_from_env(item)

        # 因为要递归，所以优先从上次返回的递归中获取
        if default is None:
            default = self.defaults.get(item)
        if value is None:
            value = default
        if self.secret_encryptor:
            value = self.secret_encryptor.decrypt_if_need(value, item)
        return value

    def __getitem__(self, item):
        return self.get(item)

    def __getattr__(self, item):
        return self.get(item)


class ConfigManager:
    config_class = Config

    def __init__(self, root_path=None):
        self.root_path = root_path
        self.config = self.config_class()

    def from_pyfile(self, filename, silent=False):
        """Updates the values in the config from a Python file.  This function
        behaves as if the file was imported as module with the
        :meth:`from_object` function.

        :param filename: the filename of the config.  This can either be an
                         absolute filename or a filename relative to the
                         root path.
        :param silent: set to ``True`` if you want silent failure for missing
                       files.

        .. versionadded:: 0.7
           `silent` parameter.
        """
        if self.root_path:
            filename = os.path.join(self.root_path, filename)
        d = types.ModuleType('config')
        d.__file__ = filename
        try:
            with open(filename, mode='rb') as config_file:
                exec(compile(config_file.read(), filename, 'exec'), d.__dict__)
        except IOError as e:
            if silent and e.errno in (errno.ENOENT, errno.EISDIR):
                return False
            e.strerror = 'Unable to load configuration file (%s)' % e.strerror
            raise
        self.from_object(d)
        return True

    def from_object(self, obj):
        """Updates the values from the given object.  An object can be of one
        of the following two types:

        -   a string: in this case the object with that name will be imported
        -   an actual object reference: that object is used directly

        Objects are usually either modules or classes. :meth:`from_object`
        loads only the uppercase attributes of the module/class. A ``dict``
        object will not work with :meth:`from_object` because the keys of a
        ``dict`` are not attributes of the ``dict`` class.

        Example of module-based configuration::

            app.config.from_object('yourapplication.default_config')
            from yourapplication import default_config
            app.config.from_object(default_config)

        You should not use this function to load the actual configuration but
        rather configuration defaults.  The actual config should be loaded
        with :meth:`from_pyfile` and ideally from a location not within the
        package because the package might be installed system wide.

        See :ref:`config-dev-prod` for an example of class-based configuration
        using :meth:`from_object`.

        :param obj: an import name or object
        """
        if isinstance(obj, str):
            obj = import_string(obj)
        for key in dir(obj):
            if key.isupper():
                self.config[key] = getattr(obj, key)

    def from_json(self, filename, silent=False):
        """Updates the values in the config from a JSON file. This function
        behaves as if the JSON object was a dictionary and passed to the
        :meth:`from_mapping` function.

        :param filename: the filename of the JSON file.  This can either be an
                         absolute filename or a filename relative to the
                         root path.
        :param silent: set to ``True`` if you want silent failure for missing
                       files.

        .. versionadded:: 0.11
        """
        if self.root_path:
            filename = os.path.join(self.root_path, filename)
        try:
            with open(filename) as json_file:
                obj = json.loads(json_file.read())
        except IOError as e:
            if silent and e.errno in (errno.ENOENT, errno.EISDIR):
                return False
            e.strerror = 'Unable to load configuration file (%s)' % e.strerror
            raise
        return self.from_mapping(obj)

    def from_yaml(self, filename, silent=False):
        if self.root_path:
            filename = os.path.join(self.root_path, filename)
        try:
            with open(filename, 'rt', encoding='utf8') as f:
                obj = yaml.safe_load(f)
        except IOError as e:
            if silent and e.errno in (errno.ENOENT, errno.EISDIR):
                return False
            e.strerror = 'Unable to load configuration file (%s)' % e.strerror
            raise
        if obj:
            return self.from_mapping(obj)
        return True

    def from_mapping(self, *mapping, **kwargs):
        """Updates the config like :meth:`update` ignoring items with non-upper
        keys.

        .. versionadded:: 0.11
        """
        mappings = []
        if len(mapping) == 1:
            if hasattr(mapping[0], 'items'):
                mappings.append(mapping[0].items())
            else:
                mappings.append(mapping[0])
        elif len(mapping) > 1:
            raise TypeError(
                'expected at most 1 positional argument, got %d' % len(mapping)
            )
        mappings.append(kwargs.items())
        for mapping in mappings:
            for (key, value) in mapping:
                if key.isupper():
                    self.config[key] = value
        return True

    def load_from_object(self):
        sys.path.insert(0, PROJECT_DIR)
        try:
            from config import config as c
        except ImportError:
            return False
        if c:
            self.from_object(c)
            return True
        else:
            return False

    def load_from_yml(self):
        for i in ['config.yml', 'config.yaml']:
            if not os.path.isfile(os.path.join(self.root_path, i)):
                continue
            loaded = self.from_yaml(i)
            if loaded:
                return True
        return False

    @classmethod
    def load_user_config(cls, root_path=None, config_class=None):
        config_class = config_class or Config
        cls.config_class = config_class
        if not root_path:
            root_path = BASE_DIR

        manager = cls(root_path=root_path)
        if manager.load_from_object():
            config = manager.config
        elif manager.load_from_yml():
            config = manager.config
        else:
            msg = """

            Error: No config file found.

            You can run `cp config_example.yml config.yml`, and edit it.
            """
            raise ImportError(msg)

        # 对config进行兼容处理
        return config