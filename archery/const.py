#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# Author : alenx.hai <alenx.hai@gmail.com>
# @Time    : 2024/5/9 下午5:54


import os

from .conf import ConfigManager

__all__ = ['BASE_DIR', 'PROJECT_DIR', 'VERSION', 'CONFIG']

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECT_DIR = os.path.dirname(BASE_DIR)
VERSION = '2.0.0'
CONFIG = ConfigManager.load_user_config()