#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask

app = Flask(__name__)
app.config.from_object('config') # configuration file


from app import views