# import simplejson as json
import sys
import random
import datetime
from datetime import timedelta
import logging
import boto3
from botocore.exceptions import ClientError
import time
import re
import os
from enum import Enum, auto
import threading

import uuid
import json
from functools import reduce

import urllib.parse
from lib.config import ddb_client, user_table_name


mutex = threading.Lock()

session_table = {}

def create_session():
    return

def get_uuid(session_token):
    return
    
def remove_session():
    return

