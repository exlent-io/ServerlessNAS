# import simplejson as json
import random
import datetime
from datetime import timedelta
import logging
import boto3
from boto3.dynamodb.types import TypeSerializer, TypeDeserializer
from botocore.exceptions import ClientError
from flask import Flask, request
from flask_cors import CORS, cross_origin
import time
import re
import os
from enum import Enum, auto
import threading
import hashlib

import uuid
import json
from functools import reduce

import urllib.parse
from lib.config import ddb_client, user_table_name, group_table_name, base_url

app = Flask(__name__)
cors = CORS(app)

mutex = threading.Lock()

cache = {}

dsr = TypeSerializer()
ddr = TypeDeserializer()

SESSION_LIVE = 86400 * 2


def sr(obj):
    return dsr.serialize(obj)["M"]


def dr(obj):
    return ddr.deserialize({"M": obj})


def hash(str):
    return hashlib.md5(str.encode("utf-8")).hexdigest()[0:4]


@app.route("/api/auth/group", methods=["POST"])
def add_new_user_and_group():
    req_json = request.json

    if (
        "username" not in req_json
        or "password" not in req_json
        or "group" not in req_json
    ):
        return "missing key", 400

    gid = req_json["group"]
    if re.search("^[A-Za-z0-9\-_\~\.]*$", gid) is None:
        return "invalid group", 400

    with mutex:
        try:
            response = ddb_client.transact_write_items(
                TransactItems=[
                    {
                        "Put": {
                            "Item": sr({"gid": gid}),
                            "TableName": group_table_name,
                            "ConditionExpression": "attribute_not_exists(gid)",
                            "ReturnValuesOnConditionCheckFailure": "NONE",
                        }
                    },
                    {
                        "Put": {
                            "Item": sr(
                                {
                                    "gid": gid,
                                    "uid": req_json["username"],
                                    "nickname": req_json["username"],
                                    "p": hashlib.sha512(
                                        req_json["password"].encode("utf-8")
                                    ).hexdigest(),
                                }
                            ),
                            "TableName": user_table_name,
                            "ConditionExpression": "attribute_not_exists(uid)",
                            "ReturnValuesOnConditionCheckFailure": "NONE",
                        }
                    },
                ]
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "TransactionCanceledException":
                print(e)
                return "group already exists", 400
            return str(e), 400
        print(response)
    return "", 200


# internal
@app.route("/api/auth/get_session", methods=["POST"])
def get_session():
    req_json = request.json
    if "session" not in req_json:
        return "", 400

    session = __get_session(req_json["session"])
    if session is None:
        return "", 404
    else:
        return session, 200


def __get_session(session_key):
    ck = hash(session_key)
    if ck in cache:
        session = cache[ck]
        if (
            session["cache_t"] > time.time() - SESSION_LIVE
            and session["session"] == session_key
        ):
            session["cache_t"] = time.time()
            return session
    else:
        return None


@app.route("/api/auth/keep_alive", methods=["POST"])
def keep_alive():
    req_json = request.json
    if "session" not in req_json:
        return "", 400

    session = __get_session(req_json["session"])
    if session is None:
        return "", 404
    else:
        return "", 200


@app.route("/api/auth/login", methods=["POST"])
def login():
    req_json = request.json

    if (
        "username" not in req_json
        or "password" not in req_json
        or "group" not in req_json
    ):
        return "missing key", 400

    gid = req_json["group"]
    u = req_json["username"]
    p = req_json["password"]

    with mutex:
        try:
            response = ddb_client.get_item(
                TableName=user_table_name,
                Key=sr({"gid": gid, "uid": u}),
                ConsistentRead=True,
                ReturnConsumedCapacity="TOTAL",
            )
        except ClientError as e:
            print(e)
            return str(e), 400

    if "Item" not in response:
        return "No such user", 401

    user = dr(response["Item"])

    if hashlib.sha512(p.encode("utf-8")).hexdigest() != user["p"]:
        return "Failed", 401

    user["cache_t"] = time.time()

    session = uuid.uuid4().hex
    ck = hash(session)
    while ck in cache and cache[ck]["cache_t"] > time.time() - 86400 * 2:
        session = uuid.uuid4().hex
        ck = hash(session)

    user["session"] = session
    cache[ck] = user
    return session, 200


# base_url_arr = base_url.split['.']
# def get_gid(headers):
#     host_arr = headers["Host"].split['.']
#     if len(host_arr) < len(base_url_arr):
#         print(base_url, headers["Host"])
#         return None
#     if base_url

#     gid =
#     return gid


@app.route("/api/auth/user", methods=["POST"])
def add_user():
    req_json = request.json

    if (
        "username" not in req_json
        or "password" not in req_json
        or "session" not in req_json
    ):
        return "missing key", 400

    gid = req_json["group"]
    if re.search("^[A-Za-z0-9\-_\~\.]*$", gid) is None:
        return "invalid group", 400

    with mutex:
        try:
            response = ddb_client.transact_write_items(
                TransactItems=[
                    {
                        "Put": {
                            "Item": {"gid": {"S": gid}},
                            "TableName": group_table_name,
                            "ConditionExpression": "attribute_not_exists(gid)",
                            "ReturnValuesOnConditionCheckFailure": "NONE",
                        }
                    },
                    {
                        "Put": {
                            "Item": {
                                "gid": {"S": gid},
                                "uid": {"S": req_json["username"]},
                                "nickname": {"S": req_json["username"]},
                                "p": {
                                    "S": hashlib.sha512(
                                        req_json["password"].encode("utf-8")
                                    ).hexdigest()
                                },
                            },
                            "TableName": user_table_name,
                            "ReturnValuesOnConditionCheckFailure": "NONE",
                        }
                    },
                ]
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "TransactionCanceledException":
                print(e)
                return "group already exists", 400
            return str(e), 400
        print(response)
    return "", 200


def modify_user():
    return


def get_user():
    return

@app.route("/api/auth/get_users_in_group", methods=["POST"])
def get_users_in_group():
    req_json = request.json

    if ("session" not in req_json):
        return "missing key", 400

    session = __get_session(req_json["session"])
    if session is None:
        return "", 401

    gid = req_json["group"]
    u = req_json["username"]
    p = req_json["password"]

    try:
        response = ddb_client.query(
            ExpressionAttributeValues=sr({":gid": gid}),
            KeyConditionExpression='gid = :gid',
            ProjectionExpression='uid,n',
            TableName=user_table_name,
            ReturnConsumedCapacity="TOTAL",
        )
    except ClientError as e:
        print(e)
        return str(e), 400

    if "Item" not in response:
        return "err", 500

    users = dr(response["Item"])

    return users, 200


def delete_user():
    # should prevent the group owner deleted
    return


def delete_group():
    return


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=4000, debug=True)
