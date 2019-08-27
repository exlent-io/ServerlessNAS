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
import traceback
import requests
import uuid
from flask import Flask, request
from flask_cors import CORS, cross_origin
import threading
import subprocess
import pathlib
import json
from functools import reduce

import urllib.parse
from lib.config import s3_client, s3_bucket_name

app = Flask(__name__)
cors = CORS(app)
mutex = threading.Lock()


ROOT_DIR = pathlib.Path.cwd() / "tree"
pathlib.Path(ROOT_DIR).mkdir(parents=True, exist_ok=True)
WAL = pathlib.Path.cwd() / "wal"


class WAL_OP:
    MKDIR = "mkdir"
    MV = "mv"
    RM = "rm"
    CREATE = "create"
    CREATE_FINISH = "create_f"
    UPDATE = "update"
    UPDATE_FINISH = "update_f"
    RENAME = "ren"


"""Schema
n=name
h=history
op=(op)erate code
p=payload
ren=rename
s=signature (for create/update)
t=timestamp
<userid>/
        /<uuid>/
               /d {"n":"123", "h"[{"op":"create", "p":{"n":"1","t":1560176500}}, {"op":"ren", "p":{"n":"123", "t":1560176601}}]}
               /<uuid> ...
        /<uuid> {"n":"hi.txt", "id":"<s3-uuid>", h[
                  {"op":"create", "p":{"n":"qq.txt", "s":"base64signature", "t":1560176500}},
                  {"op":"create_f", "p":{"s":"base64signature", "t":1560176500}},
                  {"op":"upload", "p":{"id":"<old_s3-uuid>", "t":1560176701}},
                  {"op":"ren", "p":{"n":"hi.txt", "t":1560176702}},
                  {"op":"upload", "p":{"id":"<s3-uuid>", "t":1560176703}}
                ]}
        /<uuid> {"n":"hello.txt", "ttl":1560186500, h[{"op":"create", "p":{"n":"qq.txt", "t":1560176500}}]}
"""


def __join_str(base, string):
    return reduce(lambda a, b: a.joinpath(b), string.split("/"), base)


def __level(string):
    def trans(part):
        if not part:
            return 0
        elif part == "..":
            return -1
        else:
            return 1

    return reduce(lambda a, b: a + trans(b), string.split("/"), 0)


def __is_a_in_or_eq_b(a, b):
    return str(a.resolve()) in str(b.resolve())


def __is_a_in_b(a, b):
    s_a = str(a.resolve())
    s_b = str(b.resolve())
    return s_a in s_b and s_a != s_b


def __get_last_non_empty(string):
    return reduce(lambda a, b: b if b else a, string.split("/"), None)


headers = {"content-type": "application/json; charset=utf8"}


def __get_owner_id(req_json):
    try:
        response = requests.post(
            "https://auth.exlent.io/api/auth/get_session",
            json={"session": req_json["session"]},
            headers=headers,
        )
    except Exception as e:
        print(e)
        return None

    if response.status_code != 200:
        print(response.text)
        return None
    response = response.json()
    if "gid" in response:
        return response["gid"]
    else:
        print(response)
        return None


@app.route("/", methods=["GET"])
def index():
    return "Hello, World!"


@app.route("/api/ls", methods=["POST"])
def ls():
    req_json = request.json

    # users cannot access outside of the ROOT_DIR via ../../..
    if __level(req_json["path"]) < 0:
        return "invalid value path", 401

    owner_id = __get_owner_id(req_json)
    if owner_id is None:
        return "invalid user", 401
    if not __is_a_in_or_eq_b(
        __join_str(ROOT_DIR, owner_id), __join_str(ROOT_DIR, req_json["path"])
    ):
        return "invalid value path", 401

    path = req_json["path"]
    recursive = request.args.get("recursive") is not None

    with mutex:
        return json.dumps(__ls(__join_str(ROOT_DIR, path), recursive))


def __ls(p, recursive=False):
    tree = (
        {}
        if str(p.parent.resolve()) == str(ROOT_DIR.resolve())
        else json.loads((p / "d").read_text())
    )
    tree["c"] = []
    for child in p.iterdir():
        if re.search("^[^._].*$", child.name) is None:
            print("ignore " + child.name)
            continue
        print(child.name)
        if child.is_dir():
            tree["c"].append(
                {
                    child.name: __ls(child, recursive=True)
                    if (recursive)
                    else json.loads((child / "d").read_text())
                }
            )
        elif child.name != "d":
            tree["c"].append({child.name: json.loads(child.read_text())})

    return tree


def write_wal(obj):
    try:
        with open(WAL, "a+") as f:
            f.write(json.dumps(obj) + "\n")
            f.flush()
            os.fsync(f.fileno())
    except:
        print("failed")


@app.route("/api/mkdir", methods=["POST"])
def mkdir():
    req_json = request.json

    if "path" not in req_json or "dir_name" not in req_json:
        return "missing key", 400

    # 'dir_name' should be non-empty, and cannot contains '/'
    if re.search("^[^/]+$", req_json["dir_name"]) is None:
        return "invalid value dir_name", 400
    # users cannot access outside of the ROOT_DIR via ../../..
    if __level(req_json["path"]) < 0:
        return "invalid value path", 401
    if req_json["dir_name"] == ".." or req_json["dir_name"] == ".":
        return "invalid value dir_name", 400

    owner_id = __get_owner_id(req_json)
    if owner_id is None:
        return "invalid user", 401
    if not __is_a_in_or_eq_b(
        __join_str(ROOT_DIR, owner_id), __join_str(ROOT_DIR, req_json["path"])
    ):
        return "invalid value path", 401

    with mutex:
        req_json["dir_id"] = uuid.uuid4().hex
        req_json["timestamp"] = int(time.time())
        record = {"op": WAL_OP.MKDIR, "payload": req_json}
        write_wal(record)
        new_dir = __mkdir(record)

    return str(new_dir)


def __mkdir(record):
    op = record["op"]
    req_json = record["payload"]
    path = req_json["path"]
    dir_name = req_json["dir_name"]
    dir_id = req_json["dir_id"]
    timestamp = req_json["timestamp"]
    print(path)
    new_dir = __join_str(ROOT_DIR, path) / dir_id

    os.mkdir(new_dir)
    dir_meta = new_dir / "d"

    try:
        with open(dir_meta, "w+") as f:
            f.write(
                json.dumps(
                    {
                        "n": dir_name,
                        "h": [{"op": op, "p": {"n": dir_name, "t": timestamp}}],
                    }
                )
            )
            f.flush()
            # If you’re starting with a buffered Python file object f, first
            # do f.flush(), and then do os.fsync(f.fileno()), to ensure that
            # all internal buffers associated with f are written to disk.
            # https://stackoverflow.com/questions/15348431/does-close-call-fsync-on-linux
            os.fsync(f.fileno())
    except Exception as e:
        print(e)

    return pathlib.PurePath(path, dir_id)


"""
example
src: /a/b/c
dst: /e
=> /e/c
the MOVE_AND_RENAME is not allowed
the dst must exists, there's no auto_mkdir behavior
"""


@app.route("/api/mv", methods=["POST"])
def mv():
    req_json = request.json

    if "src" not in req_json or "dst" not in req_json:
        return "missing key", 400

    # users cannot access outside of the ROOT_DIR via ../../.., and
    # src should not be ROOT_DIR
    if __level(req_json["src"]) <= 0:
        return "invalid value src", 401
    # users cannot access outside of the ROOT_DIR via ../../..
    if __level(req_json["dst"]) < 0:
        return "invalid value dst", 401
    # dst should be outside of the src
    if __is_a_in_or_eq_b(
        __join_str(ROOT_DIR, req_json["src"]), __join_str(ROOT_DIR, req_json["dst"])
    ):
        return "dst should be outside of src", 400

    owner_id = __get_owner_id(req_json)
    if owner_id is None:
        return "invalid user", 401
    if not __is_a_in_or_eq_b(
        __join_str(ROOT_DIR, owner_id), __join_str(ROOT_DIR, req_json["src"])
    ):
        return "invalid value src", 401
    if not __is_a_in_or_eq_b(
        __join_str(ROOT_DIR, owner_id), __join_str(ROOT_DIR, req_json["dst"])
    ):
        return "invalid value dst", 401

    with mutex:

        src_path = __join_str(ROOT_DIR, req_json["src"])
        if not src_path.exists():
            return "", 404

        # detect collision
        if (__join_str(ROOT_DIR, req_json["dst"]) / src_path.name).exists():
            # TODO hanle the case which dst is the same dir of src
            return "collision, NOT YET IMPLEMENTED", 500

        req_json["timestamp"] = int(time.time())
        record = {"op": WAL_OP.MV, "payload": req_json}
        write_wal(record)
        after = __mv(record)

    return str(after)


def __mv(record):
    req_json = record["payload"]
    src = req_json["src"]
    dst = req_json["dst"]
    src_name = __get_last_non_empty(src)
    after = __join_str(ROOT_DIR, dst).resolve() / src_name
    os.rename(str(__join_str(ROOT_DIR, src).resolve()), str(after))
    return after.relative_to(ROOT_DIR)


@app.route("/api/rename", methods=["POST"])
def rename():
    req_json = request.json

    if "path" not in req_json or "filename" not in req_json:
        return "missing key", 400

    # users cannot access outside of the ROOT_DIR via ../../.., and
    # path should not be ROOT_DIR
    if __level(req_json["path"]) <= 0:
        return "invalid value src", 401

    if re.search("^[^/]+$", req_json["filename"]) is None:
        return "invalid value filename", 400

    owner_id = __get_owner_id(req_json)
    if owner_id is None:
        return "invalid user", 401
    if not __is_a_in_or_eq_b(
        __join_str(ROOT_DIR, owner_id), __join_str(ROOT_DIR, req_json["path"])
    ):
        return "invalid value path", 401

    with mutex:
        target = __join_str(ROOT_DIR, req_json["path"])
        if target.is_dir():
            target = target / "d"

        if not target.exists():
            return "", 404

        req_json["timestamp"] = int(time.time())
        record = {
            "op": WAL_OP.RENAME,
            "payload": req_json,
            "before": json.loads(target.read_text()),
        }
        write_wal(record)
        __rename(record)

    return ""


def __rename(record):
    op = record["op"]
    before = record["before"]
    req_json = record["payload"]
    path = req_json["path"]
    filename = req_json["filename"]
    timestamp = req_json["timestamp"]

    obj_meta = __join_str(ROOT_DIR, path)
    if obj_meta.is_dir():
        obj_meta = obj_meta / "d"

    before["n"] = filename
    before["h"].append({"op": op, "p": {"n": filename, "t": timestamp}})

    try:
        with open(obj_meta, "w") as f:
            # The current id is None until create_finish called
            f.write(json.dumps(before))
            f.flush()
            os.fsync(f.fileno())
    except Exception as e:
        print(e)

    return


@app.route("/api/rm", methods=["POST"])
def rm():
    req_json = request.json

    if "path" not in req_json:
        return "missing key", 400

    # users cannot access outside of the ROOT_DIR via ../../..,
    # and cannot rm ROOT_DIR
    if __level(req_json["path"]) <= 0:
        return "invalid value path", 401

    owner_id = __get_owner_id(req_json)
    if owner_id is None:
        return "invalid user", 401
    if not __is_a_in_or_eq_b(
        __join_str(ROOT_DIR, owner_id), __join_str(ROOT_DIR, req_json["path"])
    ):
        return "invalid value path", 401

    with mutex:
        if not __join_str(ROOT_DIR, req_json["path"]).exists():
            return "", 404
        req_json["timestamp"] = int(time.time())
        record = {"op": WAL_OP.RM, "payload": req_json}
        write_wal(record)
        new_dir = __rm(record)

    return str(new_dir)


def __rm(record):
    req_json = record["payload"]
    path = req_json["path"]
    obj_name = __get_last_non_empty(path)
    os.rename(
        str(__join_str(ROOT_DIR, path).resolve()),
        str((__join_str(ROOT_DIR, path).parent / ("_" + obj_name)).resolve()),
    )
    return ""


@app.route("/api/create", methods=["POST"])
def create():
    req_json = request.json

    if "dir" not in req_json or "filename" not in req_json:
        return "missing key", 400

    if __level(req_json["dir"]) < 0:
        return "invalid value dir", 401

    if re.search("^[^/]+$", req_json["filename"]) is None:
        return "invalid value filename", 400

    owner_id = __get_owner_id(req_json)
    if owner_id is None:
        return "invalid user", 401
    if not __is_a_in_or_eq_b(
        __join_str(ROOT_DIR, owner_id), __join_str(ROOT_DIR, req_json["dir"])
    ):
        return "invalid value path", 401

    req_json["file_id"] = uuid.uuid4().hex
    req_json["timestamp"] = int(time.time())

    object_key = owner_id + "/" + uuid.uuid4().hex
    req_json["object_key"] = object_key
    presigned = create_presigned_post(object_key)
    """
        {"url": "https://data-source-versioned.s3.amazonaws.com/",
        "fields": {
            "key": "default_user/9d16759d675b40379345516a12e4222a",
            "acl": "bucket-owner-full-control",
            "AWSAccessKeyId": "AKIAJK345NGHN4CTHDTA",
            "policy": "eyJleHBpcmF0aW9uIjogIj",
            "signature": "Wc1gC1Y5DGETz6hwN9ae+GcVHLg="
        }}
    """
    # TODO verify presigned

    req_json["signature"] = presigned["fields"]["signature"]

    with mutex:
        # detect collision
        full_file_id_with_root = (
            __join_str(ROOT_DIR, req_json["dir"]) / req_json["file_id"]
        )
        if full_file_id_with_root.exists():
            # TODO handle the case which dst is the same dir of src
            return "collision, NOT YET IMPLEMENTED", 500

        record = {"op": WAL_OP.CREATE, "payload": req_json}
        write_wal(record)
        __create(record)

    return json.dumps(
        {
            "message": "AWS SDK S3 Pre-signed urls generated successfully.",
            "presigned": presigned,
            "full_file_id": str(full_file_id_with_root.relative_to(ROOT_DIR)),
        }
    )


def __create(record):
    op = record["op"]
    req_json = record["payload"]
    dir_name = req_json["dir"]
    file_id = req_json["file_id"]
    filename = req_json["filename"]
    object_key = req_json["object_key"]
    signature = req_json["signature"]
    timestamp = req_json["timestamp"]

    obj_meta = __join_str(ROOT_DIR, dir_name) / file_id
    try:
        with open(obj_meta, "w+") as f:
            # The current id is None until create_finish called
            f.write(
                json.dumps(
                    {
                        "n": filename,
                        "id": None,
                        "h": [
                            {
                                "op": op,
                                "p": {
                                    "n": filename,
                                    "id": object_key,
                                    "s": signature,
                                    "t": timestamp,
                                },
                            }
                        ],
                    }
                )
            )
            f.flush()
            os.fsync(f.fileno())
    except Exception as e:
        print(e)

    return


def __filter_valid_create_by_signature(list_of_json, signature):
    r = None
    for item in list_of_json:
        if item["op"] == WAL_OP.CREATE and item["p"]["s"] == signature:
            r = item
        elif item["op"] == WAL_OP.CREATE_FINISH and item["p"]["s"] == signature:
            return None
    return r


def __filter_valid_update_by_signature(list_of_json, signature):
    r = None
    for item in list_of_json:
        if item["op"] == WAL_OP.UPDATE and item["p"]["s"] == signature:
            r = item
        elif item["op"] == WAL_OP.UPDATE_FINISH and item["p"]["s"] == signature:
            return None
    return r


def __get_valid_obj_key_set(list_of_json):
    begin = {}
    finish_set = set()
    for item in list_of_json:
        if item["op"] == WAL_OP.CREATE or item["op"] == WAL_OP.UPDATE:
            begin[item["p"]["s"]] = item
        elif item["op"] == WAL_OP.CREATE_FINISH or item["op"] == WAL_OP.UPDATE_FINISH:
            finish_set.add(item["p"]["s"])
    r = set()
    for key in finish_set:
        r.add(begin[key]["id"])
    return r


@app.route("/api/create_finish", methods=["POST"])
def create_finish():
    req_json = request.json

    if "full_file_id" not in req_json or "signature" not in req_json:
        return "missing key", 400

    full_file_id = req_json["full_file_id"]
    if __level(full_file_id) <= 0:
        return "invalid value dir", 401

    with mutex:
        # validate request
        req_json["timestamp"] = int(time.time())

        before = json.loads(__join_str(ROOT_DIR, full_file_id).read_text())
        correspond_create = __filter_valid_create_by_signature(
            before["h"], req_json["signature"]
        )
        if correspond_create is None:
            return "invalid signature", 401

        record = {"op": WAL_OP.CREATE_FINISH, "payload": req_json, "before": before}
        write_wal(record)
        __create_finish(record)

    return "", 200


def __create_finish(record):
    op = record["op"]
    req_json = record["payload"]
    before = record["before"]
    signature = req_json["signature"]
    timestamp = req_json["timestamp"]
    full_file_id = req_json["full_file_id"]

    correspond_create = __filter_valid_create_by_signature(before["h"], signature)
    if correspond_create is None:
        return "No corresponding CREATE found", 404

    before["id"] = correspond_create["p"]["id"]
    before["h"].append({"op": op, "p": {"s": signature, "t": timestamp}})
    obj_meta = __join_str(ROOT_DIR, full_file_id)

    try:
        with open(obj_meta, "w") as f:
            # The current id is None until create_finish called
            f.write(json.dumps(before))
            f.flush()
            os.fsync(f.fileno())
    except Exception as e:
        print(e)

    return


@app.route("/api/ls_one", methods=["POST"])
def ls_one():
    req_json = request.json

    # users cannot access outside of the ROOT_DIR via ../../..
    if __level(req_json["path"]) < 0:
        return "invalid value path", 401

    owner_id = __get_owner_id(req_json)
    if owner_id is None:
        return "invalid user", 401
    if not __is_a_in_or_eq_b(
        __join_str(ROOT_DIR, owner_id), __join_str(ROOT_DIR, req_json["path"])
    ):
        return "invalid value path", 401

    path = req_json["path"]

    with mutex:
        f = __join_str(ROOT_DIR, path)
        if f.is_dir():
            return "doesn't support dir", 400
        else:
            return f.read_text(), 200



@app.route("/api/get_obj", methods=["POST"])
def get_obj():
    req_json = request.json

    if "path" not in req_json or "obj_id" not in req_json:
        return "missing key", 400
    path = req_json["path"]
    obj_id = req_json["obj_id"]

    if __level(path) <= 0:
        return "invalid value path", 401

    owner_id = __get_owner_id(req_json)
    if owner_id is None:
        return "invalid user", 401
    if not __is_a_in_or_eq_b(
        __join_str(ROOT_DIR, owner_id), __join_str(ROOT_DIR, req_json["path"])
    ):
        return "invalid value path", 401

    with mutex:
        before = json.loads(__join_str(ROOT_DIR, path).read_text())

    content_disposition = (
        req_json["content_disposition"]
        if ("content_disposition" in req_json)
        else before["n"]
    )
    if before["id"] == obj_id or obj_id in __get_valid_obj_key_set(before["h"]):
        return create_presigned_url(obj_id, content_disposition)
    else:
        return "", 404


@app.route("/api/update", methods=["POST"])
def update():
    req_json = request.json

    if "full_file_id" not in req_json:
        return "missing key", 400

    full_file_id = req_json["full_file_id"]
    if __level(full_file_id) <= 0:
        return "invalid value full_file_id", 401

    owner_id = __get_owner_id(req_json)
    if owner_id is None:
        return "invalid user", 401
    if not __is_a_in_or_eq_b(
        __join_str(ROOT_DIR, owner_id), __join_str(ROOT_DIR, req_json["full_file_id"])
    ):
        return "invalid value full_file_id", 401

    object_key = owner_id + "/" + uuid.uuid4().hex
    req_json["object_key"] = object_key
    presigned = create_presigned_post(object_key)
    req_json["signature"] = presigned["fields"]["signature"]

    with mutex:
        # validate request
        req_json["timestamp"] = int(time.time())

        before = json.loads(__join_str(ROOT_DIR, full_file_id).read_text())

        if before["id"] is None:
            return "update should be called after create_finish", 400

        record = {"op": WAL_OP.UPDATE, "payload": req_json, "before": before}
        write_wal(record)
        __update(record)

    return json.dumps(
        {
            "message": "AWS SDK S3 Pre-signed urls generated successfully.",
            "presigned": presigned,
        }
    )


def __update(record):
    op = record["op"]
    req_json = record["payload"]
    before = record["before"]
    signature = req_json["signature"]
    object_key = req_json["object_key"]
    timestamp = req_json["timestamp"]
    full_file_id = req_json["full_file_id"]

    before["h"].append(
        {"op": op, "p": {"id": object_key, "s": signature, "t": timestamp}}
    )
    obj_meta = __join_str(ROOT_DIR, full_file_id)

    try:
        with open(obj_meta, "w") as f:
            # The current id is None until create_finish called
            f.write(json.dumps(before))
            f.flush()
            os.fsync(f.fileno())
    except Exception as e:
        print(e)

    return


@app.route("/api/update_finish", methods=["POST"])
def update_finish():
    req_json = request.json

    if "full_file_id" not in req_json or "signature" not in req_json:
        return "missing key", 400

    full_file_id = req_json["full_file_id"]
    if __level(full_file_id) <= 0:
        return "invalid value dir", 401

    with mutex:
        # validate request
        req_json["timestamp"] = int(time.time())

        before = json.loads(__join_str(ROOT_DIR, full_file_id).read_text())
        correspond_update = __filter_valid_update_by_signature(
            before["h"], req_json["signature"]
        )
        if correspond_update is None:
            return "invalid signature", 401

        record = {"op": WAL_OP.UPDATE_FINISH, "payload": req_json, "before": before}
        write_wal(record)
        __update_finish(record)

    return "", 200


def __update_finish(record):
    op = record["op"]
    req_json = record["payload"]
    before = record["before"]
    signature = req_json["signature"]
    timestamp = req_json["timestamp"]
    full_file_id = req_json["full_file_id"]

    correspond_update = __filter_valid_update_by_signature(before["h"], signature)
    before["id"] = correspond_update["p"]["id"]
    before["h"].append({"op": op, "p": {"s": signature, "t": timestamp}})
    obj_meta = __join_str(ROOT_DIR, full_file_id)

    try:
        with open(obj_meta, "w") as f:
            # The current id is None until create_finish called
            f.write(json.dumps(before))
            f.flush()
            os.fsync(f.fileno())
    except Exception as e:
        print(e)

    return


def my_err_log():
    def log_it(retry_state):
        if retry_state.outcome.failed:
            traceback.print_tb(retry_state.outcome.exception().__traceback__)

    return log_it


def create_presigned_post(object_name):
    """Generate a presigned URL S3 POST request to upload a file

    :param bucket_name: string
    :param object_name: string
    :param fields: Dictionary of prefilled form fields
    :param conditions: List of conditions to include in the policy
    :param expiration: Time in seconds for the presigned URL to remain valid
    :return: Dictionary with the following keys:
        url: URL to post to
        fields: Dictionary of form fields and values to submit with the POST
    :return: None if error.
    """

    """
    Note that if a particular element is included in the fields dictionary it
    will not be automatically added to the conditions list.
    You must specify a condition for the element as well.
    """
    fields = {"key": object_name, "acl": "bucket-owner-full-control"}
    """
    Note that if you include a condition, you must specify the a valid value
    in the fields dictionary as well.
    A value will not be added automatically to the fields dictionary based on
    the conditions.
    """
    conditions = [{"key": object_name}, {"acl": "bucket-owner-full-control"}]

    # Generate a presigned S3 POST URL
    try:
        response = s3_client.generate_presigned_post(
            s3_bucket_name,
            object_name,
            Fields=fields,
            Conditions=conditions,
            ExpiresIn=60,
        )
    except ClientError as e:
        logging.error(e)
        return None

    # The response contains the presigned URL and required fields
    return response


def create_presigned_url(object_name, content_disposition):
    """Generate a presigned URL to share an S3 object

    :param object_name: string
    :return: Presigned URL as string. If error, returns None.
    """

    # Generate a presigned URL for the S3 object
    try:
        response = s3_client.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": s3_bucket_name,
                "Key": object_name,
                "ResponseContentDisposition": "attachment;filename=__.pdf; filename*=UTF-8''%s"
                % urllib.parse.quote(content_disposition),
            },
            ExpiresIn=60,
        )
    except ClientError as e:
        logging.error(e)
        return None

    # The response contains the presigned URL
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)

