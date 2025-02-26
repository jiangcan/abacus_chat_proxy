from flask import Flask, request, jsonify, Response
import requests
import time
import json
import uuid
import random
import io
import re
from functools import wraps
import hashlib

app = Flask(__name__)

API_ENDPOINT_URL = "https://abacus.ai/api/v0/describeDeployment"
MODEL_LIST_URL = "https://abacus.ai/api/v0/listExternalApplications"
TARGET_URL = "https://pa002.abacus.ai/api/_chatLLMSendMessageSSE"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]
PASSWORD = None
USER_NUM = 0
USER_DATA = []
CURRENT_USER = -1
MODELS = set()


def resolve_config():
    with open("config.json", "r") as f:
        config = json.load(f)
    config_list = config.get("config")
    return config_list


def get_password():
    global PASSWORD
    try:
        with open("password.txt", "r") as f:
            PASSWORD = f.read().strip()
    except FileNotFoundError:
        with open("password.txt", "w") as f:
            PASSWORD = None


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not PASSWORD:
            return f(*args, **kwargs)
        auth = request.authorization
        if not auth or not check_auth(auth.token):
            return jsonify({"error": "Unauthorized access"}), 401
        return f(*args, **kwargs)

    return decorated


def check_auth(token):
    return hashlib.sha256(token.encode()).hexdigest() == PASSWORD


def init_session():
    global USER_NUM, MODELS, USER_DATA
    config_list = resolve_config()
    user_num = len(config_list)
    for i in range(user_num):
        user = config_list[i]
        cookies = user.get("cookies")
        conversation_id = user.get("conversation_id")
        session = requests.Session()
        headers = {
            "authority": "abacus.ai",
            "method": "POST",
            "path": "/api/v0/listExternalApplications",
            "scheme": "https",
            "accept": "application/json, text/plain, */*",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
            "cache-control": "no-cache",
            "cookie": cookies,
            "origin": "https://apps.abacus.ai",
            "pragma": "no-cache",
            "priority": "u=1, i",
            "reai-ui": "1",
            "referer": "https://apps.abacus.ai/",
            "sec-ch-ua": '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "user-agent": random.choice(USER_AGENTS),
            "x-abacus-org-host": "apps",
        }
        payload = {"includeSearchLlm": False}
        try:
            response = session.post(MODEL_LIST_URL, headers=headers, json=payload)
            response.raise_for_status()
            cookies = update_cookie(session, cookies)
            print(f"Updated cookies {i+1}: {cookies}")
            response_data = response.json()
            if response_data.get("success") is True:
                model_map = {}
                for data in response_data["result"]:
                    model_map[data["name"]] = (
                        data["externalApplicationId"],
                        data["predictionOverrides"]["llmName"],
                    )
                print(f"Model map updated for cookie {i+1}")
                USER_DATA.append((session, cookies, conversation_id, model_map))
            else:
                print(
                    f"Failed to update model map for cookie {i+1}: {response_data.get('error')}"
                )
                continue
        except requests.exceptions.RequestException as e:
            print(f"Failed to update model map for cookie {i+1}: {e}")
            continue
    USER_NUM = len(USER_DATA)
    if USER_NUM == 0:
        print("No user available, exiting...")
        exit(1)
    model_map = USER_DATA[0][3]
    MODELS = set(model_map.keys())
    print(f"running for {USER_NUM} users")


def update_cookie(session, cookies):
    cookie_jar = {}
    for key, value in session.cookies.items():
        cookie_jar[key] = value
    cookie_dict = {}
    for item in cookies.split(";"):
        key, value = item.strip().split("=", 1)
        cookie_dict[key] = value
    cookie_dict.update(cookie_jar)
    cookies = "; ".join([f"{key}={value}" for key, value in cookie_dict.items()])
    return cookies


user_data = init_session()


@app.route("/v1/models", methods=["GET"])
@require_auth
def get_models():
    if len(MODELS) == 0:
        return jsonify({"error": "No models available"}), 500
    model_list = []
    for model in MODELS:
        model_list.append(
            {
                "id": model,
                "object": "model",
                "created": int(time.time()),
                "owned_by": "Elbert",
                "name": model,
            }
        )
    return jsonify({"object": "list", "data": model_list})


@app.route("/v1/chat/completions", methods=["POST"])
@require_auth
def chat_completions():
    openai_request = request.get_json()
    stream = openai_request.get("stream", False)
    messages = openai_request.get("messages")
    if messages is None:
        return jsonify({"error": "Messages is required", "status": 400}), 400
    model = openai_request.get("model")
    if model not in MODELS:
        return (
            jsonify(
                {
                    "error": "Model not available, check if it is configured properly",
                    "status": 404,
                }
            ),
            404,
        )
    message = format_message(messages)
    return (
        send_message(message, model)
        if stream
        else send_message_non_stream(message, model)
    )


def get_user_data():
    global CURRENT_USER
    CURRENT_USER = (CURRENT_USER + 1) % USER_NUM
    print(f"Using cookie {CURRENT_USER+1}")
    return USER_DATA[CURRENT_USER]


def send_message(message, model):
    (session, cookies, conversation_id, model_map) = get_user_data()
    headers = {
        "accept": "text/event-stream",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
        "cache-control": "no-cache",
        "connection": "keep-alive",
        "content-type": "text/plain;charset=UTF-8",
        "cookie": cookies,
        "host": "pa002.abacus.ai",
        "origin": "https://apps.abacus.ai",
        "pragma": "no-cache",
        "referer": "https://apps.abacus.ai/",
        "sec-ch-ua": '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "user-agent": random.choice(USER_AGENTS),
        "x-abacus-org-host": "apps",
    }
    payload = {
        "requestId": str(uuid.uuid4()),
        "deploymentConversationId": conversation_id,
        "message": message,
        "isDesktop": True,
        "chatConfig": {"timezone": "Asia/Shanghai", "language": "zh-CN"},
        "llmName": model_map[model][1],
        "externalApplicationId": model_map[model][0],
        "regenerate": True,
        "editPrompt": True,
    }
    try:
        response = session.post(TARGET_URL, headers=headers, json=payload, stream=True)
        response.raise_for_status()

        def generate():
            try:
                print("---------- Response ----------")
                for line in response.iter_lines():
                    if line:
                        decoded_line = line.decode("utf-8")
                        try:
                            data = json.loads(decoded_line)
                            segment = data.get("segment", "")
                            print(segment, end="")
                            openai_chunk = {
                                "id": "chatcmpl-" + str(uuid.uuid4()),
                                "object": "chat.completion.chunk",
                                "created": int(time.time()),
                                "model": model,
                                "choices": [
                                    {
                                        "index": 0,
                                        "delta": {"content": segment},
                                        "finish_reason": None,
                                    }
                                ],
                            }
                            yield f"data: {json.dumps(openai_chunk)}\n\n"

                        except json.JSONDecodeError:
                            print(f"Failed to decode line: {decoded_line}")
                print("\n---------- Response End ----------")
                yield f"data: [DONE]\n\n"
            except Exception as e:
                print(f"Failed to send message: {e}")
                yield f'data: {{"error": "{e}"}}\n\n'

        return Response(generate(), content_type="text/event-stream")
    except requests.exceptions.RequestException as e:
        print(f"Failed to send message: {e}")
        return jsonify({"error": "Failed to send message"}), 500


def send_message_non_stream(message, model):
    (session, cookies, conversation_id, model_map) = get_user_data()
    headers = {
        "accept": "application/json, text/plain, */*",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
        "cache-control": "no-cache",
        "content-type": "application/json;charset=UTF-8",
        "cookie": cookies,
        "origin": "https://apps.abacus.ai",
        "pragma": "no-cache",
        "referer": "https://apps.abacus.ai/",
        "sec-ch-ua": '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "user-agent": random.choice(USER_AGENTS),
        "x-abacus-org-host": "apps",
    }
    payload = {
        "requestId": str(uuid.uuid4()),
        "deploymentConversationId": conversation_id,
        "message": message,
        "isDesktop": True,
        "chatConfig": {"timezone": "Asia/Shanghai", "language": "zh-CN"},
        "llmName": model_map[model][1],
        "externalApplicationId": model_map[model][0],
        "regenerate": True,
        "editPrompt": True,
    }
    try:
        response = session.post(TARGET_URL, headers=headers, json=payload, stream=True)
        response.raise_for_status()
        buffer = io.StringIO()
        try:
            print("---------- Response ----------")
            for line in response.iter_lines():
                if line:
                    decoded_line = line.decode("utf-8")
                    try:
                        data = json.loads(decoded_line)
                        segment = data.get("segment", "")
                        print(segment, end="")
                        buffer.write(segment)
                    except json.JSONDecodeError:
                        print(f"Failed to decode line: {decoded_line}")
            print("\n---------- Response End ----------")
            openai_response = {
                "id": "chatcmpl-" + str(uuid.uuid4()),
                "object": "chat.completion",
                "created": int(time.time()),
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": buffer.getvalue()},
                        "finish_reason": "completed",
                    }
                ],
            }
            return jsonify(openai_response)
        except Exception as e:
            print(f"Failed to send message: {e}")
            return jsonify({"error": "Failed to send message"}), 500
    except requests.exceptions.RequestException as e:
        print(f"Failed to send message: {e}")
        return jsonify({"error": "Failed to send message"}), 500


def format_message(messages):
    buffer = io.StringIO()
    role_map, prefix, messages = extract_role(messages)
    for message in messages:
        role = message.get("role")
        role = "\b" + role_map[role] if prefix else role_map[role]
        content = message.get("content").replace("\\n", "\n")
        pattern = re.compile(r"<\|removeRole\|>\n")
        if pattern.match(content):
            content = pattern.sub("", content)
            buffer.write(f"{content}\n")
        else:
            buffer.write(f"{role}: {content}\n\n")
    formatted_message = buffer.getvalue()
    with open("message_log.txt", "w", encoding="utf-8") as f:
        f.write(formatted_message)
    return formatted_message


def extract_role(messages):
    role_map = {"user": "Human", "assistant": "Assistant", "system": "System"}
    prefix = False
    first_message = messages[0]["content"]
    pattern = re.compile(
        r"""
        <roleInfo>\s*
        user:\s*(?P<user>[^\n]*)\s*
        assistant:\s*(?P<assistant>[^\n]*)\s*
        system:\s*(?P<system>[^\n]*)\s*
        prefix:\s*(?P<prefix>[^\n]*)\s*
        </roleInfo>\n
    """,
        re.VERBOSE,
    )
    match = pattern.search(first_message)
    if match:
        role_map = {
            "user": match.group("user"),
            "assistant": match.group("assistant"),
            "system": match.group("system"),
        }
        prefix = match.group("prefix") == "1"
        messages[0]["content"] = pattern.sub("", first_message)
        print(f"Extracted role map:")
        print(
            f"User: {role_map['user']}, Assistant: {role_map['assistant']}, System: {role_map['system']}"
        )
        print(f"Using prefix: {prefix}")
    return (role_map, prefix, messages)


if __name__ == "__main__":
    app.run(port=9876)
