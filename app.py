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
import jwt  

app = Flask(__name__)


API_ENDPOINT_URL = "https://abacus.ai/api/v0/describeDeployment"
MODEL_LIST_URL = "https://abacus.ai/api/v0/listExternalApplications"
CHAT_URL = "https://apps.abacus.ai/api/_chatLLMSendMessageSSE"
USER_INFO_URL = "https://abacus.ai/api/v0/_getUserInfo"
CREATE_CONVERSATION_URL = "https://apps.abacus.ai/api/createDeploymentConversation"


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36"
]


PASSWORD = None
USER_NUM = 0
USER_DATA = []
CURRENT_USER = -1
MODELS = set()
LAST_CONVERSATION_ID = None  # Konservas la lastan konversacian ID
DELETE_CHAT = True  # Ĉu aŭtomate forigi la lastan konversacion post peto


def resolve_config():
    try:
        with open("config.json", "r") as f:
            config = json.load(f)
        config_list = config.get("config")
        
        # Legu la agordon delete_chat
        global DELETE_CHAT
        DELETE_CHAT = config.get("delete_chat", True)
        print(f"Legis agordon por aŭtomata forigo de malnovaj konversacioj: {'aktiva' if DELETE_CHAT else 'malaktiva'}")
        
        return config_list
    except FileNotFoundError:
        print("未找到配置文件 config.json，请运行 python config_editor.py 配置cookie")
        exit(1)


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


def is_token_expired(token):
    if not token:
        return True
    
    try:
        # Malkodi tokenon sen validigo de subskribo
        payload = jwt.decode(token, options={"verify_signature": False})
        # Akiru eksvalidiĝan tempon, konsideru eksvalidiĝinta 5 minutojn antaŭe
        return payload.get('exp', 0) - time.time() < 300
    except:
        return True


def refresh_token(session, cookies):
    """Uzu kuketon por refreŝigi session token, nur revenigu novan tokenon"""
    headers = {
        "accept": "application/json, text/plain, */*",
        "accept-language": "zh-CN,zh;q=0.9",
        "content-type": "application/json",
        "reai-ui": "1",
        "sec-ch-ua": "\"Chromium\";v=\"116\", \"Not)A;Brand\";v=\"24\", \"Google Chrome\";v=\"116\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "x-abacus-org-host": "apps",
        "user-agent": random.choice(USER_AGENTS),
        "origin": "https://apps.abacus.ai",
        "referer": "https://apps.abacus.ai/",
        "cookie": cookies
    }
    
    try:
        response = session.post(
            USER_INFO_URL,
            headers=headers,
            json={},
            cookies=None
        )
        
        if response.status_code == 200:
            response_data = response.json()
            if response_data.get('success') and 'sessionToken' in response_data.get('result', {}):
                return response_data['result']['sessionToken']
            else:
                print(f"刷新token失败: {response_data.get('error', '未知错误')}")
                return None
        else:
            print(f"刷新token失败，状态码: {response.status_code}")
            return None
    except Exception as e:
        print(f"刷新token异常: {e}")
        return None


def get_model_map(session, cookies, session_token):
    """Akiru disponeblan modelan liston kaj ĝiajn mapajn rilatojn"""
    headers = {
        "accept": "application/json, text/plain, */*",
        "accept-language": "zh-CN,zh;q=0.9",
        "content-type": "application/json",
        "reai-ui": "1",
        "sec-ch-ua": "\"Chromium\";v=\"116\", \"Not)A;Brand\";v=\"24\", \"Google Chrome\";v=\"116\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "x-abacus-org-host": "apps",
        "user-agent": random.choice(USER_AGENTS),
        "origin": "https://apps.abacus.ai",
        "referer": "https://apps.abacus.ai/",
        "cookie": cookies
    }
    
    if session_token:
        headers["session-token"] = session_token
    
    model_map = {}
    models_set = set()
    
    try:
        response = session.post(
            MODEL_LIST_URL,
            headers=headers,
            json={},
            cookies=None
        )
        
        if response.status_code != 200:
            print(f"获取模型列表失败，状态码: {response.status_code}")
            raise Exception("API请求失败")
        
        data = response.json()
        if not data.get('success'):
            print(f"获取模型列表失败: {data.get('error', '未知错误')}")
            raise Exception("API返回错误")
        
        applications = []
        if isinstance(data.get('result'), dict):
            applications = data.get('result', {}).get('externalApplications', [])
        elif isinstance(data.get('result'), list):
            applications = data.get('result', [])
        
        for app in applications:
            app_name = app.get('name', '')
            app_id = app.get('externalApplicationId', '')
            prediction_overrides = app.get('predictionOverrides', {})
            llm_name = prediction_overrides.get('llmName', '') if prediction_overrides else ''
            
            if not (app_name and app_id and llm_name):
                continue
                
            model_name = app_name
            model_map[model_name] = (app_id, llm_name)
            models_set.add(model_name)
        
        if not model_map:
            raise Exception("未找到任何可用模型")
        
        return model_map, models_set
    
    except Exception as e:
        print(f"获取模型列表异常: {e}")
        raise


def save_config(config_data):
    """Konservi agordon al dosiero"""
    try:
        with open("config.json", "w") as f:
            json.dump(config_data, f, indent=4)
        return True
    except Exception as e:
        print(f"保存配置文件失败: {e}")
        return False


def update_conversation_id(user_index, conversation_id):
    """Ĝisdatigi la konversacian ID de uzanto"""
    pass  # 不再输出日志


def init_session():
    get_password()
    global USER_NUM, MODELS, USER_DATA
    config_list = resolve_config()
    user_num = len(config_list)
    all_models = set()
    
    for i in range(user_num):
        user = config_list[i]
        cookies = user.get("cookies")
        # Ne plu legu konversacian ID el agordo, ĉiam agordu al Nenio
        conversation_id = None
        session = requests.Session()
        
        session_token = refresh_token(session, cookies)
        if not session_token:
            print(f"无法获取cookie {i+1}的token")
            continue
        
        try:
            model_map, models_set = get_model_map(session, cookies, session_token)
            all_models.update(models_set)
            USER_DATA.append((session, cookies, session_token, conversation_id, model_map, i))
        except Exception as e:
            print(f"配置用户 {i+1} 失败: {e}")
            continue
    
    USER_NUM = len(USER_DATA)
    if USER_NUM == 0:
        print("No user available, exiting...")
        exit(1)
    
    MODELS = all_models
    print(f"启动完成，共配置 {USER_NUM} 个用户")


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
    think = (
        openai_request.get("think", False) if model == "Claude Sonnet 3.7" else False
    )
    
    # Akiru parametron por kontroli ĉu forigi konversaciojn
    global DELETE_CHAT
    DELETE_CHAT = openai_request.get("delete_chat", True)
    
    return (
        send_message(message, model, think)
        if stream
        else send_message_non_stream(message, model, think)
    )


def create_conversation(session, cookies, session_token, external_application_id=None, deployment_id=None):
    """Krei novan konversacion"""
    if not (external_application_id and deployment_id):
        print("无法创建新会话: 缺少必要参数")  # Ne povas krei novan konversacion: Mankas necesaj parametroj
        return None
    
    headers = {
        "accept": "application/json, text/plain, */*",
        "accept-language": "zh-CN,zh;q=0.9",
        "content-type": "application/json",
        "cookie": cookies,
        "user-agent": random.choice(USER_AGENTS),
        "x-abacus-org-host": "apps"
    }
    
    if session_token:
        headers["session-token"] = session_token
    
    create_payload = {
        "deploymentId": deployment_id,
        "name": "New Chat",
        "externalApplicationId": external_application_id
    }
    
    try:
        response = session.post(
            CREATE_CONVERSATION_URL,
            headers=headers,
            json=create_payload
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get("success", False):
                new_conversation_id = data.get("result", {}).get("deploymentConversationId")
                if new_conversation_id:
                    return new_conversation_id
        
        print(f"创建会话失败: {response.status_code} - {response.text[:100]}")  # Malsukcesis krei konversacion: {response.status_code} - {response.text[:100]}
        return None
    except Exception as e:
        print(f"创建会话时出错: {e}")  # Eraro dum kreado de konversacio: {e}
        return None


def is_conversation_valid(session, cookies, session_token, conversation_id, model_map, model):
    """Kontroli ĉu konversacia ID estas valida"""
    if not conversation_id:
        return False
    
    # Se ne havas ĉi tiujn informojn, ne povas validigi
    if not (model in model_map and len(model_map[model]) >= 2):
        return False
        
    external_app_id = model_map[model][0]
    
    # Provu sendi malplenan mesaĝon por testi ĉu la konversacia ID estas valida
    headers = {
        "accept": "text/event-stream",
        "content-type": "text/plain;charset=UTF-8",
        "cookie": cookies,
        "user-agent": random.choice(USER_AGENTS)
    }
    
    if session_token:
        headers["session-token"] = session_token
    
    payload = {
        "requestId": str(uuid.uuid4()),
        "deploymentConversationId": conversation_id,
        "message": "",  # Malplena mesaĝo
        "isDesktop": False,
        "externalApplicationId": external_app_id
    }
    
    try:
        response = session.post(
            CHAT_URL,
            headers=headers,
            data=json.dumps(payload),
            stream=False
        )
        
        # Eĉ se revenis eraro, nur se ne estas "mankas parametro" eraro, la ID ankoraŭ validas
        if response.status_code == 200:
            return True
        
        error_text = response.text
        if "Missing required parameter" in error_text:
            return False
            
        # Aliaj eraroj, eble la ID validas sed havas aliajn problemojn
        return True
    except:
        # Se okazis peto-eraro, ni ne povas certigi, revenu False por krei novan ID
        return False


def get_user_data():
    global CURRENT_USER, USER_DATA
    CURRENT_USER = (CURRENT_USER + 1) % USER_NUM
    print(f"使用配置 {CURRENT_USER+1}")  # Uzas agordon {CURRENT_USER+1}
    
    # Akiru uzantajn datumojn
    session, cookies, session_token, conversation_id, model_map, user_index = USER_DATA[CURRENT_USER]
    
    # Kontrolu ĉu la tokeno eksvalidiĝis, se jes, refreŝigu ĝin
    if is_token_expired(session_token):
        print(f"Cookie {CURRENT_USER+1}的token已过期或即将过期，正在刷新...")  # Tokeno por kuketo {CURRENT_USER+1} eksvalidiĝis aŭ baldaŭ eksvalidiĝos, refreŝigante...
        new_token = refresh_token(session, cookies)
        if new_token:
            # Ĝisdatigu la globale konservitan tokenon
            USER_DATA[CURRENT_USER] = (session, cookies, new_token, conversation_id, model_map, user_index)
            session_token = new_token
            print(f"成功更新token: {session_token[:15]}...{session_token[-15:]}")  # Sukcese ĝisdatigis tokenon: {session_token[:15]}...{session_token[-15:]}
        else:
            print(f"警告：无法刷新Cookie {CURRENT_USER+1}的token，继续使用当前token")  # Averto: Ne povis refreŝigi tokenon por kuketo {CURRENT_USER+1}, daŭrigante kun nuna tokeno
    
    return (session, cookies, session_token, conversation_id, model_map, user_index)


def delete_conversation(session, cookies, session_token, conversation_id):
    """Forigi konversacion"""
    if not conversation_id:
        return
    
    headers = {
        "accept": "application/json, text/plain, */*",
        "accept-language": "zh-CN,zh;q=0.9",
        "content-type": "application/json",
        "cookie": cookies,
        "user-agent": random.choice(USER_AGENTS),
        "x-abacus-org-host": "apps"
    }
    
    if session_token:
        headers["session-token"] = session_token
    
    delete_payload = {
        "deploymentId": "14b2a314cc",
        "deploymentConversationId": conversation_id
    }
    
    try:
        response = requests.post(
            "https://apps.abacus.ai/api/deleteDeploymentConversation",
            headers=headers,
            json=delete_payload
        )
        
        if response.status_code == 200:
            data = response.json()
            if not data.get("success", False):
                print(f"删除会话失败: {data.get('error', '未知错误')}")  # Malsukcesis forigi konversacion: {data.get('error', 'Nekonata eraro')}
        else:
            print(f"删除会话失败，状态码: {response.status_code}")  # Malsukcesis forigi konversacion, stata kodo: {response.status_code}
    except Exception as e:
        print(f"删除会话时出错: {e}")  # Eraro dum forigo de konversacio: {e}


def get_or_create_conversation(session, cookies, session_token, conversation_id, model_map, model, user_index):
    """Akiri aŭ krei validan konversacian ID"""
    global LAST_CONVERSATION_ID
    
    # Ĉiam krei novan konversacion
    need_create = True
    
    # Se necesas krei novan konversacion
    if need_create:
        if model in model_map and len(model_map[model]) >= 2:
            external_app_id = model_map[model][0]
            # Necesas deployment_id por krei konversacion, ni uzas fiksan valoron
            # En reala aplikaĵo, ĝi devus veni el API respondo
            deployment_id = "14b2a314cc"  # Ĉi tio venas de la provizita peto
            
            new_conversation_id = create_conversation(
                session, cookies, session_token, 
                external_application_id=external_app_id,
                deployment_id=deployment_id
            )
            
            if new_conversation_id:
                # Ĝisdatigu la globale konservitan konversacian ID
                global USER_DATA, CURRENT_USER
                session, cookies, session_token, _, model_map, _ = USER_DATA[CURRENT_USER]
                USER_DATA[CURRENT_USER] = (session, cookies, session_token, new_conversation_id, model_map, user_index)
                
                # Ne plu konservu al agordo-dosiero
                update_conversation_id(user_index, new_conversation_id)
                
                return new_conversation_id
    
    # Se ne povas krei, revenigu la originalan ID
    return conversation_id


def generate_trace_id():
    """Generu novan trace_id kaj sentry_trace"""
    trace_id = str(uuid.uuid4()).replace('-', '')
    sentry_trace = f"{trace_id}-{str(uuid.uuid4())[:16]}"
    return trace_id, sentry_trace


def send_message(message, model, think=False):
    """Flua traktado kaj plusendo de mesaĝoj"""
    global LAST_CONVERSATION_ID
    (session, cookies, session_token, conversation_id, model_map, user_index) = get_user_data()
    
    # Konservu malnovan konversacian ID por posta forigo
    old_conversation_id = conversation_id
    
    # Certigu, ke havas validan konversacian ID
    conversation_id = get_or_create_conversation(session, cookies, session_token, conversation_id, model_map, model, user_index)
    
    trace_id, sentry_trace = generate_trace_id()
    
    headers = {
        "accept": "text/event-stream",
        "accept-language": "zh-CN,zh;q=0.9",
        "baggage": f"sentry-environment=production,sentry-release=975eec6685013679c139fc88db2c48e123d5c604,sentry-public_key=3476ea6df1585dd10e92cdae3a66ff49,sentry-trace_id={trace_id}",
        "content-type": "text/plain;charset=UTF-8",
        "cookie": cookies,
        "sec-ch-ua": "\"Chromium\";v=\"116\", \"Not)A;Brand\";v=\"24\", \"Google Chrome\";v=\"116\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "sentry-trace": sentry_trace,
        "user-agent": random.choice(USER_AGENTS)
    }
    
    if session_token:
        headers["session-token"] = session_token
    
    payload = {
        "requestId": str(uuid.uuid4()),
        "deploymentConversationId": conversation_id,
        "message": message,
        "isDesktop": False,
        "chatConfig": {
            "timezone": "Asia/Shanghai",
            "language": "zh-CN"
        },
        "llmName": model_map[model][1],
        "externalApplicationId": model_map[model][0],
        "regenerate": True,
        "editPrompt": True
    }
    
    if think:
        payload["useThinking"] = think
    
    try:
        response = session.post(
            CHAT_URL,
            headers=headers,
            data=json.dumps(payload),
            stream=True
        )
        
        response.raise_for_status()
        
        def extract_segment(line_data):
            try:
                data = json.loads(line_data)
                if "segment" in data:
                    if isinstance(data["segment"], str):
                        return data["segment"]
                    elif isinstance(data["segment"], dict) and "segment" in data["segment"]:
                        return data["segment"]["segment"]
                return ""
            except:
                return ""
        
        def generate():
            id = ""
            think_state = 2
            
            yield "data: " + json.dumps({"object": "chat.completion.chunk", "choices": [{"delta": {"role": "assistant"}}]}) + "\n\n"
            
            for line in response.iter_lines():
                if line:
                    decoded_line = line.decode("utf-8")
                    try:
                        if think:
                            data = json.loads(decoded_line)
                            if data.get("type") != "text":
                                continue
                            elif think_state == 2:
                                id = data.get("messageId")
                                segment = "<think>\n" + data.get("segment", "")
                                yield f"data: {json.dumps({'object': 'chat.completion.chunk', 'choices': [{'delta': {'content': segment}}]})}\n\n"
                                think_state = 1
                            elif think_state == 1:
                                if data.get("messageId") != id:
                                    segment = data.get("segment", "")
                                    yield f"data: {json.dumps({'object': 'chat.completion.chunk', 'choices': [{'delta': {'content': segment}}]})}\n\n"
                                else:
                                    segment = "\n</think>\n" + data.get("segment", "")
                                    yield f"data: {json.dumps({'object': 'chat.completion.chunk', 'choices': [{'delta': {'content': segment}}]})}\n\n"
                                    think_state = 0
                            else:
                                segment = data.get("segment", "")
                                yield f"data: {json.dumps({'object': 'chat.completion.chunk', 'choices': [{'delta': {'content': segment}}]})}\n\n"
                        else:
                            segment = extract_segment(decoded_line)
                            if segment:
                                yield f"data: {json.dumps({'object': 'chat.completion.chunk', 'choices': [{'delta': {'content': segment}}]})}\n\n"
                    except Exception as e:
                        print(f"处理响应出错: {e}")  # Eraro dum pritraktado de respondo: {e}
            
            yield "data: " + json.dumps({"object": "chat.completion.chunk", "choices": [{"delta": {}, "finish_reason": "stop"}]}) + "\n\n"
            yield "data: [DONE]\n\n"
        
        return Response(generate(), mimetype="text/event-stream")
    except requests.exceptions.RequestException as e:
        error_details = str(e)
        if hasattr(e, 'response') and e.response is not None:
            if hasattr(e.response, 'text'):
                error_details += f" - Response: {e.response.text[:200]}"
        print(f"发送消息失败: {error_details}")  # Malsukcesis sendi mesaĝon: {error_details}
        return jsonify({"error": f"Failed to send message: {error_details}"}), 500
    finally:
        # Post fino de peto, se necesas forigi antaŭan konversacion kaj ĝi ekzistas
        if DELETE_CHAT and LAST_CONVERSATION_ID and LAST_CONVERSATION_ID != conversation_id:
            delete_conversation(session, cookies, session_token, LAST_CONVERSATION_ID)
        # Ĝisdatigu la lastan konversacian ID al nuna ID
        LAST_CONVERSATION_ID = conversation_id


def send_message_non_stream(message, model, think=False):
    """Ne-flua traktado de mesaĝoj"""
    global LAST_CONVERSATION_ID
    (session, cookies, session_token, conversation_id, model_map, user_index) = get_user_data()
    
    # Konservu malnovan konversacian ID por posta forigo
    old_conversation_id = conversation_id
    
    # Certigu, ke havas validan konversacian ID
    conversation_id = get_or_create_conversation(session, cookies, session_token, conversation_id, model_map, model, user_index)
    
    trace_id, sentry_trace = generate_trace_id()
    
    headers = {
        "accept": "text/event-stream",
        "accept-language": "zh-CN,zh;q=0.9",
        "baggage": f"sentry-environment=production,sentry-release=975eec6685013679c139fc88db2c48e123d5c604,sentry-public_key=3476ea6df1585dd10e92cdae3a66ff49,sentry-trace_id={trace_id}",
        "content-type": "text/plain;charset=UTF-8",
        "cookie": cookies,
        "sec-ch-ua": "\"Chromium\";v=\"116\", \"Not)A;Brand\";v=\"24\", \"Google Chrome\";v=\"116\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "sentry-trace": sentry_trace,
        "user-agent": random.choice(USER_AGENTS)
    }
    
    if session_token:
        headers["session-token"] = session_token
    
    payload = {
        "requestId": str(uuid.uuid4()),
        "deploymentConversationId": conversation_id,
        "message": message,
        "isDesktop": False,
        "chatConfig": {
            "timezone": "Asia/Shanghai",
            "language": "zh-CN"
        },
        "llmName": model_map[model][1],
        "externalApplicationId": model_map[model][0],
        "regenerate": True,
        "editPrompt": True
    }
    
    if think:
        payload["useThinking"] = think
    
    try:
        response = session.post(
            CHAT_URL,
            headers=headers,
            data=json.dumps(payload),
            stream=True
        )
        
        response.raise_for_status()
        buffer = io.StringIO()
        
        def extract_segment(line_data):
            try:
                data = json.loads(line_data)
                if "segment" in data:
                    if isinstance(data["segment"], str):
                        return data["segment"]
                    elif isinstance(data["segment"], dict) and "segment" in data["segment"]:
                        return data["segment"]["segment"]
                return ""
            except:
                return ""
        
        if think:
            id = ""
            think_state = 2
            for line in response.iter_lines():
                if line:
                    decoded_line = line.decode("utf-8")
                    try:
                        data = json.loads(decoded_line)
                        if data.get("type") != "text":
                            continue
                        elif think_state == 2:
                            id = data.get("messageId")
                            segment = "<think>\n" + data.get("segment", "")
                            buffer.write(segment)
                            think_state = 1
                        elif think_state == 1:
                            if data.get("messageId") != id:
                                segment = data.get("segment", "")
                                buffer.write(segment)
                            else:
                                segment = "\n</think>\n" + data.get("segment", "")
                                buffer.write(segment)
                                think_state = 0
                        else:
                            segment = data.get("segment", "")
                            buffer.write(segment)
                    except json.JSONDecodeError as e:
                        print(f"解析响应出错: {e}")  # Eraro dum analizo de respondo: {e}
        else:
            for line in response.iter_lines():
                if line:
                    decoded_line = line.decode("utf-8")
                    try:
                        segment = extract_segment(decoded_line)
                        if segment:
                            buffer.write(segment)
                    except Exception as e:
                        print(f"处理响应出错: {e}")  # Eraro dum pritraktado de respondo: {e}
        
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
        error_details = str(e)
        if isinstance(e, requests.exceptions.RequestException) and e.response is not None:
            error_details += f" - Response: {e.response.text[:200]}"
        print(f"发送消息失败: {error_details}")  # Malsukcesis sendi mesaĝon: {error_details}
        return jsonify({"error": f"Failed to send message: {error_details}"}), 500
    finally:
        # Post fino de peto, se necesas forigi antaŭan konversacion kaj ĝi ekzistas
        if DELETE_CHAT and LAST_CONVERSATION_ID and LAST_CONVERSATION_ID != conversation_id:
            delete_conversation(session, cookies, session_token, LAST_CONVERSATION_ID)
        # Ĝisdatigu la lastan konversacian ID al nuna ID
        LAST_CONVERSATION_ID = conversation_id


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
        system:\s*(?P<s>[^\n]*)\s*
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
    app.run(port=9876, host="0.0.0.0")
