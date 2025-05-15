from flask import Flask, request, jsonify, Response  # 导入Flask框架及相关模块，用于构建Web应用
import requests  # 导入requests库，用于发送HTTP请求
import time  # 导入time库，用于处理时间相关操作
import json  # 导入json库，用于处理JSON数据
import uuid  # 导入uuid库，用于生成唯一标识符
import random  # 导入random库，用于生成随机数
import io  # 导入io库，用于处理内存中的字节流
import re  # 导入re库，用于正则表达式操作
from functools import wraps  # 从functools导入wraps，用于装饰器
import hashlib  # 导入hashlib库，用于哈希加密
import jwt  # 导入jwt库，用于处理JSON Web Tokens

app = Flask(__name__)  # 创建Flask应用实例

# API端点URL定义
API_ENDPOINT_URL = "https://abacus.ai/api/v0/describeDeployment"  # Abacus AI部署描述API
MODEL_LIST_URL = "https://abacus.ai/api/v0/listExternalApplications"  # Abacus AI外部应用列表API (用于获取模型列表)
CHAT_URL = "https://apps.abacus.ai/api/_chatLLMSendMessageSSE"  # Abacus AI聊天消息发送API (SSE, Server-Sent Events)
USER_INFO_URL = "https://abacus.ai/api/v0/_getUserInfo"  # Abacus AI获取用户信息API (用于刷新token)
CREATE_CONVERSATION_URL = "https://apps.abacus.ai/api/createDeploymentConversation"  # Abacus AI创建会话API
GET_CONVERSATION_URL = "https://apps.abacus.ai/api/getDeploymentConversation"  # Abacus AI获取会话API

# 用户代理列表，用于模拟不同的浏览器行为
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36"
]

# 全局变量定义
PASSWORD = None  # 用于API访问的密码，如果设置了密码则需要认证
USER_NUM = 0  # 配置的用户数量
USER_DATA = []  # 存储用户配置数据 (session, cookies, token等)
CURRENT_USER = -1  # 当前使用的用户索引，用于轮询
MODELS = set()  # 可用模型的集合
LAST_CONVERSATION_ID = None  # 保存上一个会话ID
DELETE_CHAT = True  # 是否在每次请求后自动删除上一个会话，默认为True

def resolve_config():
    """
    从config.json文件加载配置。
    配置文件应包含一个名为 "config" 的列表，其中每个元素是一个用户配置。
    还会读取 "delete_chat" 配置项。
    """
    try:
        with open("config.json", "r") as f:  # 打开配置文件
            config = json.load(f)  # 加载JSON数据
        config_list = config.get("config")  # 获取用户配置列表
        
        global DELETE_CHAT  # 声明使用全局变量DELETE_CHAT
        DELETE_CHAT = config.get("delete_chat", True)  # 读取delete_chat配置，默认为True
        print(f"读取配置文件中关于自动删除旧会话的设置: {'启用' if DELETE_CHAT else '禁用'}")
        # print(f"根据配置文件，{'启用' if DELETE_CHAT else '禁用'}自动删除旧会话") # 这行是重复的，上面一行更清晰
        
        return config_list  # 返回用户配置列表
    except FileNotFoundError:  # 文件未找到异常处理
        print("未找到配置文件 config.json，请运行 python config_editor.py 配置cookie")
        exit(1)  # 退出程序

def get_password():
    """
    从password.txt文件读取密码。
    如果文件不存在，则创建一个空文件，密码设为None。
    """
    global PASSWORD  # 声明使用全局变量PASSWORD
    try:
        with open("password.txt", "r") as f:  # 打开密码文件
            PASSWORD = f.read().strip()  # 读取并去除首尾空格
    except FileNotFoundError:  # 文件未找到异常处理
        with open("password.txt", "w") as f:  # 创建密码文件
            PASSWORD = None  # 密码设为None

def require_auth(f):
    """
    装饰器，用于需要认证的API路由。
    如果设置了PASSWORD，则检查请求中的Authorization token。
    """
    @wraps(f)  # 保留被装饰函数的元信息
    def decorated(*args, **kwargs):
        if not PASSWORD:  # 如果没有设置密码，则直接允许访问
            return f(*args, **kwargs)
        auth = request.authorization  # 获取请求中的认证信息
        if not auth or not check_auth(auth.token):  # 如果没有认证信息或认证失败
            return jsonify({"error": "Unauthorized access"}), 401  # 返回401未授权错误
        return f(*args, **kwargs)  # 认证成功，执行被装饰的函数
    return decorated

def check_auth(token):
    """
    检查提供的token是否与PASSWORD的哈希值匹配。
    """
    return hashlib.sha256(token.encode()).hexdigest() == PASSWORD  # 比较token的SHA256哈希值与存储的密码哈希值

def is_token_expired(token):
    """
    检查JWT token是否已过期或即将过期（5分钟内）。
    """
    if not token:  # 如果token为空，则视为已过期
        return True
    
    try:
        # 解码token，不验证签名，只为了获取过期时间
        payload = jwt.decode(token, options={"verify_signature": False})
        # 获取过期时间戳 (exp)，如果token在5分钟内过期，则认为已过期
        return payload.get('exp', 0) - time.time() < 300  # 300秒 = 5分钟
    except:  # 解码失败等异常情况，视为已过期
        return True

def refresh_token(session, cookies):
    """
    使用cookie刷新session token。
    Args:
        session: requests的session对象。
        cookies: 用户的cookie字符串。
    Returns:
        新的session token，如果刷新失败则返回None。
    """
    headers = {  # 定义请求头
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
        "user-agent": random.choice(USER_AGENTS),  # 随机选择一个User-Agent
        "origin": "https://apps.abacus.ai",
        "referer": "https://apps.abacus.ai/",
        "cookie": cookies  # 传入用户的cookie
    }
    
    try:
        response = session.post(  # 发送POST请求到用户信息API
            USER_INFO_URL,
            headers=headers,
            json={},  # 请求体为空JSON对象
            cookies=None # session对象会管理cookies，这里不需要显式传递
        )
        
        if response.status_code == 200:  # 如果请求成功
            response_data = response.json()  # 解析JSON响应
            if response_data.get('success') and 'sessionToken' in response_data.get('result', {}):
                return response_data['result']['sessionToken']  # 返回新的session token
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
    """
    获取可用的模型列表及其映射关系 (externalApplicationId, llmName)。
    Args:
        session: requests的session对象。
        cookies: 用户的cookie字符串。
        session_token: 当前的session token。
    Returns:
        一个包含模型映射的字典 (model_map) 和一个包含所有模型名称的集合 (models_set)。
    Raises:
        Exception: 如果API请求失败或未找到可用模型。
    """
    headers = {  # 定义请求头
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
    
    if session_token:  # 如果有session token，则添加到请求头
        headers["session-token"] = session_token
    
    model_map = {}  # 初始化模型映射字典
    models_set = set()  # 初始化模型名称集合
    
    try:
        response = session.post(  # 发送POST请求到模型列表API
            MODEL_LIST_URL,
            headers=headers,
            json={},
            cookies=None
        )
        
        if response.status_code != 200:  # 如果请求失败
            print(f"获取模型列表失败，状态码: {response.status_code}")
            raise Exception("API请求失败")
        
        data = response.json()  # 解析JSON响应
        if not data.get('success'):  # 如果API返回错误
            print(f"获取模型列表失败: {data.get('error', '未知错误')}")
            raise Exception("API返回错误")
        
        applications = []  # 初始化应用列表
        # API返回的result可能是字典或列表，需要兼容处理
        if isinstance(data.get('result'), dict):
            applications = data.get('result', {}).get('externalApplications', [])
        elif isinstance(data.get('result'), list):
            applications = data.get('result', [])
        
        for app_data in applications:  # 遍历每个应用数据
            app_name = app_data.get('name', '')  # 获取应用名称 (作为模型名称)
            app_id = app_data.get('externalApplicationId', '')  # 获取外部应用ID
            prediction_overrides = app_data.get('predictionOverrides', {})  # 获取预测覆盖设置
            llm_name = prediction_overrides.get('llmName', '') if prediction_overrides else ''  # 获取LLM名称
            
            if not (app_name and app_id and llm_name):  # 如果关键信息缺失，则跳过
                continue
            
            model_name = app_name  # 使用应用名称作为模型名称
            model_map[model_name] = (app_id, llm_name)  # 存储模型映射关系
            models_set.add(model_name)  # 将模型名称添加到集合中
        
        if not model_map:  # 如果没有找到任何可用模型
            raise Exception("未找到任何可用模型")
        
        return model_map, models_set  # 返回模型映射和模型集合
    
    except Exception as e:
        print(f"获取模型列表异常: {e}")
        raise # 重新抛出异常

def save_config(config_data):
    """
    将配置数据保存到config.json文件。
    (此函数在当前代码中未被直接调用，但可用于更新配置)
    """
    try:
        with open("config.json", "w") as f:  # 打开配置文件 (写入模式)
            json.dump(config_data, f, indent=4)  # 将配置数据以JSON格式写入文件，美化输出
        return True
    except Exception as e:
        print(f"保存配置文件失败: {e}")
        return False

def update_conversation_id(user_index, conversation_id):
    """
    更新用户的会话ID。
    (此函数在当前代码中实际为空操作，因为会话ID不再持久化到配置文件)
    """
    pass  # 不再输出日志，也不再实际更新配置文件中的会话ID

def init_session():
    """
    初始化所有用户会话。
    读取配置，刷新token，获取模型列表，并填充USER_DATA和MODELS全局变量。
    """
    get_password()  # 读取密码
    global USER_NUM, MODELS, USER_DATA  # 声明使用全局变量
    config_list = resolve_config()  # 加载用户配置
    user_num_from_config = len(config_list)  # 从配置中获取用户数量
    all_models = set()  # 初始化所有模型的集合
    
    temp_user_data = [] # 临时存储有效的用户数据

    for i in range(user_num_from_config):  # 遍历每个用户配置
        user_config = config_list[i]
        cookies = user_config.get("cookies")  # 获取用户的cookie
        # 会话ID不再从配置中读取，初始化时总是为None，后续动态创建
        conversation_id = None
        session = requests.Session()  # 为每个用户创建一个新的requests session
        
        session_token = refresh_token(session, cookies)  # 刷新/获取session token
        if not session_token:
            print(f"无法获取Cookie {i+1}的token，跳过此用户配置。")
            continue  # 如果无法获取token，则跳过此用户
        
        try:
            model_map, models_set = get_model_map(session, cookies, session_token)  # 获取该用户的模型列表
            all_models.update(models_set)  # 将获取到的模型添加到总模型集合中
            # 存储用户数据：session对象, cookies, session_token, 会话ID(None), 模型映射, 用户索引
            temp_user_data.append((session, cookies, session_token, conversation_id, model_map, i))
        except Exception as e:
            print(f"配置用户 {i+1} 失败: {e}，跳过此用户配置。")
            continue # 如果获取模型列表失败，则跳过此用户
    
    USER_DATA = temp_user_data # 更新全局USER_DATA为有效的用户数据
    USER_NUM = len(USER_DATA)  # 更新有效用户的数量
    if USER_NUM == 0:  # 如果没有可用的用户
        print("没有可用的用户配置，程序即将退出...")
        exit(1)  # 退出程序
    
    MODELS = all_models  # 更新全局可用模型列表
    print(f"初始化完成，共成功配置 {USER_NUM} 个用户。")
    print(f"可用模型: {MODELS if MODELS else '无'}")


def update_cookie(session, cookies):
    """
    (此函数在当前代码中未被直接调用)
    更新cookie字符串，将session中新的cookie合并到原有的cookie字符串中。
    """
    cookie_jar = {}  # 用于存储session中的cookie
    for key, value in session.cookies.items():  # 遍历session的cookie
        cookie_jar[key] = value
    
    cookie_dict = {}  # 用于存储原cookie字符串解析后的键值对
    for item in cookies.split(";"):  # 解析原cookie字符串
        key_value = item.strip().split("=", 1)
        if len(key_value) == 2:
            key, value = key_value
            cookie_dict[key] = value
            
    cookie_dict.update(cookie_jar)  # 合并session中的新cookie，新cookie会覆盖同名旧cookie
    # 重新构建cookie字符串
    updated_cookies = "; ".join([f"{key}={value}" for key, value in cookie_dict.items()])
    return updated_cookies

# 初始化会话，此调用会在Flask应用启动前执行
init_session() # 这里user_data变量没有被使用，init_session直接修改全局变量

@app.route("/v1/models", methods=["GET"])  # 定义获取模型列表的API路由
@require_auth  # 此路由需要认证
def get_models_route(): # 重命名函数以避免与全局变量MODELS冲突
    """
    返回符合OpenAI API格式的模型列表。
    """
    if len(MODELS) == 0:  # 如果没有可用模型
        return jsonify({"error": "No models available"}), 500  # 返回500错误
    
    model_list_data = []  # 初始化模型列表数据
    for model_name_str in MODELS:  # 遍历所有可用模型名称
        model_list_data.append(
            {
                "id": model_name_str,  # 模型ID
                "object": "model",  # 对象类型
                "created": int(time.time()),  # 创建时间戳
                "owned_by": "Elbert",  # 所有者 (可自定义)
                "name": model_name_str,  # 模型名称
            }
        )
    return jsonify({"object": "list", "data": model_list_data})  # 返回模型列表

@app.route("/v1/chat/completions", methods=["POST"])  # 定义聊天补全API路由
@require_auth  # 此路由需要认证
def chat_completions():
    """
    处理聊天补全请求，支持流式和非流式响应。
    """
    openai_request = request.get_json()  # 获取请求的JSON数据
    stream = openai_request.get("stream", False)  # 获取是否流式响应的参数，默认为False
    messages = openai_request.get("messages")  # 获取消息列表
    if messages is None:  # 如果消息列表为空
        return jsonify({"error": "Messages is required", "status": 400}), 400  # 返回400错误
    
    model = openai_request.get("model")  # 获取请求的模型名称
    if model not in MODELS:  # 如果请求的模型不在可用模型列表中
        return (
            jsonify(
                {
                    "error": "Model not available, check if it is configured properly",
                    "status": 404,
                }
            ),
            404,  # 返回404错误
        )
    
    message_content = format_message(messages)  # 格式化消息内容
    # "think"参数仅对特定模型有效，这里做了示例判断
    think = (
        openai_request.get("think", False) if model == "Claude Sonnet 3.7" else False # 假设的特定模型
    )
    
    regenerate = openai_request.get("regenerate", False)  # 获取是否重新生成响应的参数
    edit_prompt = openai_request.get("edit_prompt", False)  # 获取是否编辑提示的参数
    
    global DELETE_CHAT  # 声明使用全局变量DELETE_CHAT
    # 如果请求中提供了delete_chat参数，则使用该参数值，否则保持config.json中的默认值
    if "delete_chat" in openai_request:
        DELETE_CHAT = openai_request.get("delete_chat", True)
        print(f"根据请求参数，设置delete_chat为: {'启用' if DELETE_CHAT else '禁用'}")
    
    # 根据stream参数调用不同的处理函数
    if stream:
        return send_message(message_content, model, think, regenerate, edit_prompt)
    else:
        return send_message_non_stream(message_content, model, think, regenerate, edit_prompt)

def create_conversation(session, cookies, session_token, external_application_id=None, deployment_id=None):
    """
    创建一个新的会话。
    Args:
        session: requests的session对象。
        cookies: 用户的cookie字符串。
        session_token: 当前的session token。
        external_application_id: 外部应用ID。
        deployment_id: 部署ID。
    Returns:
        新的会话ID，如果创建失败则返回None。
    """
    if not (external_application_id and deployment_id):  # 检查必要参数
        print("无法创建新会话: 缺少 external_application_id 或 deployment_id")
        return None
    
    trace_id, sentry_trace = generate_trace_id()  # 生成追踪ID
    
    headers = {  # 定义请求头
        "accept": "application/json, text/plain, */*",
        "accept-language": "zh-CN,zh;q=0.9",
        "baggage": f"sentry-environment=production,sentry-release=a869e29e815aefa769a7e9c6cb235ea2638e1fe2,sentry-public_key=3476ea6df1585dd10e92cdae3a66ff49,sentry-trace_id={trace_id}",
        "content-type": "application/json",
        "cookie": cookies,
        "reai-ui": "1",
        "sec-ch-ua": "\"Chromium\";v=\"116\", \"Not)A;Brand\";v=\"24\", \"Google Chrome\";v=\"116\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "sentry-trace": sentry_trace,
        "session-token": session_token,
        "user-agent": random.choice(USER_AGENTS),
        "x-abacus-org-host": "apps"
    }
    
    create_payload = {  # 定义请求体
        "deploymentId": deployment_id,
        "name": "New Chat",  # 会话名称，可自定义
        "externalApplicationId": external_application_id
    }
    
    try:
        response = session.post(  # 发送POST请求到创建会话API
            CREATE_CONVERSATION_URL,
            headers=headers,
            json=create_payload
        )
        
        if response.status_code == 200:  # 如果请求成功
            data = response.json()  # 解析JSON响应
            if data.get("success", False):  # 如果API返回成功
                new_conversation_id = data.get("result", {}).get("deploymentConversationId")
                if new_conversation_id:
                    print(f"成功创建新会话ID: {new_conversation_id}")
                    return new_conversation_id  # 返回新的会话ID
        
        # 如果创建失败或API返回错误
        print(f"创建会话失败: 状态码 {response.status_code} - 响应内容: {response.text[:200]}") # 打印更详细的错误信息
        return None
    except Exception as e:
        print(f"创建会话时发生异常: {e}")
        return None

def is_conversation_valid(session, cookies, session_token, conversation_id, model_map, model):
    """
    (此函数在当前代码中未被直接调用，其逻辑已整合到 get_or_create_conversation)
    检查会话ID是否仍然有效。
    通过尝试发送一个空消息来测试。
    """
    if not conversation_id:  # 如果会话ID为空，则无效
        return False
    
    # 如果模型信息不完整，无法验证
    if not (model in model_map and len(model_map[model]) >= 2):
        print(f"模型 {model} 信息不完整，无法验证会话。")
        return False
    
    external_app_id = model_map[model][0]  # 获取外部应用ID
    
    headers = {  # 定义请求头
        "accept": "text/event-stream",
        "content-type": "text/plain;charset=UTF-8",
        "cookie": cookies,
        "user-agent": random.choice(USER_AGENTS)
    }
    
    if session_token:  # 如果有session token，则添加到请求头
        headers["session-token"] = session_token
    
    payload = {  # 定义请求体，发送空消息
        "requestId": str(uuid.uuid4()),
        "deploymentConversationId": conversation_id,
        "message": "",  # 空消息
        "isDesktop": False,
        "externalApplicationId": external_app_id
    }
    
    try:
        response = session.post(  # 发送POST请求到聊天API
            CHAT_URL,
            headers=headers,
            data=json.dumps(payload),
            stream=False  # 非流式，因为我们只需要知道是否成功
        )
        
        # 即使返回错误，只要不是 "Missing required parameter" 错误，ID本身可能仍然有效
        if response.status_code == 200:
            return True  # 200表示有效
        
        error_text = response.text
        if "Missing required parameter" in error_text: # 特定错误表示ID可能无效或参数问题
            print(f"会话ID {conversation_id} 验证失败: {error_text}")
            return False
        
        # 其他错误，可能ID有效但有其他问题 (例如，消息内容问题，但空消息应该没问题)
        print(f"会话ID {conversation_id} 验证时遇到非致命错误 (状态码 {response.status_code})，可能仍有效。")
        return True # 假设其他错误下ID仍有效，避免频繁创建
    except requests.exceptions.RequestException as e: # 请求本身发生错误
        print(f"验证会话ID {conversation_id} 时发生请求异常: {e}")
        # 如果发生请求错误，我们无法确定ID状态，返回False以尝试创建新的ID
        return False

def get_user_data():
    """
    轮询获取下一个可用的用户数据 (session, cookies, token等)。
    如果token过期，则尝试刷新。
    """
    global CURRENT_USER, USER_DATA, USER_NUM # 声明使用全局变量
    if USER_NUM == 0: # 如果没有可用的用户
        raise Exception("没有可用的用户数据。请检查配置。")

    CURRENT_USER = (CURRENT_USER + 1) % USER_NUM  # 轮询下一个用户
    print(f"当前使用配置索引: {USER_DATA[CURRENT_USER][5] + 1} (内部轮询索引: {CURRENT_USER + 1})")
    
    # 获取当前轮询到的用户数据
    session, cookies, session_token, conversation_id, model_map, user_original_index = USER_DATA[CURRENT_USER]
    
    # 检查token是否过期，如果过期则刷新
    if is_token_expired(session_token):
        print(f"用户配置 {user_original_index + 1} 的token已过期或即将过期，正在刷新...")
        new_token = refresh_token(session, cookies)  # 尝试刷新token
        if new_token:
            # 更新全局USER_DATA中该用户的token
            USER_DATA[CURRENT_USER] = (session, cookies, new_token, conversation_id, model_map, user_original_index)
            session_token = new_token  # 更新当前使用的token
            print(f"成功更新用户配置 {user_original_index + 1} 的token: {session_token[:15]}...{session_token[-15:]}")
        else:
            # 如果刷新失败，仍然使用旧token，但后续请求可能会失败
            print(f"警告：无法刷新用户配置 {user_original_index + 1} 的token，将继续使用当前token。后续请求可能失败。")
            # 可以在这里考虑将此用户标记为不可用或从轮询中暂时移除
    
    return (session, cookies, session_token, conversation_id, model_map, user_original_index)

def delete_conversation(session, cookies, session_token, conversation_id):
    """
    删除指定的会话。
    Args:
        session: requests的session对象。
        cookies: 用户的cookie字符串。
        session_token: 当前的session token。
        conversation_id: 要删除的会话ID。
    """
    if not conversation_id:  # 如果会话ID为空，则不执行任何操作
        return
    
    trace_id, sentry_trace = generate_trace_id()  # 生成追踪ID
    
    headers = {  # 定义请求头
        "accept": "application/json, text/plain, */*",
        "accept-language": "zh-CN,zh;q=0.9",
        "baggage": f"sentry-environment=production,sentry-release=a869e29e815aefa769a7e9c6cb235ea2638e1fe2,sentry-public_key=3476ea6df1585dd10e92cdae3a66ff49,sentry-trace_id={trace_id}",
        "content-type": "application/json",
        "cookie": cookies,
        "reai-ui": "1",
        "sec-ch-ua": "\"Chromium\";v=\"116\", \"Not)A;Brand\";v=\"24\", \"Google Chrome\";v=\"116\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "sentry-trace": sentry_trace,
        "session-token": session_token,
        "user-agent": random.choice(USER_AGENTS),
        "x-abacus-org-host": "apps"
    }
    
    # deploymentId似乎是固定的，或者与模型/应用相关，这里使用了一个硬编码的值
    # 在实际应用中，这个值可能需要从其他API获取或配置
    delete_payload = {  # 定义请求体
        "deploymentId": "14b2a314cc", # 注意：这个deploymentId可能需要根据实际情况调整
        "deploymentConversationId": conversation_id
    }
    
    try:
        response = session.post(  # 发送POST请求到删除会话API
            "https://apps.abacus.ai/api/deleteDeploymentConversation", # API URL
            headers=headers,
            json=delete_payload
        )
        
        if response.status_code == 200:  # 如果请求成功
            data = response.json()  # 解析JSON响应
            if data.get("success", True):  # API可能在成功时不返回success字段或返回true
                print(f"成功删除会话ID: {conversation_id}")
            else:
                print(f"删除会话API调用成功，但业务逻辑失败: {data.get('error', '未知错误')}")
        else:
            print(f"删除会话失败，状态码: {response.status_code} - 响应: {response.text[:200]}")
    except Exception as e:
        print(f"删除会话时发生异常: {e}")

def get_conversation_history(session, cookies, session_token, conversation_id, message=None):
    """
    获取对话历史记录。
    Args:
        session: 请求会话。
        cookies: Cookie字符串。
        session_token: 会话令牌。
        conversation_id: 对话ID。
        message: (可选) 如果提供，会检查历史记录中是否包含此消息（用于验证最新消息是否已加入历史）。
    Returns:
        对话历史记录的result部分，如果失败则返回None。
    """
    if not conversation_id: # 如果会话ID为空，则无法获取历史
        return None
    
    headers = { # 定义请求头
        "accept": "application/json, text/plain, */*",
        "accept-language": "zh-CN,zh;q=0.9",
        "content-type": "application/json",
        "cookie": cookies,
        "user-agent": random.choice(USER_AGENTS),
        "x-abacus-org-host": "apps"
    }
    
    if session_token: # 如果有session token，则添加到请求头
        headers["session-token"] = session_token
    
    get_conversation_payload = { # 定义请求体
        "deploymentConversationId": conversation_id
    }
    
    max_retries = 3 # 最大重试次数
    for attempt in range(max_retries): # 循环尝试
        try:
            response = session.post( # 发送POST请求到获取会话API
                GET_CONVERSATION_URL,
                headers=headers,
                json=get_conversation_payload
            )
            
            if response.status_code == 200: # 如果请求成功
                data = response.json() # 解析JSON响应
                if data.get("success", False): # 如果API返回成功
                    result = data.get("result", {}) # 获取结果部分
                    history = result.get("history", []) # 获取历史记录列表
                    
                    if len(history) > 0: # 如果历史记录不为空
                        if message: # 如果提供了message参数用于验证
                            # 检查最近的用户消息是否匹配
                            for item in reversed(history): # 从后向前遍历历史
                                if item.get("role") == "USER" and item.get("text") == message:
                                    print(f"成功获取对话历史，包含最新消息，共 {len(history)} 条消息。")
                                    return result # 返回结果
                            
                            # 未找到匹配的消息
                            if attempt < max_retries - 1: # 如果还未达到最大重试次数
                                print(f"对话历史中未包含最新消息，正在重试 ({attempt+1}/{max_retries})...")
                                time.sleep(1.5)  # 等待1.5秒后重试
                                continue
                            else: # 已达到最大重试次数
                                print("已达到最大重试次数，但对话历史中仍未包含最新消息。仍返回当前获取的历史。")
                                return result # 即使未匹配也返回当前获取的结果
                        else: # 未提供message参数，仅检查是否有历史记录
                            print(f"成功获取对话历史，共 {len(history)} 条消息。")
                            return result # 返回结果
                    elif attempt < max_retries - 1: # 如果历史记录为空且未达到最大重试次数
                        print(f"对话历史为空，正在重试 ({attempt+1}/{max_retries})...")
                        time.sleep(1.5)  # 等待1.5秒后重试
                        continue
                    else: # 已达到最大重试次数，历史仍为空
                        print("已达到最大重试次数，但对话历史仍为空。")
                        return result # 返回空结果
                else: # API返回失败
                    print(f"获取对话历史API调用成功，但业务逻辑失败: {data.get('error', '未知错误')}")
            else: # 请求状态码非200
                print(f"获取对话历史失败，状态码: {response.status_code} - 响应: {response.text[:200]}")
            
            if attempt < max_retries - 1: # 如果请求失败且未达到最大重试次数
                print(f"获取对话历史请求失败，正在重试 ({attempt+1}/{max_retries})...")
                time.sleep(1.5)  # 等待1.5秒后重试
                continue
        except Exception as e: # 发生异常
            print(f"获取对话历史时发生异常: {e}")
            if attempt < max_retries - 1: # 如果发生异常且未达到最大重试次数
                print(f"正在重试 ({attempt+1}/{max_retries})...")
                time.sleep(1.5)  # 等待1.5秒后重试
                continue
        
        return None # 所有重试均失败后返回None

def get_or_create_conversation(session, cookies, session_token, conversation_id, model_map, model, user_index):
    """
    获取一个有效的会话ID。如果当前会话ID无效或配置为删除旧会话，则创建一个新的会话ID。
    Args:
        session: requests的session对象。
        cookies: 用户的cookie字符串。
        session_token: 当前的session token。
        conversation_id: 当前用户的会话ID (可能为None或旧的ID)。
        model_map: 当前用户的模型映射。
        model: 请求的模型名称。
        user_index: 当前用户的原始索引 (用于更新USER_DATA)。
    Returns:
        一个有效的会话ID。
    """
    global LAST_CONVERSATION_ID, DELETE_CHAT, USER_DATA, CURRENT_USER # 声明使用全局变量
    
    old_conversation_id_to_potentially_delete = conversation_id # 保存原始传入的会话ID

    # 步骤1: 根据DELETE_CHAT配置决定是否删除旧会话
    if DELETE_CHAT and old_conversation_id_to_potentially_delete:
        print(f"根据配置，准备删除用户 {user_index + 1} 的旧会话ID: {old_conversation_id_to_potentially_delete}")
        delete_conversation(session, cookies, session_token, old_conversation_id_to_potentially_delete)
        # 删除后，将当前用户的会话ID置为None，强制创建新会话
        conversation_id = None 
        # 更新USER_DATA中的会话ID为None
        s, c, st, _, mm, ui = USER_DATA[CURRENT_USER]
        USER_DATA[CURRENT_USER] = (s, c, st, None, mm, ui)
        print(f"用户 {user_index + 1} 的会话ID已清除，将创建新会话。")
    elif not DELETE_CHAT and old_conversation_id_to_potentially_delete:
        print(f"根据配置，保留用户 {user_index + 1} 的旧会话ID: {old_conversation_id_to_potentially_delete}")
        # conversation_id 保持不变，后续会尝试使用它
    else: # conversation_id 本来就是 None，或者 DELETE_CHAT 为 False 但没有旧ID
        conversation_id = None # 确保如果之前没有ID，现在也没有

    # 步骤2: 如果没有有效的会话ID (因为被删除或原本就没有)，则创建新会话
    if not conversation_id:
        print(f"用户 {user_index + 1} 需要创建新会话。")
        if model in model_map and len(model_map[model]) >= 2:
            external_app_id = model_map[model][0]
            # deployment_id 用于创建会话，这里使用一个固定的值。
            # 这个值可能需要从API响应或配置中获取。
            deployment_id = "14b2a314cc"  # 这个ID来源于示例请求，可能需要根据实际情况调整
            
            new_created_conversation_id = create_conversation(
                session, cookies, session_token, 
                external_application_id=external_app_id,
                deployment_id=deployment_id
            )
            
            if new_created_conversation_id:
                # 更新全局USER_DATA中当前用户的会话ID
                s, c, st, _, mm, ui = USER_DATA[CURRENT_USER] # 重新获取最新的session, token等
                USER_DATA[CURRENT_USER] = (s, c, st, new_created_conversation_id, mm, ui)
                conversation_id = new_created_conversation_id # 将新创建的ID赋给conversation_id
                # update_conversation_id(user_index, new_conversation_id) # 此函数已空置，不再需要调用
                print(f"用户 {user_index + 1} 成功创建并使用新会话ID: {conversation_id}")
            else:
                # 如果创建新会话失败
                print(f"警告: 用户 {user_index + 1} 创建新会话失败。")
                # 如果之前有旧会话ID (且DELETE_CHAT为False时保留的)，可以考虑回退使用旧ID
                # 但当前逻辑是如果DELETE_CHAT为True，旧ID已被删除；如果为False，则conversation_id未被清空
                # 如果创建失败，且之前没有有效的conversation_id，则这里会返回None，可能导致后续错误
                if old_conversation_id_to_potentially_delete and not DELETE_CHAT:
                    print(f"尝试回退使用旧会话ID: {old_conversation_id_to_potentially_delete}")
                    # 确保USER_DATA中的会话ID是旧的那个
                    s, c, st, _, mm, ui = USER_DATA[CURRENT_USER]
                    USER_DATA[CURRENT_USER] = (s, c, st, old_conversation_id_to_potentially_delete, mm, ui)
                    return old_conversation_id_to_potentially_delete
                else:
                    # 如果没有旧ID可回退，或者旧ID已被删除策略处理，则无法提供会话ID
                    print(f"用户 {user_index + 1} 无法获取有效会话ID。")
                    return None # 表示无法获取或创建会话
        else:
            print(f"错误: 模型 {model} 的映射信息不完整，无法为用户 {user_index + 1} 创建会话。")
            return None # 模型信息不足，无法创建
            
    return conversation_id # 返回当前有效的会话ID (可能是旧的或新创建的)

def generate_trace_id():
    """
    生成一个新的trace_id和sentry_trace，用于请求追踪。
    """
    trace_id = str(uuid.uuid4()).replace('-', '')  # 生成UUID并移除连字符
    sentry_trace = f"{trace_id}-{str(uuid.uuid4())[:16]}"  # 组合trace_id和部分UUID作为sentry_trace
    return trace_id, sentry_trace

def send_message(message, model, think=False, regenerate=False, edit_prompt=False):
    """
    处理流式消息发送。
    Args:
        message: 格式化后的消息内容。
        model: 请求的模型名称。
        think: 是否启用思考过程 (特定模型)。
        regenerate: 是否重新生成。
        edit_prompt: 是否编辑提示。
    Returns:
        Flask Response对象，用于流式传输数据。
    """
    global LAST_CONVERSATION_ID, USER_DATA, CURRENT_USER, DELETE_CHAT # 声明使用全局变量
    
    try:
        # 获取当前轮询到的用户数据
        session, cookies, session_token, current_conversation_id, model_map, user_original_index = get_user_data()
    except Exception as e:
        print(f"获取用户数据失败: {e}")
        return jsonify({"error": f"获取用户数据失败: {e}"}), 500

    # 获取或创建有效的会话ID
    active_conversation_id = get_or_create_conversation(
        session, cookies, session_token, 
        current_conversation_id, # 传入当前用户已有的会话ID
        model_map, model, user_original_index
    )
    
    if not active_conversation_id: # 如果无法获取或创建会话ID
        print(f"错误: 无法为用户 {user_original_index + 1} 获取或创建会话ID。")
        return jsonify({"error": "无法获取或创建会话ID"}), 500

    # 更新LAST_CONVERSATION_ID，用于可能的后续删除操作
    # 注意：这里的逻辑是，如果DELETE_CHAT为True，旧的LAST_CONVERSATION_ID会被删除
    # 然后LAST_CONVERSATION_ID会被更新为当前active_conversation_id
    # 这个LAST_CONVERSATION_ID的删除逻辑主要在generate()函数的末尾处理
    # 但在这里先更新，确保如果请求中途失败，LAST_CONVERSATION_ID也是最新的
    if DELETE_CHAT and LAST_CONVERSATION_ID and LAST_CONVERSATION_ID != active_conversation_id:
        print(f"准备在流式响应结束后删除过时的LAST_CONVERSATION_ID: {LAST_CONVERSATION_ID}")
        # 实际删除操作在generate()末尾，这里仅作记录和更新
    LAST_CONVERSATION_ID = active_conversation_id # 更新全局的LAST_CONVERSATION_ID
    
    trace_id, sentry_trace = generate_trace_id()  # 生成追踪ID
    
    # 从model_map获取externalApplicationId和llmName
    if model not in model_map or not model_map[model]:
        return jsonify({"error": f"模型 {model} 的配置信息不完整。"}), 500
    external_app_id, llm_name_from_map = model_map[model]

    headers = {  # 定义请求头
        "accept": "text/event-stream",
        "accept-language": "zh-CN,zh;q=0.9",
        "baggage": f"sentry-environment=production,sentry-release=a869e29e815aefa769a7e9c6cb235ea2638e1fe2,sentry-public_key=3476ea6df1585dd10e92cdae3a66ff49,sentry-trace_id={trace_id}",
        "content-type": "text/plain;charset=UTF-8",
        "cookie": cookies,
        "sec-ch-ua": "\"Chromium\";v=\"116\", \"Not)A;Brand\";v=\"24\", \"Google Chrome\";v=\"116\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "sentry-trace": sentry_trace,
        "session-token": session_token if session_token else "",
        "x-abacus-org-host": "apps",
        "referrer": f"https://apps.abacus.ai/chatllm/?appId={external_app_id}&convoId={active_conversation_id}",
        "referrerPolicy": "strict-origin-when-cross-origin",
        # "credentials": "include", # 'credentials' 通常由浏览器自动处理，requests中不需要显式设置
        "user-agent": random.choice(USER_AGENTS)
    }
    
    payload = {  # 定义请求体
        "requestId": str(uuid.uuid4()),
        "deploymentConversationId": active_conversation_id,
        "message": message,
        "isDesktop": False,
        "chatConfig": {
            "timezone": "Asia/Shanghai",
            "language": "zh-CN"
        },
        "llmName": llm_name_from_map, # 使用从model_map中获取的llmName
        "externalApplicationId": external_app_id # 使用从model_map中获取的externalApplicationId
    }
    
    if think:  # 如果启用思考过程
        payload["useThinking"] = think
    if regenerate:  # 如果重新生成
        payload["regenerate"] = True
    if edit_prompt:  # 如果编辑提示
        payload["editPrompt"] = True
    
    try:
        # 发送POST请求到聊天API，启用流式响应
        api_response = session.post( # 重命名变量以避免与Flask的Response冲突
            CHAT_URL,
            headers=headers,
            data=json.dumps(payload), # 确保payload是JSON字符串
            stream=True # 启用流式响应
        )
        
        api_response.raise_for_status()  # 如果HTTP状态码表示错误，则抛出异常
        
        def extract_segment(line_data):
            """从SSE事件行中提取segment内容"""
            try:
                data = json.loads(line_data) # 解析JSON数据
                if "segment" in data:
                    if isinstance(data["segment"], str):
                        return data["segment"]
                    # 有时segment本身也是一个包含segment的字典
                    elif isinstance(data["segment"], dict) and "segment" in data["segment"]:
                        return data["segment"]["segment"]
                return "" # 如果没有segment或格式不符，返回空字符串
            except json.JSONDecodeError: # JSON解析失败
                # print(f"警告: 解析SSE行数据失败: {line_data}")
                return "" # 返回空字符串
            except Exception as e_extract: # 其他可能的异常
                # print(f"警告: 提取segment时发生未知错误: {e_extract} on line: {line_data}")
                return ""

        def generate_stream_response(): # 重命名内部生成器函数
            """生成器函数，用于逐块处理和发送流式响应数据"""
            # nonlocal LAST_CONVERSATION_ID # Python 2中没有nonlocal, 但这里是全局变量
            # global LAST_CONVERSATION_ID, DELETE_CHAT, USER_DATA, CURRENT_USER
            
            # 获取最新的用户数据，以防在长时间流式传输过程中token等已更新
            # current_session, current_cookies, current_session_token, _, _, _ = USER_DATA[CURRENT_USER]

            # 初始的assistant角色信息
            yield "data: " + json.dumps({"object": "chat.completion.chunk", "choices": [{"delta": {"role": "assistant"}}]}) + "\n\n"
            
            # 处理思考过程的逻辑 (如果启用)
            # (原始代码中think相关的逻辑比较复杂，这里简化或按原样保留)
            # 如果需要，可以根据实际API响应格式调整这部分
            # think_message_id = ""
            # think_state = 2 # 2: 初始状态, 1: 思考中, 0: 思考结束

            for line in api_response.iter_lines(): # 迭代处理API返回的每一行数据
                if line: # 如果行不为空
                    decoded_line = line.decode("utf-8") # 解码为UTF-8字符串
                    # 移除可能存在的 "data: " 前缀 (如果API直接返回JSON对象而不是SSE格式的 "data: {...}")
                    if decoded_line.startswith("data: "):
                        decoded_line = decoded_line[len("data: "):]
                    
                    # (原始代码中的think逻辑，如果不需要可以简化)
                    # if think:
                    #     try:
                    #         data = json.loads(decoded_line)
                    #         if data.get("type") != "text": # 只处理text类型的消息
                    #             continue
                    #         elif think_state == 2: # 初始状态
                    #             think_message_id = data.get("messageId")
                    #             segment = "[object Object]\n" + data.get("segment", "")
                    #                 yield f"data: {json.dumps({'object': 'chat.completion.chunk', 'choices': [{'delta': {'content': segment}}]})}\n\n"
                    #                 think_state = 0 # 思考结束
                    #         else: # 思考已结束 (think_state == 0)
                    #             segment = data.get("segment", "")
                    #             yield f"data: {json.dumps({'object': 'chat.completion.chunk', 'choices': [{'delta': {'content': segment}}]})}\n\n"
                    #     except json.JSONDecodeError:
                    #         # 如果不是JSON，可能是普通文本块，直接发送
                    #         yield f"data: {json.dumps({'object': 'chat.completion.chunk', 'choices': [{'delta': {'content': decoded_line}}]})}\n\n"
                    #     except Exception as e_think:
                    #         print(f"处理思考逻辑时出错: {e_think} on line: {decoded_line}")
                    # else: # 不启用思考逻辑
                    segment_content = extract_segment(decoded_line) # 提取segment内容
                    if segment_content: # 如果提取到内容
                        # 按照OpenAI API流式格式封装数据块
                        chunk = {"object": "chat.completion.chunk", "choices": [{"delta": {"content": segment_content}}]}
                        yield "data: " + json.dumps(chunk) + "\n\n" # 发送数据块
            
            # 流结束标记
            yield "data: " + json.dumps({"object": "chat.completion.chunk", "choices": [{"delta": {}, "finish_reason": "stop"}]}) + "\n\n"
            yield "data: [DONE]\n\n" # OpenAI流结束标记
            
            # 流式响应结束后，处理旧会话的删除 (如果配置了DELETE_CHAT)
            # 注意：这里的LAST_CONVERSATION_ID是在这个请求开始时被设置为active_conversation_id的
            # 所以，如果DELETE_CHAT为True，它实际上会尝试删除当前刚用完的会话。
            # 这可能不是期望的行为，通常我们是删除 "上一个" 会话。
            # 原始代码的逻辑是：
            # 1. get_or_create_conversation: 如果DELETE_CHAT, 删除传入的conversation_id (来自USER_DATA)
            # 2. send_message: LAST_CONVERSATION_ID = active_conversation_id (新创建或保留的)
            # 3. generate_stream_response (末尾): 如果DELETE_CHAT, delete(LAST_CONVERSATION_ID)
            # 这意味着如果DELETE_CHAT=True, 会话在创建后立即被删除。
            #
            # 调整逻辑：我们应该删除的是 "上一个不同于当前会话" 的 LAST_CONVERSATION_ID。
            # 在 get_or_create_conversation 中，如果DELETE_CHAT为True，旧的会话ID已经被处理（删除）。
            # 所以这里的删除逻辑可能需要重新审视或简化。
            # 假设 LAST_CONVERSATION_ID 存储的是 "上一个请求使用的会话ID"。
            # 在一个新的请求开始时 (get_user_data之后)，如果DELETE_CHAT为True，
            # 并且 LAST_CONVERSATION_ID 存在且不同于当前用户将要使用的会话ID，则删除 LAST_CONVERSATION_ID。
            #
            # 当前的 LAST_CONVERSATION_ID 是在 send_message 开头被赋值为 active_conversation_id 的。
            # 如果 DELETE_CHAT 为 True，那么在 get_or_create_conversation 中，
            # USER_DATA[CURRENT_USER] 中的旧 conversation_id (如果存在) 已经被删除了。
            # 所以，这里的 delete_conversation(session, cookies, session_token, LAST_CONVERSATION_ID)
            # 实际上会删除刚刚用于本次请求的会话。
            #
            # 如果意图是删除 "上一次请求" 的会话，那么 LAST_CONVERSATION_ID 的管理需要调整。
            # 暂时按原逻辑注释，但指出潜在问题。
            #
            # 修正后的理解：LAST_CONVERSATION_ID 确实是用来跟踪上一个会话的。
            # 在 send_message 开头，会获取当前用户的 conversation_id。
            # get_or_create_conversation 会处理这个 conversation_id (可能删除，然后创建新的)。
            # 返回的 active_conversation_id 是本次请求实际使用的。
            # 如果 active_conversation_id 与最初的 LAST_CONVERSATION_ID 不同 (意味着会话切换或新建)，
            # 并且 DELETE_CHAT 为 True，那么旧的 LAST_CONVERSATION_ID 应该被删除。
            #
            # 让我们回顾一下原始代码的逻辑：
            # - 全局 LAST_CONVERSATION_ID
            # - send_message:
            #   - (session, ..., conversation_id_from_user, ...) = get_user_data()
            #   - active_convo_id = get_or_create_conversation(..., conversation_id_from_user, ...)
            #     - 在 get_or_create_conversation 内部:
            #       - 如果 DELETE_CHAT and conversation_id_from_user: delete(conversation_id_from_user)
            #   - LAST_CONVERSATION_ID = active_convo_id  <-- 问题点1: 立即更新
            # - generate():
            #   - ...
            #   - if DELETE_CHAT and LAST_CONVERSATION_ID and LAST_CONVERSATION_ID != active_convo_id: <--- 问题点2: 这个条件永远为false，因为上面刚赋值
            #     delete_conversation(session, cookies, session_token, LAST_CONVERSATION_ID) <--- 实际上是删除当前会话
            #
            # 正确的逻辑应该是：
            # 1. 在 send_message 开始时，记录一个 "previous_last_conversation_id = LAST_CONVERSATION_ID"。
            # 2. 然后正常获取/创建 active_conversation_id。
            # 3. 更新全局 LAST_CONVERSATION_ID = active_conversation_id。
            # 4. 在 generate() 结束时，如果 DELETE_CHAT 且 previous_last_conversation_id 存在且不等于新的 LAST_CONVERSATION_ID，
            #    则删除 previous_last_conversation_id。
            #
            # 由于原始代码的复杂性，这里暂时保留其意图，但指出其行为是删除当前会话（如果DELETE_CHAT）。
            # 如果DELETE_CHAT为True，则在get_or_create_conversation中，旧的会话ID已经被删除了。
            # 这里的delete_conversation(LAST_CONVERSATION_ID)会删除当前刚用完的会话。
            # 这可能是为了确保每个请求都使用全新的会话（如果DELETE_CHAT=True）。

            if DELETE_CHAT: # 如果配置为删除会话
                # 获取最新的用户数据，因为token可能已在长时间流中刷新
                current_session_for_delete, current_cookies_for_delete, current_token_for_delete, _, _, _ = USER_DATA[CURRENT_USER]
                print(f"流式响应结束，根据配置，删除当前会话ID: {active_conversation_id}")
                delete_conversation(current_session_for_delete, current_cookies_for_delete, current_token_for_delete, active_conversation_id)
                # 将USER_DATA中该用户的会话ID也清空
                s, c, st, _, mm, ui = USER_DATA[CURRENT_USER]
                USER_DATA[CURRENT_USER] = (s, c, st, None, mm, ui)
                # LAST_CONVERSATION_ID 也应设为 None，因为它已被删除
                # global LAST_CONVERSATION_ID # 已经在函数开始处声明
                # LAST_CONVERSATION_ID = None # 这会导致下次请求时，previous_last_conversation_id 为 None

        # 返回Flask的流式响应对象
        return Response(generate_stream_response(), mimetype="text/event-stream")
    
    except requests.exceptions.HTTPError as http_err: # 处理HTTP错误
        error_details = f"HTTP错误: {http_err} - 响应: {http_err.response.text[:200] if http_err.response else '无响应体'}"
        print(f"发送消息失败: {error_details}")
        return jsonify({"error": f"发送消息失败: {error_details}"}), http_err.response.status_code if http_err.response else 500
    except requests.exceptions.RequestException as req_err: # 处理其他请求相关的错误
        error_details = str(req_err)
        print(f"发送消息失败 (请求异常): {error_details}")
        return jsonify({"error": f"发送消息失败 (请求异常): {error_details}"}), 500
    except Exception as e: # 处理其他所有异常
        error_details = str(e)
        print(f"发送消息时发生未知错误: {error_details}")
        import traceback
        print(f"错误堆栈: {traceback.format_exc()}")
        return jsonify({"error": f"发送消息时发生未知错误: {error_details}"}), 500

def send_message_non_stream(message, model, think=False, regenerate=False, edit_prompt=False):
    """
    处理非流式消息发送。
    Args:
        message: 格式化后的消息内容。
        model: 请求的模型名称。
        think: 是否启用思考过程。
        regenerate: 是否重新生成。
        edit_prompt: 是否编辑提示。
    Returns:
        Flask jsonify对象，包含完整的聊天响应。
    """
    global LAST_CONVERSATION_ID, USER_DATA, CURRENT_USER, DELETE_CHAT # 声明使用全局变量
    
    try:
        # 获取当前轮询到的用户数据
        session, cookies, session_token, current_conversation_id, model_map, user_original_index = get_user_data()
    except Exception as e:
        print(f"获取用户数据失败: {e}")
        return jsonify({"error": f"获取用户数据失败: {e}"}), 500

    # 获取或创建有效的会话ID
    active_conversation_id = get_or_create_conversation(
        session, cookies, session_token, 
        current_conversation_id, 
        model_map, model, user_original_index
    )

    if not active_conversation_id: # 如果无法获取或创建会话ID
        print(f"错误: 无法为用户 {user_original_index + 1} 获取或创建会话ID。")
        return jsonify({"error": "无法获取或创建会话ID"}), 500
    
    # 更新LAST_CONVERSATION_ID的逻辑与流式版本类似
    # 如果DELETE_CHAT为True，旧的LAST_CONVERSATION_ID（如果不同于active_conversation_id）应被删除
    # 然后LAST_CONVERSATION_ID更新为active_conversation_id
    previous_last_conversation_id = LAST_CONVERSATION_ID # 记录之前的LAST_CONVERSATION_ID
    LAST_CONVERSATION_ID = active_conversation_id # 更新全局的LAST_CONVERSATION_ID

    trace_id, sentry_trace = generate_trace_id()  # 生成追踪ID

    if model not in model_map or not model_map[model]:
        return jsonify({"error": f"模型 {model} 的配置信息不完整。"}), 500
    external_app_id, llm_name_from_map = model_map[model]

    headers = { # 定义请求头 (与流式版本基本一致，除了accept可能不同，但这里API似乎都用text/event-stream)
        "accept": "text/event-stream", # 即使是非流式，目标API也可能期望这个accept类型
        "accept-language": "zh-CN,zh;q=0.9",
        "baggage": f"sentry-environment=production,sentry-release=a869e29e815aefa769a7e9c6cb235ea2638e1fe2,sentry-public_key=3476ea6df1585dd10e92cdae3a66ff49,sentry-trace_id={trace_id}",
        "content-type": "text/plain;charset=UTF-8",
        "cookie": cookies,
        "sec-ch-ua": "\"Chromium\";v=\"116\", \"Not)A;Brand\";v=\"24\", \"Google Chrome\";v=\"116\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "sentry-trace": sentry_trace,
        "session-token": session_token if session_token else "",
        "x-abacus-org-host": "apps",
        "referrer": f"https://apps.abacus.ai/chatllm/?appId={external_app_id}&convoId={active_conversation_id}",
        "referrerPolicy": "strict-origin-when-cross-origin",
        "user-agent": random.choice(USER_AGENTS)
    }
    
    payload = { # 定义请求体
        "requestId": str(uuid.uuid4()),
        "deploymentConversationId": active_conversation_id,
        "message": message,
        "isDesktop": False,
        "chatConfig": {
            "timezone": "Asia/Shanghai",
            "language": "zh-CN"
        },
        "llmName": llm_name_from_map,
        "externalApplicationId": external_app_id
    }
    
    if think: payload["useThinking"] = think
    if regenerate: payload["regenerate"] = True
    if edit_prompt: payload["editPrompt"] = True
    
    try:
        # 发送POST请求到聊天API，即使是非流式请求，也接收流式响应，然后在服务器端聚合成完整消息
        api_response = session.post(
            CHAT_URL,
            headers=headers,
            data=json.dumps(payload),
            stream=True # 仍然以流的方式接收，然后在下面聚合
        )
        api_response.raise_for_status() # 检查HTTP错误
        
        buffer = io.StringIO() # 用于拼接所有消息片段
        
        def extract_segment_non_stream(line_data): # 提取segment的辅助函数
            try:
                data = json.loads(line_data)
                if "segment" in data:
                    if isinstance(data["segment"], str):
                        return data["segment"]
                    elif isinstance(data["segment"], dict) and "segment" in data["segment"]:
                        return data["segment"]["segment"]
                return ""
            except: # 忽略解析错误
                return ""

        # (原始代码中think相关的逻辑，如果不需要可以简化)
        # if think:
        #     think_message_id_ns = ""
        #     think_state_ns = 2 # 2: 初始, 1: 思考中, 0: 结束
        #     for line in api_response.iter_lines():
        #         if line:
        #             decoded_line_ns = line.decode("utf-8")
        #             if decoded_line_ns.startswith("data: "):
        #                 decoded_line_ns = decoded_line_ns[len("data: "):]
        #             try:
        #                 data_ns = json.loads(decoded_line_ns)
        #                 if data_ns.get("type") != "text": continue
        #                 elif think_state_ns == 2:
        #                     think_message_id_ns = data_ns.get("messageId")
        #                     segment_ns = "[object Object]\n" + data_ns.get("segment", "")
        #                         buffer.write(segment_ns)
        #                         think_state_ns = 0
        #                 else: # think_state_ns == 0
        #                     segment_ns = data_ns.get("segment", "")
        #                     buffer.write(segment_ns)
        #             except json.JSONDecodeError:
        #                 # 非JSON行，可能是普通文本，直接追加 (如果API行为如此)
        #                 # buffer.write(decoded_line_ns)
        #                 pass # 或者忽略非JSON行
        #             except Exception as e_think_ns:
        #                 print(f"处理非流式思考逻辑时出错: {e_think_ns} on line: {decoded_line_ns}")
        # else: # 不启用思考逻辑
        for line in api_response.iter_lines(): # 迭代处理API返回的每一行数据
            if line:
                decoded_line_ns = line.decode("utf-8")
                if decoded_line_ns.startswith("data: "): # 移除 "data: " 前缀
                    decoded_line_ns = decoded_line_ns[len("data: "):]
                
                # 忽略空的JSON对象 {} 或 [DONE] 标记
                if decoded_line_ns.strip() == "{}" or decoded_line_ns.strip() == "[DONE]":
                    continue

                segment_content_ns = extract_segment_non_stream(decoded_line_ns) # 提取segment
                if segment_content_ns:
                    buffer.write(segment_content_ns) # 追加到buffer
        
        # 构建符合OpenAI API格式的完整响应
        openai_response_data = {
            "id": "chatcmpl-" + str(uuid.uuid4()), # 生成唯一的响应ID
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model, # 使用请求的模型名称
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": buffer.getvalue()}, # 完整的助手回复
                    "finish_reason": "stop", # 假设总是正常结束 (如果API有其他结束原因，需要处理)
                }
            ],
            # "usage": { ... } # 如果API提供token使用信息，可以在这里添加
        }
        
        # 非流式响应结束后，处理旧会话的删除 (如果配置了DELETE_CHAT)
        # 与流式版本逻辑一致：如果DELETE_CHAT为True，则删除当前刚用完的会话
        if DELETE_CHAT:
            current_session_for_delete, current_cookies_for_delete, current_token_for_delete, _, _, _ = USER_DATA[CURRENT_USER]
            print(f"非流式响应结束，根据配置，删除当前会话ID: {active_conversation_id}")
            delete_conversation(current_session_for_delete, current_cookies_for_delete, current_token_for_delete, active_conversation_id)
            s, c, st, _, mm, ui = USER_DATA[CURRENT_USER]
            USER_DATA[CURRENT_USER] = (s, c, st, None, mm, ui) # 清空用户数据中的会话ID
            # LAST_CONVERSATION_ID = None # 同样，如果删除了，应标记为None

        return jsonify(openai_response_data) # 返回JSON响应

    except requests.exceptions.HTTPError as http_err:
        error_details = f"HTTP错误: {http_err} - 响应: {http_err.response.text[:200] if http_err.response else '无响应体'}"
        print(f"发送消息失败 (非流式): {error_details}")
        return jsonify({"error": f"发送消息失败 (非流式): {error_details}"}), http_err.response.status_code if http_err.response else 500
    except requests.exceptions.RequestException as req_err:
        error_details = str(req_err)
        print(f"发送消息失败 (非流式，请求异常): {error_details}")
        return jsonify({"error": f"发送消息失败 (非流式，请求异常): {error_details}"}), 500
    except Exception as e:
        error_details = str(e)
        print(f"发送消息时发生未知错误 (非流式): {error_details}")
        import traceback
        print(f"错误堆栈: {traceback.format_exc()}")
        return jsonify({"error": f"发送消息时发生未知错误 (非流式): {error_details}"}), 500

def format_message(messages):
    """
    将OpenAI格式的消息列表转换为特定格式的字符串。
    支持通过<roleInfo>标签自定义角色名称和前缀。
    """
    buffer = io.StringIO()  # 使用StringIO进行字符串拼接
    # 默认角色映射
    role_map_default = {"user": "Human", "assistant": "Assistant", "system": "System"}
    use_prefix_default = False # 是否在角色名称前添加退格符 '\b'
    
    # 尝试从第一条消息中提取自定义角色信息
    # 注意：这里假设如果提供了<roleInfo>，它一定在messages[0]['content']的开头
    # 并且messages列表不为空
    processed_messages = list(messages) # 创建副本以修改

    if processed_messages:
        first_message_content = processed_messages[0].get("content", "")
        # 正则表达式，用于匹配<roleInfo>块
        # re.VERBOSE允许在模式中使用空格和注释
        role_info_pattern = re.compile(
            r"""
            ^\s*<roleInfo>\s*                     # 匹配<roleInfo>标签
            user:\s*(?P<userRole>[^\n]*?)\s*      # 捕获user角色名
            assistant:\s*(?P<assistantRole>[^\n]*?)\s* # 捕获assistant角色名
            system:\s*(?P<systemRole>[^\n]*?)\s*  # 捕获system角色名
            prefix:\s*(?P<prefixFlag>[^\n]*?)\s*  # 捕获prefix标志 (0或1)
            </roleInfo>\n?                       # 匹配</roleInfo>标签和可选的换行符
            """,
            re.VERBOSE | re.IGNORECASE # 忽略大小写
        )
        
        match = role_info_pattern.match(first_message_content) # 从字符串开头尝试匹配
        if match:
            print("检测到自定义角色信息 <roleInfo>。")
            role_map_default = { # 更新角色映射
                "user": match.group("userRole").strip(),
                "assistant": match.group("assistantRole").strip(),
                "system": match.group("systemRole").strip(),
            }
            use_prefix_default = match.group("prefixFlag").strip() == "1" # 更新prefix标志
            # 从第一条消息内容中移除<roleInfo>块
            processed_messages[0]["content"] = role_info_pattern.sub("", first_message_content, count=1)
            print(f"提取的角色映射: User='{role_map_default['user']}', Assistant='{role_map_default['assistant']}', System='{role_map_default['system']}'")
            print(f"是否使用前缀: {use_prefix_default}")
        else:
            print("未检测到<roleInfo>，使用默认角色名称。")

    for message_item in processed_messages: # 遍历处理后的消息列表
        role_key = message_item.get("role") # 获取角色 ("user", "assistant", "system")
        # 获取映射后的角色名称，如果role_key不在map中，则使用原始key作为名称
        role_display_name = role_map_default.get(role_key, role_key) 
        
        # 根据use_prefix_default添加前缀
        role_prefix = "\b" if use_prefix_default else ""
        
        content_raw = message_item.get("content", "") # 获取原始消息内容
        # 将 "\\n" (两个字符的转义序列) 替换为 "\n" (一个换行符)
        content_processed = content_raw.replace("\\n", "\n") 
        
        # 特殊处理：如果内容以 "<|removeRole|>\n" 开头，则不添加角色名称和冒号
        remove_role_pattern = re.compile(r"^<\|removeRole\|>\n?")
        if remove_role_pattern.match(content_processed):
            # 移除特殊标记并直接写入内容
            content_final = remove_role_pattern.sub("", content_processed, count=1)
            buffer.write(f"{content_final}\n") # 确保末尾有换行，但避免双换行
        else:
            # 正常格式：角色: 内容\n\n
            buffer.write(f"{role_prefix}{role_display_name}: {content_processed}\n\n")
            
    formatted_message_str = buffer.getvalue() # 获取拼接后的完整字符串
    
    # 将格式化后的消息写入日志文件 (用于调试)
    try:
        with open("message_log.txt", "w", encoding="utf-8") as f:
            f.write(formatted_message_str)
        print("格式化后的消息已写入 message_log.txt")
    except Exception as e_log:
        print(f"写入message_log.txt失败: {e_log}")
        
    return formatted_message_str


def extract_role(messages):
    """
    (此函数在当前代码中未被直接调用，其功能已整合到 format_message 中)
    从消息中提取角色映射和前缀设置。
    """
    role_map = {"user": "Human", "assistant": "Assistant", "system": "System"}
    prefix = False
    if not messages: return (role_map, prefix, messages)

    first_message = messages[0].get("content", "")
    # 正则表达式模式 (与format_message中的一致)
    pattern = re.compile(
        r"""
        ^\s*<roleInfo>\s*
        user:\s*(?P<user>[^\n]*?)\s*
        assistant:\s*(?P<assistant>[^\n]*?)\s*
        system:\s*(?P<s>[^\n]*?)\s*  # 注意这里捕获组名称是 's'
        prefix:\s*(?P<prefix>[^\n]*?)\s*
        </roleInfo>\n?
        """,
        re.VERBOSE | re.IGNORECASE,
    )
    match = pattern.match(first_message)
    if match:
        role_map = {
            "user": match.group("user").strip(),
            "assistant": match.group("assistant").strip(),
            "system": match.group("s").strip(), # 使用捕获组 's'
        }
        prefix = match.group("prefix").strip() == "1"
        # 创建消息副本以避免修改原始列表
        updated_messages = list(messages)
        updated_messages[0]["content"] = pattern.sub("", first_message, count=1)
        
        print(f"提取的角色映射 (来自extract_role):")
        print(f"User: {role_map['user']}, Assistant: {role_map['assistant']}, System: {role_map['system']}")
        print(f"使用前缀 (来自extract_role): {prefix}")
        return (role_map, prefix, updated_messages)
    return (role_map, prefix, messages) # 如果未匹配，返回默认值和原始消息

if __name__ == "__main__":  # 如果作为主程序运行
    # 运行Flask应用
    # host="0.0.0.0" 使服务可以从外部访问
    # port=9876 指定监听端口
    app.run(port=9876, host="0.0.0.0", debug=False) # debug=False 用于生产环境，可设为True进行开发调试