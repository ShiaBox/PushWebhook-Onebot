from flask import Flask, request, jsonify
import requests
import json
import base64
import time
import logging
import re
import hmac
import platform
import os
import hashlib
import urllib.parse
from datetime import datetime
from threading import Thread, Timer, Lock
from logging.handlers import TimedRotatingFileHandler

app = Flask(__name__)
# ================= 日志配置 =================
class ColoredFormatter(logging.Formatter):
    """带颜色的日志格式化器"""
    grey = "\x1b[38;21m"
    green = "\x1b[32;1m"
    yellow = "\x1b[33;21m"
    red = "\x1b[31;21m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format_str = "[%(asctime)s][%(levelname)s]%(message)s"

    FORMATS = {
        logging.DEBUG: grey + format_str + reset,
        logging.INFO: green + format_str + reset,
        logging.WARNING: yellow + format_str + reset,
        logging.ERROR: red + format_str + reset,
        logging.CRITICAL: bold_red + format_str + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(
            log_fmt, 
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        return formatter.format(record)

# 初始化日志系统
def setup_logging():
    # Windows启用VT模式
    if platform.system() == 'Windows':
        os.system('')  # 启用VT100转义序列支持
    # 创建日志目录
    os.makedirs('log', exist_ok=True)
    # 获取根日志器
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    # 移除默认处理器
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # 配置控制台输出
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(ColoredFormatter())
    root_logger.addHandler(console_handler)
    
    # 文件处理器
    file_handler = TimedRotatingFileHandler(
        filename=os.path.join('log', 'app.log'),  # 基础日志文件路径
        when='midnight',  # 每天午夜滚动
        interval=1,       # 每天生成一个新文件
        backupCount=30,   # 保留30天日志
        encoding='utf-8'
    )
    # 自定义文件名生成逻辑
    def custom_namer(default_name):
        # 将默认文件名格式从 app.log.2023-10-10 转换为 log/2023-10-10.log
        base_dir = os.path.dirname(default_name)
        base_file = os.path.basename(default_name)
        
        if '.' in base_file:
            filename_parts = base_file.split('.')
            if len(filename_parts) > 2:
                date_str = filename_parts[-1]
                return os.path.join(base_dir, f"{date_str}.log")
        
        return default_name
    
    file_handler.namer = custom_namer
    
    # 文件日志格式（无颜色）
    file_formatter = logging.Formatter(
        '[%(asctime)s][%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)
    
    # 抑制 Flask/Werkzeug 日志
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    app.logger.handlers = [console_handler]
    #app.logger.setLevel(logging.WARNING)
    app.logger.setLevel(logging.DEBUG)

# 在程序初始化时调用
setup_logging()

with open('config.json', 'r', encoding='utf-8') as f:
    config = json.load(f)
with open('template.json', 'r', encoding='utf-8') as f:
    templates = json.load(f)

# ================= 工具函数 =================
def timestamp_to_date(ts):
    return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

def gen_feishu_sign(timestamp, secret):
    """生成飞书签名"""
    string_to_sign = f"{timestamp}\n{secret}"
    hmac_code = hmac.new(string_to_sign.encode(), digestmod=hashlib.sha256).digest()
    return base64.b64encode(hmac_code).decode()

def gen_dingtalk_sign(timestamp, secret):
    """生成钉钉签名"""
    string_to_sign = f"{timestamp}\n{secret}"
    hmac_code = hmac.new(secret.encode(), string_to_sign.encode(), hashlib.sha256).digest()
    return urllib.parse.quote_plus(base64.b64encode(hmac_code))

# ================= 消息处理器 =================
class MessageProcessor:
    def __init__(self):
        self.processed_messages = {}
        self.lock = Lock() 
    def process_segments(self, raw_msg):
        segments = []
        buffer = []
        has_text = False
        placeholder = config["image_placeholder"]
        for part in re.finditer(r'(\[CQ:\w+?.*?\])|([^[]+)', raw_msg):
            cq_code, text = part.groups()
            
            if cq_code:
                if buffer:
                    segments.append(('text', ''.join(buffer)))
                    buffer = []
                    has_text = True
                code_type = re.search(r'CQ:(\w+)', cq_code).group(1)
                if code_type == 'image':
                    url = re.search(r'url=(.*?)(?:\]|,)', cq_code).group(1)
                    segments.append(('image', url.replace("&amp;", "&")))
                elif code_type == 'face':
                    buffer.append('[QQ表情]')
            elif text.strip():
                buffer.append(text.strip())
                has_text = True
        
        if buffer:
            segments.append(('text', ''.join(buffer)))
            has_text = True
        
        if not has_text and any(seg[0] == 'image' for seg in segments):
            segments.insert(0, ('text', placeholder))
        
        return segments
    
    def deduplicate_message(self, identifier, event_time, user_id):
        """基于唯一标识符、时间戳、用户ID生成MD5哈希进行去重"""
        with self.lock:
            current_time = time.time()
            
            # 生成唯一哈希键
            unique_str = f"{identifier}_{event_time}_{user_id}"
            unique_key = hashlib.md5(unique_str.encode()).hexdigest()
            
            # 清理过期条目（基于过期时间）
            expired = [k for k, expiry in self.processed_messages.items() if expiry < current_time]
            for k in expired:
                del self.processed_messages[k]
            
            # 检查是否已存在
            if unique_key in self.processed_messages:
                return False
            
            # 设置过期时间（当前时间 + 配置的保留时间）
            expiry_time = current_time + config["message_id_expiry"]
            self.processed_messages[unique_key] = expiry_time
            return True
    
# ================= 推送渠道实现 =================
class ChannelSender:
    def __init__(self, config):
        self.config = config
        self.split_images = config.get('split_images', False)
    
    def _build_webhook_url(self):
        raise NotImplementedError
    
    def _build_text_payload(self, content):
        raise NotImplementedError
    
    def _build_image_payload(self, image_data):
        raise NotImplementedError
    
    def _check_response(self, response):
        raise NotImplementedError
    
    def send(self, payload):
        channel_type = self.config['type']
        try:
            # 记录开始时间
            start_time = time.time()
            
            # 发送请求
            webhook_url = self._build_webhook_url()
            response = requests.post(
                webhook_url,
                json=payload,
                timeout=5
            )
            
            # 计算耗时
            elapsed = f"{(time.time() - start_time) * 1000:.2f}ms"
            
            # 解析响应内容
            try:
                resp_content = response.json()
            except json.JSONDecodeError:
                resp_content = {"raw_response": response.text}
            
            # 检查响应状态
            is_success = self._check_response(response)
            
            # 记录日志
            if is_success:
                logging.info(
                    f"[{channel_type}] 推送成功 | "
                    f"耗时: {elapsed} | "
                    f"响应: {json.dumps(resp_content, ensure_ascii=False)}"
                )
            else:
                logging.error(
                    f"[{channel_type}] 推送失败 | "
                    f"状态码: {response.status_code} | "
                    f"响应: {json.dumps(resp_content, ensure_ascii=False)}"
                )
            
            return is_success
            
        except Exception as e:
            logging.error(
                f"[{channel_type}] 推送异常 | "
                f"错误类型: {type(e).__name__} | "
                f"详情: {str(e)}"
            )
            return False

class WechatWorkSender(ChannelSender):
    def _build_webhook_url(self):
        return f"{self.config['webhook_url']}?key={self.config['key']}"
    
    def _build_text_payload(self, content):
        return {"msgtype": "markdown", "markdown": {"content": content}}
    
    def _build_image_payload(self, image_data):
        return {
            "msgtype": "image",
            "image": {
                "base64": image_data["base64"],
                "md5": image_data["md5"]
            }
        }
    
    def _check_response(self, response):
        return response.json().get("errcode", -1) == 0

class FeishuSender(ChannelSender):
    def _build_webhook_url(self):
        return f"{self.config['webhook_url']}/{self.config['key']}"
    
    def _build_text_payload(self, content):
        payload = {"msg_type": "text", "content": {"text": content}}
        if "sign_secret" in self.config:
            timestamp = str(int(time.time()))
            sign = gen_feishu_sign(timestamp, self.config["sign_secret"])
            payload.update({"timestamp": timestamp, "sign": sign})
        return payload
    
    def _build_image_payload(self, image_key):
        return {
            "msg_type": "image",
            "content": {"image_key": image_key}
        }
    
    def _check_response(self, response):
        return response.json().get("code", -1) == 0

class DingTalkSender(ChannelSender):
    def _build_webhook_url(self):
        base_url = f"{self.config['webhook_url']}?access_token={self.config['key']}"
        if "sign_secret" in self.config:
            timestamp = str(round(time.time() * 1000))
            sign = gen_dingtalk_sign(timestamp, self.config["sign_secret"])
            logging.log(logging.INFO, f"[PROCESS]钉钉签名参数 | 时间戳: {timestamp} | 签名: {sign}")
            return f"{base_url}&timestamp={timestamp}&sign={sign}"
        return base_url
    
    def _build_text_payload(self, content):
        return {
            "msgtype": "markdown",
            "markdown": {
                "title": "QQ消息通知",
                "text": content
            }
        }
    
    def _build_image_payload(self, image_url):
        return {
            "msgtype": "markdown",
            "markdown": {
                "title": "QQ图片消息",
                "text": f"![图片]({image_url})"
            }
        }
    
    def _check_response(self, response):
        return response.json().get("errcode", -1) == 0

# ================= 核心逻辑 =================
class BotCore:
    def __init__(self):
        self.msg_processor = MessageProcessor()
        self.senders = self._init_senders()
        self.welcome_sent = set() 
        self.welcome_lock = Lock()
        self.processed_messages = {}
        self.lock = Lock()
    
    def _init_senders(self):
        senders = []
        for channel in config["push_channels"]:
            if not channel["enable"]:
                logging.log(logging.INFO, f"[PROCESS]渠道 {channel['type']} 已禁用，跳过初始化")
                continue
            logging.log(logging.INFO, f"[PROCESS]正在初始化渠道: {channel['type']}") 
            sender_class = {
                "wechat_work": WechatWorkSender,
                "feishu": FeishuSender,
                "dingtalk": DingTalkSender
            }[channel["type"]]
            senders.append(sender_class(channel))
        return senders
    
    def _upload_feishu_image(self, url):
        """上传图片到飞书"""
        try:
            # 获取tenant_access_token
            feishu_config = next(c for c in config["push_channels"] if c["type"] == "feishu")
            token_url = "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal"
            token_data = {
                "app_id": feishu_config["app_id"],
                "app_secret": feishu_config["app_secret"]
            }
            token_resp = requests.post(token_url, json=token_data, timeout=5)
            if token_resp.status_code != 200 or not token_resp.json().get("tenant_access_token"):
                logging.error("飞书tenant_access_token获取失败")
                logging.warning("这是因为飞书文档里写了发送图片需要上传图片并获得image_key，但是自定义机器人没有app_id和app_secret，没法获得tenant_access_token，也就没法获得image_key")
                return None
            
            # 下载图片
            image_resp = requests.get(url, timeout=10)
            if image_resp.status_code != 200:
                logging.error("图片下载失败")
                return None
            
            # 上传到飞书
            upload_url = "https://open.feishu.cn/open-apis/im/v1/images"
            headers = {
                "Authorization": f"Bearer {token_resp.json()['tenant_access_token']}",
                "Content-Type": "multipart/form-data"
            }
            files = {
                "image_type": (None, "message"),
                "image": ("image.jpg", image_resp.content, "image/jpeg")
            }
            upload_resp = requests.post(upload_url, headers=headers, files=files, timeout=10)
            return upload_resp.json().get("data", {}).get("image_key")
        except Exception as e:
            logging.error(f"飞书图片上传异常: {str(e)}")
            return None
    
    def _download_image(self, url):
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                return {
                    "base64": base64.b64encode(response.content).decode(),
                    "md5": hashlib.md5(response.content).hexdigest()
                }
        except Exception as e:
            logging.error(f"图片下载失败: {str(e)}")
        return None
    
    def send_message_package(self, nickname, user_id, msg_time, segments):
        logging.log(logging.INFO, f"[PROCESS]开始处理消息推送，渠道数: {len(self.senders)}")
        
        # 构造消息头
        header = templates["private_message"]["header"].format(
            nickname=nickname, 
            user_id=user_id, 
            msg_time=msg_time
        )
        
        # 处理每个发送者
        for sender in self.senders:
            logging.log(logging.INFO, f"[PROCESS]处理渠道类型: {sender.config['type']}")
            
            # 根据发送者的split_images设置处理消息
            if sender.split_images:
                # 分片发送：按顺序发送文字和图片
                message_parts = []
                text_buffer = []
                has_text = False
                
                for seg_type, content in segments:
                    if seg_type == 'text':
                        text_buffer.append(content)
                        has_text = True
                    elif seg_type == 'image':
                        if text_buffer:
                            message_parts.append(('text', ' '.join(text_buffer)))
                            text_buffer = []
                        # 检查是否有文本，如果没有，插入占位符
                        if not has_text:
                            message_parts.append(('text', config["image_placeholder"]))
                            has_text = True
                        message_parts.append(('image', content))
                
                # 处理剩余内容
                if text_buffer:
                    message_parts.append(('text', ' '.join(text_buffer)))
                
                # 发送分片
                total = len(message_parts)
                for idx, (msg_type, content) in enumerate(message_parts, 1):
                    full_content = header + templates["private_message"]["content_part"].format(
                        current=idx, 
                        total=total, 
                        content=content
                    )
                    
                    if msg_type == 'text':
                        payload = sender._build_text_payload(full_content)
                    else:
                        if isinstance(sender, FeishuSender):
                            image_key = self._upload_feishu_image(content)
                            payload = sender._build_image_payload(image_key) if image_key else None
                        elif isinstance(sender, DingTalkSender):
                            payload = sender._build_image_payload(content)
                        else:
                            img_data = self._download_image(content)
                            payload = sender._build_image_payload(img_data) if img_data else None
                    
                    if payload and not sender.send(payload):
                        logging.error(f"{sender.config['type']}推送失败")
                        return False
                    time.sleep(0.3)
            else:
                # 不分片发送
                if isinstance(sender, DingTalkSender):
                    # 钉钉支持图文混排，转换为Markdown
                    markdown_content = header
                    for seg_type, content in segments:
                        if seg_type == 'text':
                            markdown_content += content
                        elif seg_type == 'image':
                            markdown_content += f"![图片]({content})"
                    
                    payload = sender._build_text_payload(markdown_content)
                    if payload and not sender.send(payload):
                        logging.error(f"{sender.config['type']}推送失败")
                        return False
                else:
                    # 飞书和企业微信：先发文字，再发图片
                    # 构建文字内容（带占位符）
                    text_content = header
                    for seg_type, content in segments:
                        if seg_type == 'text':
                            text_content += content
                        elif seg_type == 'image':
                            text_content += config["image_placeholder"]
                    
                    payload = sender._build_text_payload(text_content)
                    if payload and not sender.send(payload):
                        logging.error(f"{sender.config['type']}推送失败")
                        return False
                    
                    # 发送图片
                    for seg_type, content in segments:
                        if seg_type == 'image':
                            if isinstance(sender, FeishuSender):
                                image_key = self._upload_feishu_image(content)
                                payload = sender._build_image_payload(image_key) if image_key else None
                            else:
                                img_data = self._download_image(content)
                                payload = sender._build_image_payload(img_data) if img_data else None
                            
                            if payload and not sender.send(payload):
                                logging.error(f"{sender.config['type']}推送失败")
                                return False
                            time.sleep(0.3)
        
        return True
    
    def handle_friend_request(self, event):
        user_id = event.get('user_id')
        comment = event.get('comment', '')
        flag = event.get('flag')
        approve_config = config["auto_approve_friend"]
        
        logging.info(f"[好友申请] 收到来自用户 {user_id} 的申请 | 验证信息：'{comment}'")
        
        # 条件判断合并
        has_keyword = any(kw in comment for kw in approve_config.get("keywords", []))
        should_auto_approve = all([
            approve_config.get("enable", False),
            has_keyword,
            event.get('request_type') == 'friend',
            flag
        ])
        
        # 状态参数设置
        action_status = "已自动通过" if should_auto_approve else "请及时处理"
        color = "info" if should_auto_approve else "warning"
        
        # 推送通知（无论是否自动通过都推送）
        content = templates["friend_request"]["content"].format(
            user_id=user_id,
            comment=comment,
            color=color,
            action_status=action_status
        )
        logging.info(f"[好友申请] 推送内容：{content}")
        for sender in self.senders:
            payload = sender._build_text_payload(content)
            sender.send(payload)
        
        # 自动通过逻辑
        if should_auto_approve:
            try:
                # 检查重复处理
                with self.welcome_lock:
                    if user_id in self.welcome_sent:
                        logging.info(f"用户{user_id}已在处理中，跳过重复操作")
                        return jsonify(status="ignored")
                    self.welcome_sent.add(user_id)

                # API调用通过好友申请
                resp = requests.post(
                    f"{config['cqhttp_api_url']}/set_friend_add_request",
                    json={"flag": flag, "approve": True},
                    timeout=5
                )
                if resp.json().get('status') != 'ok':
                    logging.error(f"自动通过失败 | 响应：{resp.text}")
                    return jsonify(status="error"), 500

                # 定义带状态清理的欢迎词发送函数
                def send_welcome():
                    try:
                        for retry in range(3):
                            try:
                                resp = requests.post(
                                    f"{config['cqhttp_api_url']}/send_private_msg",
                                    json={"user_id": user_id, "message": approve_config["welcome_message"]},
                                    timeout=5
                                )
                                if resp.json().get('status') == 'ok':
                                    logging.info(f"欢迎词发送成功（用户 {user_id}）")
                                    return
                                logging.warning(f"欢迎词发送失败，第{retry+1}次重试...")
                                time.sleep(2)
                            except Exception as e:
                                logging.error(f"发送异常：{str(e)}")
                        logging.error("欢迎词发送失败，已达最大重试次数")
                    finally:
                        with self.welcome_lock:
                            if user_id in self.welcome_sent:
                                self.welcome_sent.remove(user_id)

                Timer(2.0, send_welcome).start()
                return jsonify(status="ok")
            except Exception as e:
                with self.welcome_lock:
                    self.welcome_sent.discard(user_id)
                logging.error(f"处理好友请求异常：{str(e)}")
                return jsonify(status="error"), 500
        return jsonify(status="ignored")

# ================= Flask路由 =================
bot = BotCore()

@app.route('/', methods=['POST'])
def handle_event():
    event = request.json
    
        
    # 第一层过滤：群消息直接忽略
    if event.get('message_type') == 'group':
        return jsonify(status="ignored")
    
    # 第二层过滤：精确匹配需要记录的事件类型
    if (
        (event.get('post_type') == 'message' and event.get('message_type') == 'private') 
        or 
        (event.get('post_type') == 'request' and event.get('request_type') == 'friend')
    ):
        # 完全原始数据克隆（不做任何修改）
        raw_log = event.copy()
        logging.info(
            f"[原始事件] [{datetime.now().strftime('%H:%M:%S')}]\n" +
            json.dumps(raw_log, indent=2, ensure_ascii=False)
        )
    
    # 统一处理好友申请的去重检查
    if event.get('post_type') == 'request' and event.get('request_type') == 'friend':
        user_id = event.get('user_id')
        flag = event.get('flag', '')
        event_time = event.get('time', time.time())
        
        # 使用三重标识符生成哈希键
        if not bot.msg_processor.deduplicate_message(flag, event_time, user_id):
            logging.info(f"[去重拦截] 已忽略重复好友申请：flag={flag}")
            return jsonify(status="ignored")
        
        # 在路由层完成所有处理
        return bot.handle_friend_request(event)
    
    # 其他事件处理
    if event.get('message_type') == 'group':
        return jsonify(status="ignored")
    
    message_id = event.get('message_id')
    if message_id:
        user_id = event.get('user_id')
        event_time = event.get('time', time.time())
        if not bot.msg_processor.deduplicate_message(message_id, event_time, user_id):
            return jsonify(status="ignored")
    
    try:
        if event.get('post_type') == 'message':
            return handle_private_message(event)
    except Exception as e:
        logging.error(f"处理异常: {str(e)}")
    return jsonify(status="ignored")

def handle_private_message(event):
    user_id = event.get('user_id')
    nickname = event.get('sender', {}).get('nickname', '未知用户')
    raw_msg = event.get('message', '')
    msg_time = timestamp_to_date(event.get('time', time.time()))
    segments = bot.msg_processor.process_segments(raw_msg)
    
    # 处理测试指令
    text_content = ''.join([c for t,c in segments if t == 'text']).strip()
    if text_content == config["auto_reply"]["test_command"]:
        requests.post(
            f"{config['cqhttp_api_url']}/send_private_msg",
            json={
                "user_id": user_id,
                "message": config["auto_reply"]["response"]
            }
        )
        return jsonify(status="ok")
    
    logging.info(f"[PROCESS]收到来自[{nickname}]QQ[{user_id}]的消息  ")
    logging.log(logging.INFO, f"[PROCESS]消息原始内容：{raw_msg}")   
    if bot.send_message_package(nickname, user_id, msg_time, segments):
        return jsonify(status="ok")
    return jsonify(status="error"), 500

# ================= 监控线程 =================
def status_monitor():
    while True:
        try:
            resp = requests.get(f"{config['cqhttp_api_url']}/get_status", timeout=5)
            if not resp.json().get('data', {}).get('online', False):
                for sender in bot.senders:
                    payload = sender._build_text_payload(templates["system_alert"]["offline"])
                    sender.send(payload)
        except:
            for sender in bot.senders:
                payload = sender._build_text_payload(templates["system_alert"]["check_failed"])
                sender.send(payload)
        time.sleep(60)

# ================= 启动程序 =================
if __name__ == '__main__':
    Thread(target=status_monitor, daemon=True).start()
    app.run(
        host='0.0.0.0', 
        port=config["port"],
        threaded=True
)
