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

app = Flask(__name__)
# ================= 日志配置 =================
class ColoredFormatter(logging.Formatter):
    """带颜色的日志格式化器"""
    grey = "\x1b[38;21m"
    yellow = "\x1b[33;21m"
    red = "\x1b[31;21m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format_str = "[%(asctime)s][%(levelname)s]%(message)s"

    FORMATS = {
        logging.DEBUG: grey + format_str + reset,
        logging.INFO: grey + format_str + reset,
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
    # 移除默认处理器
    root_logger = logging.getLogger()
    for hdlr in root_logger.handlers[:]:
        root_logger.removeHandler(hdlr)

    # 配置控制台输出
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(ColoredFormatter())
    
    # 配置级别和处理器
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(console_handler)
    
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
    
    def deduplicate_message(self, message_id):
        with self.lock:
            current_time = time.time()
            expired = [mid for mid, ts in self.processed_messages.items() 
                      if current_time - ts > config["message_id_expiry"]]
            for mid in expired:
                del self.processed_messages[mid]
            if message_id in self.processed_messages:
                return False
            self.processed_messages[message_id] = current_time
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
        """上传图片到飞书，这个接口用不了，文档里写了需要上传图片并获得image_key，但是自定义机器人没有app_id和app_secret，没法获得tenant_access_token，也就没法获得image_key"""
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
                logging.error("飞书token获取失败")
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
        approve_config = config["auto_approve_friend"]
        
        has_keyword = any(kw in comment for kw in approve_config["keywords"])
        action_status = "已自动通过" if has_keyword and approve_config["enable"] else "请及时处理"
        color = "info" if has_keyword else "warning"
        
        # 推送通知
        content = templates["friend_request"]["content"].format(
            user_id=user_id,
            comment=comment,
            color=color,
            action_status=action_status
        )
        for sender in self.senders:
            payload = sender._build_text_payload(content)
            sender.send(payload)
        
        # 自动通过逻辑
        if has_keyword and approve_config["enable"]:
            try:
                requests.post(
                    f"{config['cqhttp_api_url']}/set_friend_add_request",
                    json={"flag": event['flag'], "approve": True}
                )
                Timer(2.0, lambda: requests.post(
                    f"{config['cqhttp_api_url']}/send_private_msg",
                    json={
                        "user_id": user_id,
                        "message": approve_config["welcome_message"]
                    }
                )).start()
                return jsonify(status="ok")
            except Exception as e:
                logging.error(f"处理好友请求失败: {str(e)}")
                return jsonify(status="error"), 500
        return jsonify(status="ignored")

# ================= Flask路由 =================
bot = BotCore()

@app.route('/', methods=['POST'])
def handle_event():
    event = request.json
    if event.get('message_type') == 'group':
        return jsonify(status="ignored")
    
    message_id = event.get('message_id')
    if message_id and not bot.msg_processor.deduplicate_message(message_id):
        return jsonify(status="ignored")
    
    try:
        if event.get('post_type') == 'message':
            return handle_private_message(event)
        elif event.get('post_type') == 'request':
            return bot.handle_friend_request(event)
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
