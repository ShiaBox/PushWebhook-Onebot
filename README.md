# PushWebhook-Onebot
通过Onebot v11获取并推送QQ私聊信息到企业微信、钉钉、飞书Webhook机器人，起到提醒和通知功能。

目前飞书部分受限于官方接口上传图片的模式，暂时不可用。

## 使用方法

克隆源码

```
git clone https://github.com/ShiaBox/PushWebhook-Onebot.git
cd PushWebhook-Onebot
```

安装依赖

```
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
```
为OneBot登录端设置HTTP Server和HTTP Client （略）

修改配置文件

```
{
  "cqhttp_api_url": "http://127.0.0.1:5700", //登录端的 HTTP Server 地址
  "port": 7788, //本服务要开启的端口，需要去登录端的 HTTP Client 里填入
  "image_placeholder": "[图片]", //图片占位符，发消息的时候如果包含图片，就会在文字推送中以[图片]占位
  "auto_approve_friend": {
    "enable": true, //是否自动通过好友申请
    "keywords": ["希亚", "骰"], //根据关键字自动通过好友申请
    "welcome_message": "这是由程序自动通过的好友请求，有事请留言！" //添加好友后自动发送的留言
  },
  "message_id_expiry": 10, //防止风怒
  "auto_reply": {
    "test_command": "希亚", //测试指令
    "response": "自动回复机器人在线中。" //测试回复
  },
  "push_channels": [
    {
      "type": "wechat_work", //企业微信渠道
      "enable": true, //是否开启
      "split_images": false, //是否开启分段发送，开启后图和文字会按顺序一条一条推送。关闭多图文混排消息后会合并成一条文字消息发送，其余图片顺序发送。
      "webhook_url": "https://qyapi.weixin.qq.com/cgi-bin/webhook/send",
      "key": "YOUR_KEY"
    },
    {
      "type": "feishu",
      "enable": true,
      "split_images": true,
      "webhook_url": "https://open.feishu.cn/open-apis/bot/v2/hook",
      "key": "YOUR_KEY",
      "sign_secret": "YOUR_SIGN_SECRET", //选择加签验证时填写，为空则忽略，建议使用
      "app_id": "YOUR_APP_ID", //自定义机器人没有这个玩意儿，所以不能发图，只写了图片上传方式，没写自定义机器人怎么办，很无语
      "app_secret": "YOUR_APP_SECERT"
    },
    {
      "type": "dingtalk",
      "enable": true,
      "split_images": false, //是否开启分段发送，开启后图和文字会按顺序一条一条推送。钉钉支持markdown图文混排，很不错，如果关闭此选项就能直接一条消息全推送过去。
      "webhook_url": "https://oapi.dingtalk.com/robot/send",
      "key": "YOUR_KEY",
      "sign_secret": "YOUR_SIGN_SECRET" //选择加签验证时填写，为空则忽略，建议使用
    }
  ]
}
```

运行

```
python pwob.py
```
