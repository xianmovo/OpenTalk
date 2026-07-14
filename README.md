# WeCom AI Bot（企业微信 AI 机器人）

部署在阿里云函数计算 (FC)，调用 DeepSeek API 实现 AI 对话。

## 架构

微信 → 企业微信 → 阿里云函数计算（处理消息 + AI 调用）→ 回复到微信

## 准备工作

1. 注册企业微信（已完成）
2. 创建自建应用，已拿到的参数：

   | 参数 | 值 |
   |------|-----|
   | CorpId | `ww826c49e00dbc7f3b` |
   | AgentId | `1000002` |
   | Secret | `qmWLiTrsKQVe_2NeuljsdQ93V9q_xr4aPaVyg2E_20w` |
   | Token | `wxOpenTalk37` |
   | EncodingAESKey | `SIUycU9NL68jtxtQBPi0Z87eLRlielGHk8pQGOo6GyW` |

## 部署到阿里云函数计算

### 第一步：创建函数

1. 打开 https://fc.console.aliyun.com/ → **服务及函数**
2. 创建 **服务**（如 `wecom-bot-service`）
3. 在服务下 **创建函数**
   - **运行环境**: Node.js 18 或 20
   - **函数代码**: 上传本项目的 `index.js`
   - **触发器类型**: **HTTP 触发器**
   - **认证方式**: 无需认证（默认）
4. 修改函数 **超时时间** 为 **30 秒**（默认 3 秒不够）

### 第二步：设置环境变量

在函数配置 → **环境变量** 中填入：

| 变量名 | 值 |
|--------|------|
| `WECOM_TOKEN` | `wxOpenTalk37` |
| `WECOM_AES_KEY` | `SIUycU9NL68jtxtQBPi0Z87eLRlielGHk8pQGOo6GyW` |
| `WECOM_CORP_ID` | `ww826c49e00dbc7f3b` |
| `WECOM_AGENT_ID` | `1000002` |
| `WECOM_SECRET` | `qmWLiTrsKQVe_2NeuljsdQ93V9q_xr4aPaVyg2E_20w` |
| `AI_API_KEY` | `sk-48f4466c09da4431af8ab32994ba5e78` |

### 第三步：发布上线

发布后，FC 会分配一个 **公网访问地址**，例如：
```
https://xxx.cn-shanghai.fc.aliyuncs.com/xxx/
```

### 第四步：配置企业微信回调

回到企业微信应用详情 → **接收消息** → **设置API接收**：

| 字段 | 值 |
|------|-----|
| **URL** | 上面拿到的 FC 地址 |
| **Token** | `wxOpenTalk37` |
| **EncodingAESKey** | `SIUycU9NL68jtxtQBPi0Z87eLRlielGHk8pQGOo6GyW` |

保存验证成功后即可在手机企业微信中发送消息聊天。

## 本地测试

```bash
node -e "
const event = JSON.stringify({
  method: 'GET',
  queryParameters: {
    msg_signature: 'xxx',
    timestamp: 'xxx',
    nonce: 'xxx',
    echostr: 'xxx'
  }
});
// 然后用这个 event 调用 handler
"
```

## 项目文件

| 文件 | 说明 |
|------|------|
| `index.js` | 阿里云函数计算入口（主文件） |
| `src/worker.js` | Cloudflare Worker 版本（存档） |
| `api/wecom.js` | Vercel 版本（存档） |
| `package.json` | 项目信息 |
