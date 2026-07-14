// ========== Crypto helpers ==========
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const { subtle } = globalThis.crypto;

function b64decode(s) {
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}
function b64encode(b) {
  return btoa(String.fromCharCode(...new Uint8Array(b)));
}

async function sha1Hex(str) {
  const buf = await subtle.digest("SHA-1", textEncoder.encode(str));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function pkcs7Pad(data, blockSize) {
  const padLen = blockSize - (data.length % blockSize);
  const padded = new Uint8Array(data.length + padLen);
  padded.set(data);
  padded.fill(padLen, data.length);
  return padded;
}

function pkcs7Unpad(data) {
  const padLen = data[data.length - 1];
  if (padLen < 1 || padLen > 32) throw new Error("Invalid PKCS7 padding");
  for (let i = data.length - padLen; i < data.length; i++) {
    if (data[i] !== padLen) throw new Error("Invalid padding bytes");
  }
  return data.slice(0, data.length - padLen);
}

async function getAesCryptoKey(aesKeyBase64) {
  const raw = b64decode(aesKeyBase64);
  return subtle.importKey("raw", raw, { name: "AES-CBC" }, false, ["encrypt", "decrypt"]);
}

function getIv(aesKeyBase64) {
  return b64decode(aesKeyBase64).slice(0, 16);
}

async function wecomDecrypt(cipherBase64, aesKeyBase64) {
  const key = await getAesCryptoKey(aesKeyBase64);
  const iv = getIv(aesKeyBase64);
  const ciphertext = b64decode(cipherBase64);
  const decrypted = await subtle.decrypt({ name: "AES-CBC", iv }, key, ciphertext);
  const raw = pkcs7Unpad(new Uint8Array(decrypted));
  const contentLen = (raw[16] << 24) | (raw[17] << 16) | (raw[18] << 8) | raw[19];
  const content = textDecoder.decode(raw.slice(20, 20 + contentLen));
  const receiveId = textDecoder.decode(raw.slice(20 + contentLen));
  return { content, receiveId };
}

// ========== Helpers ==========
const env = (key) => process.env[key];
const sortJoin = (...items) => [...items].sort().join("");
const xmlGetTag = (xml, tag) => {
  const reg = new RegExp(`<${tag}[^>]*>(?:<!\\[CDATA\\[)?(.*?)(?:\\]\\]>)?<\\/${tag}>`, "s");
  const m = xml.match(reg);
  return m ? m[1].trim() : "";
};

// ========== WeCom API ==========
let cachedToken = null;
let tokenExpiresAt = 0;

async function getAccessToken() {
  if (cachedToken && Date.now() < tokenExpiresAt) return cachedToken;
  const resp = await fetch(
    "https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=" + env("WECOM_CORP_ID") + "&corpsecret=" + env("WECOM_SECRET")
  );
  const data = await resp.json();
  if (data.errcode !== 0) throw new Error("获取 token 失败: " + data.errmsg);
  cachedToken = data.access_token;
  tokenExpiresAt = Date.now() + (data.expires_in - 60) * 1000;
  return cachedToken;
}

async function sendTextMessage(toUser, content) {
  const token = await getAccessToken();
  const resp = await fetch(
    "https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=" + token,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        touser: toUser,
        msgtype: "text",
        agentid: env("WECOM_AGENT_ID"),
        text: { content },
        safe: 0,
      }),
    }
  );
  const data = await resp.json();
  if (data.errcode !== 0) throw new Error("发送消息失败: " + data.errmsg);
}

// ========== AI call ==========
async function callAI(messages) {
  const baseUrl = env("AI_BASE_URL") || "https://api.deepseek.com";
  const model = env("AI_MODEL") || "deepseek-chat";
  const resp = await fetch(baseUrl + "/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer " + env("AI_API_KEY"),
    },
    body: JSON.stringify({ model, messages, max_tokens: 2048, temperature: 0.7 }),
  });
  const data = await resp.json();
  if (data.error) throw new Error("AI API 错误: " + (data.error.message || JSON.stringify(data.error)));
  return data.choices?.[0]?.message?.content || "抱歉，我没有理解您的意思。";
}

// ========== HTTP Handlers ==========
async function handleVerification(url, res) {
  const msgSignature = url.searchParams.get("msg_signature");
  const timestamp = url.searchParams.get("timestamp");
  const nonce = url.searchParams.get("nonce");
  const echostr = url.searchParams.get("echostr");

  const sigStr = sortJoin(env("WECOM_TOKEN"), timestamp, nonce, echostr);
  const computedSig = await sha1Hex(sigStr);
  if (computedSig !== msgSignature) {
    res.writeHead(403);
    return res.end("签名验证失败");
  }

  const { content, receiveId } = await wecomDecrypt(echostr, env("WECOM_AES_KEY"));
  if (receiveId !== env("WECOM_CORP_ID")) {
    res.writeHead(403);
    return res.end("CorpID 不匹配");
  }

  res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8" });
  res.end(content);
}

async function handleMessage(url, req, res) {
  const msgSignature = url.searchParams.get("msg_signature");
  const timestamp = url.searchParams.get("timestamp");
  const nonce = url.searchParams.get("nonce");

  // Read request body
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(typeof chunk === "string" ? chunk : chunk.toString());
  }
  const body = chunks.join("");

  // Extract Encrypt from XML
  const encryptContent = xmlGetTag(body, "Encrypt");
  if (!encryptContent) {
    res.writeHead(400);
    return res.end("无效的 XML 格式");
  }

  // Verify signature
  const sigStr = sortJoin(env("WECOM_TOKEN"), timestamp, nonce, encryptContent);
  const computedSig = await sha1Hex(sigStr);
  if (computedSig !== msgSignature) {
    res.writeHead(403);
    return res.end("签名验证失败");
  }

  // Decrypt message
  const { content: decryptedXml, receiveId } = await wecomDecrypt(encryptContent, env("WECOM_AES_KEY"));
  if (receiveId !== env("WECOM_CORP_ID")) {
    res.writeHead(403);
    return res.end("CorpID 不匹配");
  }

  // Parse message
  const fromUser = xmlGetTag(decryptedXml, "FromUserName");
  const msgType = xmlGetTag(decryptedXml, "MsgType");
  const msgContent = xmlGetTag(decryptedXml, "Content");

  // Acknowledge WeCom immediately
  res.writeHead(200);
  res.end("");

  // Process AI reply in background
  if (msgType === "text" && msgContent && fromUser) {
    processReply(fromUser, msgContent).catch((err) => console.error("回复出错:", err));
  }
}

async function processReply(toUser, userMessage) {
  const systemPrompt =
    env("AI_SYSTEM_PROMPT") || "你是一个友好的微信助手，请用中文简洁地回答用户的问题。";

  const reply = await callAI([
    { role: "system", content: systemPrompt },
    { role: "user", content: userMessage },
  ]);

  await sendTextMessage(toUser, reply);
}

// ========== HTTP Server ==========
const http = require("http");
const port = parseInt(process.env.PORT || "3000", 10);

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://" + (req.headers.host || "localhost"));

    if (req.method === "GET") {
      return await handleVerification(url, res);
    } else if (req.method === "POST") {
      return await handleMessage(url, req, res);
    }

    res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("OK - WeCom AI Bot is running");
  } catch (err) {
    console.error("Unhandled error:", err);
    res.writeHead(500);
    res.end("Internal Error");
  }
});

server.listen(port, "0.0.0.0", () => {
  console.log("WeCom AI Bot server listening on port " + port);
});
