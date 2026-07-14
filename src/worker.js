// ========== Crypto helpers ==========
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function b64decode(s) {
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}
function b64encode(b) {
  return btoa(String.fromCharCode(...new Uint8Array(b)));
}

async function sha1Hex(str) {
  const buf = await crypto.subtle.digest("SHA-1", textEncoder.encode(str));
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
  return crypto.subtle.importKey("raw", raw, { name: "AES-CBC" }, false, ["encrypt", "decrypt"]);
}

function getIv(aesKeyBase64) {
  return b64decode(aesKeyBase64).slice(0, 16);
}

async function wecomDecrypt(cipherBase64, aesKeyBase64) {
  const key = await getAesCryptoKey(aesKeyBase64);
  const iv = getIv(aesKeyBase64);
  const ciphertext = b64decode(cipherBase64);

  const decrypted = await crypto.subtle.decrypt({ name: "AES-CBC", iv }, key, ciphertext);
  const raw = pkcs7Unpad(new Uint8Array(decrypted));

  // 16B random + 4B content length (big-endian) + content + receiveId
  const contentLen = (raw[16] << 24) | (raw[17] << 16) | (raw[18] << 8) | raw[19];
  const content = textDecoder.decode(raw.slice(20, 20 + contentLen));
  const receiveId = textDecoder.decode(raw.slice(20 + contentLen));
  return { content, receiveId };
}

async function wecomEncrypt(xmlContent, aesKeyBase64, receiveId) {
  const key = await getAesCryptoKey(aesKeyBase64);
  const iv = getIv(aesKeyBase64);

  const randomBytes = crypto.getRandomValues(new Uint8Array(16));
  const contentBytes = textEncoder.encode(xmlContent);
  const idBytes = textEncoder.encode(receiveId);

  const lenBytes = new Uint8Array(4);
  lenBytes[0] = (contentBytes.length >> 24) & 0xff;
  lenBytes[1] = (contentBytes.length >> 16) & 0xff;
  lenBytes[2] = (contentBytes.length >> 8) & 0xff;
  lenBytes[3] = contentBytes.length & 0xff;

  const toEncrypt = new Uint8Array([...randomBytes, ...lenBytes, ...contentBytes, ...idBytes]);
  const padded = pkcs7Pad(toEncrypt, 32);

  const encrypted = await crypto.subtle.encrypt({ name: "AES-CBC", iv }, key, padded);
  return b64encode(new Uint8Array(encrypted));
}

// ========== Signature ==========
function sortJoin(...items) {
  return [...items].sort().join("");
}

// ========== Simple XML parser for WeCom format ==========
function xmlGetTag(xml, tag) {
  const reg = new RegExp(`<${tag}[^>]*>(?:<!\\[CDATA\\[)?(.*?)(?:\\]\\]>)?<\\/${tag}>`, "s");
  const m = xml.match(reg);
  return m ? m[1].trim() : "";
}

// ========== WeCom API ==========
let cachedToken = null;
let tokenExpiresAt = 0;

async function getAccessToken(corpId, secret) {
  if (cachedToken && Date.now() < tokenExpiresAt) return cachedToken;
  const resp = await fetch(
    `https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=${corpId}&corpsecret=${secret}`
  );
  const data = await resp.json();
  if (data.errcode !== 0) throw new Error(`获取 token 失败: ${data.errmsg}`);
  cachedToken = data.access_token;
  tokenExpiresAt = Date.now() + (data.expires_in - 60) * 1000;
  return cachedToken;
}

async function sendTextMessage(accessToken, agentId, toUser, content) {
  const resp = await fetch(
    `https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=${accessToken}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        touser: toUser,
        msgtype: "text",
        agentid: agentId,
        text: { content },
        safe: 0,
      }),
    }
  );
  const data = await resp.json();
  if (data.errcode !== 0) throw new Error(`发送消息失败: ${data.errmsg}`);
  return data;
}

// ========== AI call ==========
async function callAI(apiKey, baseUrl, model, messages) {
  const resp = await fetch(`${baseUrl}/chat/completions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model,
      messages,
      max_tokens: 2048,
      temperature: 0.7,
    }),
  });
  const data = await resp.json();
  if (data.error)
    throw new Error(`AI API 错误: ${data.error.message || JSON.stringify(data.error)}`);
  return data.choices?.[0]?.message?.content || "抱歉，我没有理解您的意思。";
}

// ========== Handle verification (GET) ==========
async function handleVerification(request, env) {
  const url = new URL(request.url);
  const msgSignature = url.searchParams.get("msg_signature");
  const timestamp = url.searchParams.get("timestamp");
  const nonce = url.searchParams.get("nonce");
  const echostr = url.searchParams.get("echostr");

  const sigStr = sortJoin(env.WECOM_TOKEN, timestamp, nonce, echostr);
  const computedSig = await sha1Hex(sigStr);
  if (computedSig !== msgSignature) {
    return new Response("签名验证失败", { status: 403 });
  }

  const { content, receiveId } = await wecomDecrypt(echostr, env.WECOM_AES_KEY);
  if (receiveId !== env.WECOM_CORP_ID) {
    return new Response("CorpID 不匹配", { status: 403 });
  }

  return new Response(content);
}

// ========== Handle messages (POST) ==========
async function handleMessage(request, env, ctx) {
  const url = new URL(request.url);
  const msgSignature = url.searchParams.get("msg_signature");
  const timestamp = url.searchParams.get("timestamp");
  const nonce = url.searchParams.get("nonce");

  const body = await request.text();

  // Extract Encrypt from XML
  const encryptContent = xmlGetTag(body, "Encrypt");
  if (!encryptContent) {
    return new Response("无效的 XML 格式", { status: 400 });
  }

  // Verify signature
  const sigStr = sortJoin(env.WECOM_TOKEN, timestamp, nonce, encryptContent);
  const computedSig = await sha1Hex(sigStr);
  if (computedSig !== msgSignature) {
    return new Response("签名验证失败", { status: 403 });
  }

  // Decrypt message
  const { content: decryptedXml, receiveId } = await wecomDecrypt(encryptContent, env.WECOM_AES_KEY);
  if (receiveId !== env.WECOM_CORP_ID) {
    return new Response("CorpID 不匹配", { status: 403 });
  }

  // Parse decrypted XML fields
  const fromUser = xmlGetTag(decryptedXml, "FromUserName");
  const msgType = xmlGetTag(decryptedXml, "MsgType");
  const msgContent = xmlGetTag(decryptedXml, "Content");

  // Only handle text messages
  if (msgType === "text" && msgContent && fromUser) {
    ctx.waitUntil(handleReply(env, fromUser, msgContent));
  }

  // Return success immediately
  return new Response("");
}

async function handleReply(env, toUser, userMessage) {
  try {
    const aiBaseUrl = env.AI_BASE_URL || "https://api.openai.com/v1";
    const aiModel = env.AI_MODEL || "gpt-4o-mini";
    const systemPrompt =
      env.AI_SYSTEM_PROMPT || "你是一个友好的微信助手，请用中文简洁地回答用户的问题。";

    const reply = await callAI(env.AI_API_KEY, aiBaseUrl, aiModel, [
      { role: "system", content: systemPrompt },
      { role: "user", content: userMessage },
    ]);

    const accessToken = await getAccessToken(env.WECOM_CORP_ID, env.WECOM_SECRET);
    await sendTextMessage(accessToken, env.WECOM_AGENT_ID, toUser, reply);
  } catch (err) {
    console.error("回复出错:", err);
    try {
      const accessToken = await getAccessToken(env.WECOM_CORP_ID, env.WECOM_SECRET);
      await sendTextMessage(
        accessToken,
        env.WECOM_AGENT_ID,
        toUser,
        "抱歉，我暂时无法回复，请稍后再试。"
      );
    } catch (e) {
      console.error("发送错误通知失败:", e);
    }
  }
}

// ========== Worker entry ==========
export default {
  async fetch(request, env, ctx) {
    if (request.method === "GET") {
      return handleVerification(request, env);
    } else if (request.method === "POST") {
      return handleMessage(request, env, ctx);
    }
    return new Response("OK", { status: 200 });
  },
};
