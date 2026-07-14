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
    `https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=${env("WECOM_CORP_ID")}&corpsecret=${env("WECOM_SECRET")}`
  );
  const data = await resp.json();
  if (data.errcode !== 0) throw new Error(`鑾峰彇 token 澶辫触: ${data.errmsg}`);
  cachedToken = data.access_token;
  tokenExpiresAt = Date.now() + (data.expires_in - 60) * 1000;
  return cachedToken;
}

async function sendTextMessage(toUser, content) {
  const token = await getAccessToken();
  const resp = await fetch(
    `https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=${token}`,
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
  if (data.errcode !== 0) throw new Error(`鍙戦€佹秷鎭け璐? ${data.errmsg}`);
}

// ========== AI call ==========
async function callAI(messages) {
  const baseUrl = env("AI_BASE_URL") || "https://api.deepseek.com";
  const model = env("AI_MODEL") || "deepseek-chat";
  const resp = await fetch(`${baseUrl}/chat/completions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${env("AI_API_KEY")}`,
    },
    body: JSON.stringify({ model, messages, max_tokens: 2048, temperature: 0.7 }),
  });
  const data = await resp.json();
  if (data.error) throw new Error(`AI API 閿欒: ${data.error.message || JSON.stringify(data.error)}`);
  return data.choices?.[0]?.message?.content || "鎶辨瓑锛屾垜娌℃湁鐞嗚В鎮ㄧ殑鎰忔€濄€?;
}

// ========== Handlers ==========
async function handleVerification(url, res) {
  const msgSignature = url.searchParams.get("msg_signature");
  const timestamp = url.searchParams.get("timestamp");
  const nonce = url.searchParams.get("nonce");
  const echostr = url.searchParams.get("echostr");

  const sigStr = sortJoin(env("WECOM_TOKEN"), timestamp, nonce, echostr);
  const computedSig = await sha1Hex(sigStr);
  if (computedSig !== msgSignature) {
    console.error("绛惧悕楠岃瘉澶辫触");
    return res.status(403).end("绛惧悕楠岃瘉澶辫触");
  }

  const { content, receiveId } = await wecomDecrypt(echostr, env("WECOM_AES_KEY"));
  if (receiveId !== env("WECOM_CORP_ID")) {
    console.error("CorpID 涓嶅尮閰?);
    return res.status(403).end("CorpID 涓嶅尮閰?);
  }

  res.status(200).end(content);
}

async function handleMessage(req, url, res) {
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
    return res.status(400).end("鏃犳晥鐨?XML");
  }

  // Verify signature
  const sigStr = sortJoin(env("WECOM_TOKEN"), timestamp, nonce, encryptContent);
  const computedSig = await sha1Hex(sigStr);
  if (computedSig !== msgSignature) {
    return res.status(403).end("绛惧悕楠岃瘉澶辫触");
  }

  // Decrypt message
  const { content: decryptedXml, receiveId } = await wecomDecrypt(encryptContent, env("WECOM_AES_KEY"));
  if (receiveId !== env("WECOM_CORP_ID")) {
    return res.status(403).end("CorpID 涓嶅尮閰?);
  }

  // Parse message
  const fromUser = xmlGetTag(decryptedXml, "FromUserName");
  const msgType = xmlGetTag(decryptedXml, "MsgType");
  const msgContent = xmlGetTag(decryptedXml, "Content");

  // Acknowledge WeCom immediately
  res.status(200).end("");

  // Process reply asynchronously
  if (msgType === "text" && msgContent && fromUser) {
    handleReply(fromUser, msgContent).catch((err) => console.error("鍥炲鍑洪敊:", err));
  }
}

async function handleReply(toUser, userMessage) {
  const systemPrompt =
    env("AI_SYSTEM_PROMPT") || "浣犳槸涓€涓弸濂界殑寰俊鍔╂墜锛岃鐢ㄤ腑鏂囩畝娲佸湴鍥炵瓟鐢ㄦ埛鐨勯棶棰樸€?;

  const reply = await callAI([
    { role: "system", content: systemPrompt },
    { role: "user", content: userMessage },
  ]);

  await sendTextMessage(toUser, reply);
}

// ========== Vercel entry ==========
module.exports = async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);

    if (req.method === "GET") {
      return await handleVerification(url, res);
    } else if (req.method === "POST") {
      return await handleMessage(req, url, res);
    }

    res.status(200).end("OK");
  } catch (err) {
    console.error("Unhandled error:", err);
    res.status(500).end("Internal Error");
  }
};
