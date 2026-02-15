/**
 * Multi-Purpose QR Code System
 * 多功能二维码管理系统
 * 
 * 核心功能：
 * 1. 普通二维码 /n/:id - 展示公开信息
 * 2. 授权二维码 /a/:id - 需授权查看私密信息
 * 3. 联系二维码 /c/:id - 实时聊天通讯
 * 4. 实时通知：WebSocket + 美化弹窗
 * 5. 富文本支持：Markdown + HTML + 图片上传
 * 6. 二维码可编辑：内容可更新，链接不变
 */

// ==================== 通用样式 ====================

/**
 * 通用CSS样式 - 避免在每个页面重复定义
 */
function getCommonStyles(gradientColors = '#667eea 0%, #764ba2 100%') {
  return `
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: linear-gradient(135deg, ${gradientColors});
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .card {
      background: white;
      border-radius: 16px;
      padding: 40px;
      max-width: 600px;
      width: 100%;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
    }
    .card > h1 { font-size: 28px; margin-bottom: 24px; color: #333; text-align: center; }
    .content { font-size: 16px; line-height: 1.8; color: #555; }
    .content img { max-width: 100%; border-radius: 12px; margin: 20px 0; }
    .content h1 { font-size: 26px; margin-top: 32px; margin-bottom: 16px; color: #333; text-align: left; font-weight: 600; }
    .content h2 { font-size: 22px; margin-top: 28px; margin-bottom: 14px; color: #333; text-align: left; font-weight: 600; }
    .content h3 { font-size: 18px; margin-top: 24px; margin-bottom: 12px; color: #333; text-align: left; font-weight: 600; }
    .content h4 { font-size: 16px; margin-top: 20px; margin-bottom: 10px; color: #333; text-align: left; font-weight: 600; }
    .content p { margin-bottom: 16px; }
    .content pre { background: #f5f7fa; padding: 16px; border-radius: 8px; overflow-x: auto; }
    .content code { background: #f5f7fa; padding: 2px 6px; border-radius: 4px; font-family: monospace; }
    .content ul, .content ol { margin-left: 24px; margin-bottom: 16px; }
    .content li { margin-bottom: 8px; }
    .content a { color: #667eea; text-decoration: none; }
    .content a:hover { text-decoration: underline; }
    .content blockquote { border-left: 4px solid #667eea; padding-left: 16px; margin: 16px 0; color: #666; font-style: italic; }
    .image-container { text-align: center; margin: 24px 0; }
    .image-container img { max-width: 100%; border-radius: 12px; }
    .btn { display: inline-block; padding: 12px 24px; border-radius: 8px; font-size: 16px; font-weight: 600; text-align: center; cursor: pointer; border: none; transition: all 0.3s; }
    .btn-primary { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }
    .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4); }
    .btn-secondary { background: #e0e0e0; color: #333; }
    .btn-secondary:hover { background: #d0d0d0; }
    .status { padding: 12px 16px; border-radius: 8px; margin-bottom: 20px; font-size: 14px; border: 2px solid; text-align: center; }
  `;
}

// ==================== 工具函数 ====================

/**
 * 生成 HMAC 签名的 Token
 * @param {Object} payload - 载荷数据
 * @param {string} secret - 密钥
 * @returns {Promise<string>} - Base64 编码的 Token
 */
async function createToken(payload, secret) {
  const data = JSON.stringify(payload);
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    encoder.encode(data)
  );
  
  const token = {
    payload,
    signature: arrayBufferToBase64(signature)
  };
  
  return btoa(JSON.stringify(token));
}

/**
 * 验证 HMAC 签名的 Token
 * @param {string} tokenStr - Base64 编码的 Token
 * @param {string} secret - 密钥
 * @param {number} maxAge - 最大有效期（秒）
 * @returns {Promise<Object|null>} - 验证成功返回 payload，失败返回 null
 */
async function verifyToken(tokenStr, secret, maxAge = 3600) {
  try {
    const token = JSON.parse(atob(tokenStr));
    const { payload, signature } = token;
    
    // 检查时间戳
    if (Date.now() - payload.timestamp > maxAge * 1000) {
      return null; // Token 已过期
    }
    
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    
    const isValid = await crypto.subtle.verify(
      'HMAC',
      key,
      base64ToArrayBuffer(signature),
      encoder.encode(JSON.stringify(payload))
    );
    
    return isValid ? payload : null;
  } catch (e) {
    return null;
  }
}

/**
 * ArrayBuffer 转 Base64
 */
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Base64 转 ArrayBuffer
 */
function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * 生成随机 ID
 */
function generateId(prefix = 'item') {
  return `${prefix}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * 记录操作日志
 */
async function logActivity(env, itemId, type, metadata = {}) {
  const logKey = `logs:${itemId}`;
  let logs = [];
  
  try {
    const existing = await env.ASSET_KV.get(logKey, 'json');
    if (existing) logs = existing;
  } catch (e) {
    // 忽略错误，使用空数组
  }
  
  logs.push({
    ts: Date.now(),
    type,
    ...metadata
  });
  
  // 只保留最近 1000 条日志
  if (logs.length > 1000) {
    logs = logs.slice(-1000);
  }
  
  await env.ASSET_KV.put(logKey, JSON.stringify(logs));
}

/**
 * 获取客户端真实 IP
 */
function getClientIP(request) {
  return request.headers.get('CF-Connecting-IP') || 
         request.headers.get('X-Real-IP') || 
         'unknown';
}

/**
 * 获取地理位置信息
 */
function getGeoInfo(request) {
  const country = request.cf?.country || 'unknown';
  const city = request.cf?.city || 'unknown';
  const timezone = request.cf?.timezone || 'unknown';
  
  return { country, city, timezone };
}

/**
 * 模板变量替换引擎
 * @param {string} template - 包含 {{variable}} 的模板字符串
 * @param {object} data - 变量数据对象
 * @returns {string} - 替换后的字符串
 */
function replaceTemplateVariables(template, data) {
  if (!template) return '';
  
  let result = template;
  
  // 替换所有 {{variable}} 格式的变量
  for (const [key, value] of Object.entries(data)) {
    const regex = new RegExp('\\{\\{' + key + '\\}\\}', 'g');
    result = result.replace(regex, String(value || ''));
  }
  
  return result;
}

// ==================== Durable Object: 连接管理器 ====================

export class ConnectionManager {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.sessions = new Map(); // sessionId -> WebSocket
    this.adminSessions = new Set(); // 管理员连接的 sessionId
  }

  async fetch(request) {
    const url = new URL(request.url);

    // WebSocket 升级
    if (request.headers.get('Upgrade') === 'websocket') {
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);

      await this.handleSession(server, request);

      return new Response(null, {
        status: 101,
        webSocket: client,
      });
    }

    // 获取在线状态
    if (url.pathname === '/status') {
      return new Response(JSON.stringify({
        total: this.sessions.size,
        admin: this.adminSessions.size,
        hasAdmin: this.adminSessions.size > 0
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 广播消息（供 Worker 调用）
    if (url.pathname === '/broadcast' && request.method === 'POST') {
      const message = await request.json();
      this.broadcast(message, message.to);
      return new Response('OK');
    }

    return new Response('Not found', { status: 404 });
  }

  async handleSession(websocket, request) {
    websocket.accept();

    const sessionId = crypto.randomUUID();
    this.sessions.set(sessionId, websocket);
    
    // 心跳机制：定期检测连接是否存活
    const heartbeatInterval = setInterval(() => {
      try {
        websocket.send(JSON.stringify({ type: 'ping', timestamp: Date.now() }));
      } catch (e) {
        console.log('Heartbeat failed for session ' + sessionId + ', cleaning up');
        clearInterval(heartbeatInterval);
        
        const wasAdmin = this.adminSessions.has(sessionId);
        this.sessions.delete(sessionId);
        this.adminSessions.delete(sessionId);
        
        if (wasAdmin && this.adminSessions.size === 0) {
          this.broadcast({
            type: 'admin_status_changed',
            isOnline: false
          }, 'user');
        }
      }
    }, 30000); // 每30秒发送一次心跳

    websocket.addEventListener('message', async (msg) => {
      try {
        const data = JSON.parse(msg.data);

        // 注册为管理员连接
        if (data.type === 'register_admin') {
          this.adminSessions.add(sessionId);
          websocket.send(JSON.stringify({
            type: 'registered',
            role: 'admin',
            sessionId
          }));
          
          // 广播管理员上线状态
          this.broadcast({
            type: 'admin_status_changed',
            isOnline: true
          }, 'user');
        }

        // 转发消息
        if (data.type === 'broadcast') {
          this.broadcast(data.payload, data.to);
        }

        // 审批决策（在线模式）
        if (data.type === 'approval_decision') {
          this.broadcast({
            type: 'approval_result',
            ...data.payload
          }, 'user');
        }

        // 聊天消息转发
        if (data.type === 'chat_message') {
          // 转发消息
          this.broadcast({
            type: 'chat_message',
            ...data.payload
          }, data.to || 'all');
          
          // 保存聊天消息到KV（通过环境变量）
          if (data.payload.qrId && data.payload.sessionId) {
            try {
              await this.saveChatMessage(data.payload);
            } catch (e) {
              console.error('Failed to save chat message:', e);
            }
          }
        }

        // 聊天请求决策
        if (data.type === 'chat_request_decision') {
          this.broadcast({
            type: 'chat_request_result',
            ...data.payload
          }, 'user');
        }
      } catch (e) {
        console.error('WebSocket message error:', e);
      }
    });

    websocket.addEventListener('close', () => {
      clearInterval(heartbeatInterval);
      
      const wasAdmin = this.adminSessions.has(sessionId);
      this.sessions.delete(sessionId);
      this.adminSessions.delete(sessionId);
      
      console.log('WebSocket closed. Session: ' + sessionId + ', Was admin: ' + wasAdmin + ', Remaining admins: ' + this.adminSessions.size);
      
      // 如果是管理员断开且没有其他管理员在线，立即广播离线状态
      if (wasAdmin && this.adminSessions.size === 0) {
        console.log('Last admin disconnected, broadcasting offline status');
        this.broadcast({
          type: 'admin_status_changed',
          isOnline: false
        }, 'user');
      }
    });

    websocket.addEventListener('error', (error) => {
      clearInterval(heartbeatInterval);
      
      console.error('WebSocket error for session ' + sessionId + ':', error);
      const wasAdmin = this.adminSessions.has(sessionId);
      this.sessions.delete(sessionId);
      this.adminSessions.delete(sessionId);
      
      // 错误时也广播离线状态
      if (wasAdmin && this.adminSessions.size === 0) {
        console.log('Admin disconnected due to error, broadcasting offline status');
        this.broadcast({
          type: 'admin_status_changed',
          isOnline: false
        }, 'user');
      }
    });
  }

  /**
   * 广播消息
   * @param {Object} message - 消息内容
   * @param {string} target - 目标：'admin' | 'user' | 'all'
   */
  broadcast(message, target = 'all') {
    const msg = JSON.stringify(message);

    for (const [sessionId, ws] of this.sessions.entries()) {
      try {
        if (target === 'all') {
          ws.send(msg);
        } else if (target === 'admin' && this.adminSessions.has(sessionId)) {
          ws.send(msg);
        } else if (target === 'user' && !this.adminSessions.has(sessionId)) {
          ws.send(msg);
        }
      } catch (e) {
        // 连接已关闭，清理
        this.sessions.delete(sessionId);
        this.adminSessions.delete(sessionId);
      }
    }
  }

  /**
   * 保存聊天消息到KV
   */
  async saveChatMessage(payload) {
    const { qrId, sessionId, from, message, imageUrl, timestamp } = payload;
    
    try {
      // 获取现有聊天数据
      let chatData = await this.env.ASSET_KV.get(`chat:${qrId}`, 'json') || { sessions: {} };
      chatData.sessions = chatData.sessions || {};
      
      if (!chatData.sessions[sessionId]) {
        chatData.sessions[sessionId] = {
          accepted: true,
          messages: [],
          startedAt: Date.now()
        };
      }
      
      // 添加新消息
      chatData.sessions[sessionId].messages.push({
        from,
        message,
        imageUrl,
        timestamp: timestamp || Date.now()
      });
      
      // 保存回KV
      await this.env.ASSET_KV.put(`chat:${qrId}`, JSON.stringify(chatData));
    } catch (e) {
      console.error('Save chat message error:', e);
    }
  }
}

// ==================== 主 Worker ====================

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // CORS 处理
      if (request.method === 'OPTIONS') {
        return new Response(null, {
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
          }
        });
      }

      // WebSocket 连接
      if (path === '/ws') {
        const id = env.CONNECTION_MANAGER.idFromName('global');
        const stub = env.CONNECTION_MANAGER.get(id);
        return stub.fetch(request);
      }

      // WebSocket 状态查询
      if (path === '/ws/status') {
        const id = env.CONNECTION_MANAGER.idFromName('global');
        const stub = env.CONNECTION_MANAGER.get(id);
        return stub.fetch(new Request('http://internal/status'));
      }

      // 后台管理页面
      if (path === '/admin') {
        return handleAdmin(request, env);
      }

      // 管理 API
      if (path.startsWith('/api/admin')) {
        return handleAdminAPI(request, env);
      }

      // 普通二维码入口
      if (path.startsWith('/n/')) {
        const qrId = path.split('/')[2];
        return handleNormalQR(request, env, qrId);
      }

      // 授权二维码入口
      if (path.startsWith('/a/')) {
        const qrId = path.split('/')[2];
        return handleAuthQR(request, env, qrId);
      }

      // 授权申请API（用户点击申请按钮调用）
      if (path === '/api/request-auth' && request.method === 'POST') {
        return handleAuthRequest(request, env);
      }

      // 聊天请求API（用户发送初始消息）
      if (path === '/api/request-chat' && request.method === 'POST') {
        return handleChatRequest(request, env);
      }

      // 联系二维码入口
      if (path.startsWith('/c/')) {
        const qrId = path.split('/')[2];
        return handleContactQR(request, env, qrId);
      }

      // 审批回调
      if (path === '/approve') {
        return handleApproval(request, env);
      }

      // 聊天请求回调
      if (path === '/chat-decision') {
        return handleChatDecision(request, env);
      }

      // 图片上传
      if (path === '/api/upload') {
        return handleImageUpload(request, env);
      }

      // 获取上传的图片
      if (path.startsWith('/api/image/')) {
        const imageId = path.split('/')[3];
        const imageData = await env.ASSET_KV.get(`img:${imageId}`, 'json');
        
        if (!imageData) {
          return new Response('Image not found', { status: 404 });
        }
        
        const imageBuffer = base64ToArrayBuffer(imageData.data);
        return new Response(imageBuffer, {
          headers: {
            'Content-Type': imageData.contentType,
            'Cache-Control': 'public, max-age=31536000'
          }
        });
      }

      // 静态资源（二维码生成）
      if (path === '/qr') {
        return handleQRCode(request, env);
      }

      return new Response('Not Found', { status: 404 });

    } catch (error) {
      console.error('Worker error:', error);
      return new Response('Internal Server Error: ' + error.message, { 
        status: 500 
      });
    }
  }
};

// ==================== 路由处理函数 ====================

/**
 * 后台管理页面
 */
async function handleAdmin(request, env) {
  // 简单的 Session 验证
  const cookie = request.headers.get('Cookie') || '';
  const hasSession = cookie.includes('admin_session=');

  if (!hasSession && request.method === 'GET') {
    return new Response(getLoginPage(), {
      headers: { 'Content-Type': 'text/html;charset=UTF-8' }
    });
  }

  if (request.method === 'POST') {
    const formData = await request.formData();
    const password = formData.get('password');

    if (password === env.ADMIN_PASSWORD) {
      const sessionToken = await createToken(
        { type: 'admin_session', timestamp: Date.now() },
        env.ADMIN_PASSWORD
      );

      // 使用 PRG 模式：POST后重定向到GET
      return new Response(null, {
        status: 302,
        headers: {
          'Location': '/admin',
          'Set-Cookie': `admin_session=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`
        }
      });
    } else {
      return new Response(getLoginPage('密码错误'), {
        headers: { 'Content-Type': 'text/html;charset=UTF-8' },
        status: 401
      });
    }
  }

  return new Response(getAdminDashboard(), {
    headers: { 'Content-Type': 'text/html;charset=UTF-8' }
  });
}

/**
 * 管理 API 处理
 */
async function handleAdminAPI(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  // 验证管理员权限
  const cookie = request.headers.get('Cookie') || '';
  if (!cookie.includes('admin_session=')) {
    return new Response('Unauthorized', { status: 401 });
  }

  // 列出所有二维码
  if (path === '/api/admin/qrcodes' && request.method === 'GET') {
    const list = await env.ASSET_KV.list({ prefix: 'qr:' });
    const qrcodes = [];

    for (const key of list.keys) {
      const qr = await env.ASSET_KV.get(key.name, 'json');
      if (qr) {
        qrcodes.push({ id: key.name.replace('qr:', ''), ...qr });
      }
    }

    return jsonResponse(qrcodes);
  }

  // 创建新二维码
  if (path === '/api/admin/qrcodes' && request.method === 'POST') {
    const data = await request.json();
    
    // 普通二维码：保存到KV
    const qrId = generateId('qr');
    
    const qrcode = {
      title: data.title || '未命名二维码',
      type: data.type || 'normal', // normal | auth | contact
      content: data.content || '',
      privateContent: data.privateContent || '', // 仅用于授权码
      image: data.image || '',
      created_at: Date.now(),
      updated_at: Date.now()
    };

    await env.ASSET_KV.put(`qr:${qrId}`, JSON.stringify(qrcode));
    await logActivity(env, qrId, 'created', { creator: 'admin' });

    return jsonResponse({ id: qrId, ...qrcode });
  }

  // 更新二维码
  if (path.match(/^\/api\/admin\/qrcodes\/[^/]+$/) && request.method === 'PUT') {
    const qrId = path.split('/').pop();
    const data = await request.json();
    
    const existing = await env.ASSET_KV.get(`qr:${qrId}`, 'json');
    if (!existing) {
      return new Response('QR code not found', { status: 404 });
    }

    const updated = {
      ...existing,
      ...data,
      updated_at: Date.now()
    };

    await env.ASSET_KV.put(`qr:${qrId}`, JSON.stringify(updated));
    await logActivity(env, qrId, 'updated', { editor: 'admin' });

    return jsonResponse(updated);
  }

  // 删除二维码
  if (path.match(/^\/api\/admin\/qrcodes\/[^/]+$/) && request.method === 'DELETE') {
    const qrId = path.split('/').pop();
    await env.ASSET_KV.delete(`qr:${qrId}`);
    await env.ASSET_KV.delete(`logs:${qrId}`);
    await env.ASSET_KV.delete(`chat:${qrId}`);
    
    return jsonResponse({ success: true });
  }

  // 获取日志
  if (path.match(/^\/api\/admin\/qrcodes\/[^/]+\/logs$/) && request.method === 'GET') {
    const qrId = path.split('/')[4];
    const logs = await env.ASSET_KV.get(`logs:${qrId}`, 'json') || [];
    
    return jsonResponse(logs);
  }

  // 获取聊天记录
  if (path.match(/^\/api\/admin\/qrcodes\/[^/]+\/chat$/) && request.method === 'GET') {
    const qrId = path.split('/')[4];
    const chat = await env.ASSET_KV.get(`chat:${qrId}`, 'json') || { messages: [] };
    
    return jsonResponse(chat);
  }

  // 获取聊天请求信息
  if (path.match(/^\/api\/admin\/chat-request\/[^/]+$/) && request.method === 'GET') {
    const sessionId = path.split('/')[4];
    const requestData = await env.ASSET_KV.get(`chat_request:${sessionId}`, 'json');
    
    if (!requestData) {
      return jsonResponse({ error: 'Request not found' }, 404);
    }
    
    return jsonResponse(requestData);
  }

  // 删除聊天记录
  if (path.match(/^\/api\/admin\/qrcodes\/[^/]+\/chat\/[^/]+$/) && request.method === 'DELETE') {
    const qrId = path.split('/')[4];
    const sessionId = path.split('/')[6];
    
    const chatData = await env.ASSET_KV.get(`chat:${qrId}`, 'json') || { sessions: {} };
    
    if (chatData.sessions && chatData.sessions[sessionId]) {
      delete chatData.sessions[sessionId];
      await env.ASSET_KV.put(`chat:${qrId}`, JSON.stringify(chatData));
    }
    
    return jsonResponse({ success: true });
  }

  // 获取系统配置
  if (path === '/api/admin/config' && request.method === 'GET') {
    const config = await env.ASSET_KV.get('config:system', 'json') || {
      base_url: '',
      hmac_secret: '',
      qywx_webhook: ''
    };
    
    return jsonResponse(config);
  }

  // 更新系统配置
  if (path === '/api/admin/config' && request.method === 'PUT') {
    const config = await request.json();
    await env.ASSET_KV.put('config:system', JSON.stringify(config));
    
    return jsonResponse(config);
  }

  // 测试通知
  if (path === '/api/admin/test-notification' && request.method === 'POST') {
    const config = await request.json();
    
    const testData = {
      qrId: 'test_qr',
      requestId: 'test_request',
      qrTitle: '测试二维码',
      token: 'test_token_' + Date.now(),
      geo: {
        city: '测试城市',
        country: '测试国家',
        timezone: 'Asia/Shanghai'
      },
      baseUrl: config.base_url
    };
    
    let success = false;
    let error = null;
    
    // 尝试企业微信应用通知（如果启用）
    if (config.enable_app && config.qywx_app_url && config.qywx_app_code) {
      try {
        const notifyUrl = config.qywx_app_url.replace(/\/$/, '') + '/api/notify/' + config.qywx_app_code + '/textcard';
        
        console.log('Testing WeChat App notification:', notifyUrl);
        
        const response = await fetch(notifyUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            title: '🧪 系统测试通知',
            description: '这是一条测试通知\n\n如果您收到此消息，说明企业微信应用通知配置正确！\n\n📅 发送时间：' + new Date().toLocaleString('zh-CN'),
            url: config.base_url + '/admin',
            btntxt: '打开管理后台'
          })
        });
        
        console.log('WeChat App response status:', response.status);
        
        if (response.ok) {
          success = true;
        } else {
          const responseText = await response.text();
          console.log('WeChat App error response:', responseText);
          error = '企业微信应用API返回错误: ' + response.status + ' - ' + responseText;
        }
      } catch (e) {
        console.error('WeChat App notification error:', e);
        error = '企业微信应用通知发送失败: ' + e.message;
      }
    }
    
    // 尝试群机器人（如果启用且应用通知失败）
    if (!success && config.enable_webhook && config.qywx_webhook) {
      try {
        await fetch(config.qywx_webhook, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            msgtype: 'text',
            text: {
              content: '🧪 系统测试通知\n\n这是一条测试通知，如果您收到此消息，说明企业微信群机器人配置正确！\n\n发送时间：' + new Date().toLocaleString('zh-CN')
            }
          })
        });
        success = true;
        error = null;
      } catch (e) {
        error = '群机器人通知发送失败: ' + e.message;
      }
    }
    
    return jsonResponse({ success, error });
  }
  
  // ==================== 自定义通知渠道 API ====================
  
  // 获取所有自定义渠道
  if (path === '/api/admin/channels' && request.method === 'GET') {
    const channelIds = await env.ASSET_KV.get('config:custom_channels', 'json') || [];
    const channels = [];
    
    for (const id of channelIds) {
      const channel = await env.ASSET_KV.get(`channel:${id}`, 'json');
      if (channel) {
        channels.push(channel);
      }
    }
    
    return jsonResponse(channels);
  }
  
  // 获取单个渠道
  if (path.match(/^\/api\/admin\/channels\/[^/]+$/) && request.method === 'GET') {
    const channelId = path.split('/').pop();
    const channel = await env.ASSET_KV.get(`channel:${channelId}`, 'json');
    
    if (!channel) {
      return jsonResponse({ error: 'Channel not found' }, 404);
    }
    
    return jsonResponse(channel);
  }
  
  // 创建自定义渠道
  if (path === '/api/admin/channels' && request.method === 'POST') {
    const data = await request.json();
    
    // 生成渠道ID
    const channelId = 'ch_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    
    const channel = {
      id: channelId,
      name: data.name,
      enabled: data.enabled || false,
      notifyType: data.notifyType || 'both',
      method: data.method || 'POST',
      url: data.url,
      headers: data.headers || {},
      bodyTemplate: data.bodyTemplate || '',
      createdAt: Date.now(),
      updatedAt: Date.now()
    };
    
    // 保存渠道
    await env.ASSET_KV.put(`channel:${channelId}`, JSON.stringify(channel));
    
    // 更新渠道列表
    const channelIds = await env.ASSET_KV.get('config:custom_channels', 'json') || [];
    channelIds.push(channelId);
    await env.ASSET_KV.put('config:custom_channels', JSON.stringify(channelIds));
    
    return jsonResponse({ success: true, channel });
  }
  
  // 更新自定义渠道
  if (path.match(/^\/api\/admin\/channels\/[^/]+$/) && request.method === 'PUT') {
    const channelId = path.split('/').pop();
    const data = await request.json();
    
    const existingChannel = await env.ASSET_KV.get(`channel:${channelId}`, 'json');
    if (!existingChannel) {
      return jsonResponse({ error: 'Channel not found' }, 404);
    }
    
    const channel = {
      ...existingChannel,
      name: data.name,
      enabled: data.enabled,
      notifyType: data.notifyType,
      method: data.method,
      url: data.url,
      headers: data.headers || {},
      bodyTemplate: data.bodyTemplate,
      updatedAt: Date.now()
    };
    
    await env.ASSET_KV.put(`channel:${channelId}`, JSON.stringify(channel));
    
    return jsonResponse({ success: true, channel });
  }
  
  // 删除自定义渠道
  if (path.match(/^\/api\/admin\/channels\/[^/]+$/) && request.method === 'DELETE') {
    const channelId = path.split('/').pop();
    
    // 删除渠道
    await env.ASSET_KV.delete(`channel:${channelId}`);
    
    // 从列表中移除
    const channelIds = await env.ASSET_KV.get('config:custom_channels', 'json') || [];
    const newChannelIds = channelIds.filter(id => id !== channelId);
    await env.ASSET_KV.put('config:custom_channels', JSON.stringify(newChannelIds));
    
    return jsonResponse({ success: true });
  }
  
  // 测试自定义渠道（通用测试）
  if (path === '/api/admin/channels/test' && request.method === 'POST') {
    const channelData = await request.json();
    
    try {
      const testData = {
        qr_id: 'test_qr_123',
        qr_title: '测试二维码',
        request_id: 'test_request_456',
        approve_url: 'https://example.com/approve?token=test',
        reject_url: 'https://example.com/reject?token=test',
        geo_city: '测试城市',
        geo_country: '测试国家',
        geo_timezone: 'Asia/Shanghai',
        timestamp: Date.now(),
        time_formatted: new Date().toLocaleString('zh-CN')
      };
      
      const body = replaceTemplateVariables(channelData.bodyTemplate, testData);
      
      const response = await fetch(channelData.url, {
        method: channelData.method,
        headers: channelData.headers,
        body: channelData.method !== 'GET' ? body : undefined
      });
      
      if (response.ok) {
        return jsonResponse({ success: true });
      } else {
        return jsonResponse({ success: false, error: `HTTP ${response.status}` });
      }
    } catch (e) {
      return jsonResponse({ success: false, error: e.message });
    }
  }
  
  // 测试指定渠道
  if (path.match(/^\/api\/admin\/channels\/[^/]+\/test$/) && request.method === 'POST') {
    const channelId = path.split('/')[4];
    const channel = await env.ASSET_KV.get(`channel:${channelId}`, 'json');
    
    if (!channel) {
      return jsonResponse({ error: 'Channel not found' }, 404);
    }
    
    try {
      const testData = {
        qr_id: 'test_qr_123',
        qr_title: '测试二维码',
        request_id: 'test_request_456',
        approve_url: 'https://example.com/approve?token=test',
        reject_url: 'https://example.com/reject?token=test',
        geo_city: '测试城市',
        geo_country: '测试国家',
        geo_timezone: 'Asia/Shanghai',
        timestamp: Date.now(),
        time_formatted: new Date().toLocaleString('zh-CN')
      };
      
      const body = replaceTemplateVariables(channel.bodyTemplate, testData);
      
      const response = await fetch(channel.url, {
        method: channel.method,
        headers: channel.headers,
        body: channel.method !== 'GET' ? body : undefined
      });
      
      if (response.ok) {
        return jsonResponse({ success: true });
      } else {
        return jsonResponse({ success: false, error: `HTTP ${response.status}` });
      }
    } catch (e) {
      return jsonResponse({ success: false, error: e.message });
    }
  }
  
  // ==================== 结束自定义通知渠道 API ====================

  return new Response('Not Found', { status: 404 });
}

/**
 * 普通二维码处理 (/n/:id)
 */
async function handleNormalQR(request, env, qrId) {
  const qr = await env.ASSET_KV.get(`qr:${qrId}`, 'json');
  
  if (!qr) {
    return new Response(getNotFoundPage(), {
      headers: { 'Content-Type': 'text/html;charset=UTF-8' },
      status: 404
    });
  }

  // 记录扫码日志
  const ip = getClientIP(request);
  const geo = getGeoInfo(request);
  const userAgent = request.headers.get('User-Agent') || 'unknown';

  await logActivity(env, qrId, 'scan_normal', { ip, geo, userAgent });

  // 实时通知管理端
  await notifyAdmin(env, {
    type: 'qr_scanned',
    qrId,
    qrTitle: qr.title,
    qrType: 'normal',
    timestamp: Date.now(),
    location: geo
  });

  // 返回展示页面
  return new Response(getNormalQRPage(qrId, qr), {
    headers: { 'Content-Type': 'text/html;charset=UTF-8' }
  });
}

/**
 * 授权二维码处理 (/a/:id)
 */
async function handleAuthQR(request, env, qrId) {
  const qr = await env.ASSET_KV.get(`qr:${qrId}`, 'json');
  
  if (!qr) {
    return new Response(getNotFoundPage(), {
      headers: { 'Content-Type': 'text/html;charset=UTF-8' },
      status: 404
    });
  }

  // 记录扫码日志
  const ip = getClientIP(request);
  const geo = getGeoInfo(request);
  const userAgent = request.headers.get('User-Agent') || 'unknown';

  await logActivity(env, qrId, 'scan_auth', { ip, geo, userAgent });

  // 检查管理员是否在线
  const hasAdmin = await checkAdminOnline(env);

  // 返回授权页面（等待用户点击申请按钮）
  return new Response(getAuthQRPage(qrId, qr, hasAdmin), {
    headers: { 'Content-Type': 'text/html;charset=UTF-8' }
  });
}

/**
 * 处理授权申请（用户点击申请按钮时调用）
 */
async function handleAuthRequest(request, env) {
  const { qrId } = await request.json();
  
  const qr = await env.ASSET_KV.get(`qr:${qrId}`, 'json');
  if (!qr) {
    return jsonResponse({ error: 'QR code not found' }, 404);
  }

  // 获取用户信息
  const ip = getClientIP(request);
  const geo = getGeoInfo(request);

  // 检查管理员是否在线
  const hasAdmin = await checkAdminOnline(env);

  // 生成请求ID
  const requestId = generateId('req');

  // 保存请求信息
  await env.ASSET_KV.put(`request:${requestId}`, JSON.stringify({
    qrId,
    timestamp: Date.now(),
    ip,
    geo
  }), { expirationTtl: 3600 });

  // 获取系统配置
  const config = await env.ASSET_KV.get('config:system', 'json') || {};
  const hmacSecret = config.hmac_secret || 'default_secret';

  // 生成盲签名 Token
  const token = await createToken(
    {
      qr_id: qrId,
      request_id: requestId,
      action: 'request_auth',
      timestamp: Date.now(),
      ip,
      geo
    },
    hmacSecret
  );

  // 实时通知管理端
  await notifyAdmin(env, {
    type: 'auth_requested',
    qrId,
    requestId,
    qrTitle: qr.title,
    timestamp: Date.now(),
    location: geo,
    token,
    isOnline: hasAdmin
  });

  // 如果管理员不在线，发送企业微信通知
  if (!hasAdmin && config.qywx_webhook) {
    await sendWeChatNotification(env, {
      qrId,
      requestId,
      qrTitle: qr.title,
      token,
      geo,
      baseUrl: config.base_url
    });
  }

  return jsonResponse({ 
    success: true, 
    requestId,
    isOnline: hasAdmin 
  });
}

/**
 * 处理聊天请求（用户发送初始消息时调用）
 */
async function handleChatRequest(request, env) {
  const { qrId, sessionId, message, imageUrl } = await request.json();
  
  const qr = await env.ASSET_KV.get(`qr:${qrId}`, 'json');
  if (!qr) {
    return jsonResponse({ error: 'QR code not found' }, 404);
  }

  // 获取用户信息
  const ip = getClientIP(request);
  const geo = getGeoInfo(request);

  // 检查管理员是否在线
  const hasAdmin = await checkAdminOnline(env);

  // 保存聊天会话请求
  await env.ASSET_KV.put(`chat_request:${sessionId}`, JSON.stringify({
    qrId,
    sessionId,
    message,
    imageUrl,
    timestamp: Date.now(),
    ip,
    geo
  }), { expirationTtl: 3600 });

  // 获取系统配置
  const config = await env.ASSET_KV.get('config:system', 'json') || {};
  const hmacSecret = config.hmac_secret || 'default_secret';

  // 生成盲签名 Token
  const token = await createToken(
    {
      qr_id: qrId,
      session_id: sessionId,
      action: 'request_chat',
      timestamp: Date.now(),
      ip,
      geo
    },
    hmacSecret
  );

  // 实时通知管理端
  await notifyAdmin(env, {
    type: 'chat_requested',
    qrId,
    sessionId,
    qrTitle: qr.title,
    message,
    imageUrl,
    timestamp: Date.now(),
    location: geo,
    token,
    isOnline: hasAdmin
  });

  // 如果管理员不在线，发送企业微信通知
  if (!hasAdmin && config.qywx_webhook) {
    await sendWeChatChatNotification(env, {
      qrId,
      sessionId,
      qrTitle: qr.title,
      token,
      geo,
      message,
      baseUrl: config.base_url
    });
  }

  return jsonResponse({ 
    success: true, 
    sessionId,
    isOnline: hasAdmin 
  });
}

/**
 * 联系二维码处理 (/c/:id)
 */
async function handleContactQR(request, env, qrId) {
  const qr = await env.ASSET_KV.get(`qr:${qrId}`, 'json');
  
  if (!qr) {
    return new Response(getNotFoundPage(), {
      headers: { 'Content-Type': 'text/html;charset=UTF-8' },
      status: 404
    });
  }

  // 记录扫码日志
  const ip = getClientIP(request);
  const geo = getGeoInfo(request);
  const userAgent = request.headers.get('User-Agent') || 'unknown';

  await logActivity(env, qrId, 'scan_contact', { ip, geo, userAgent });

  // 检查管理员是否在线
  const hasAdmin = await checkAdminOnline(env);

  // 生成会话ID
  const sessionId = generateId('session');

  // 返回联系页面
  return new Response(getContactQRPage(qrId, sessionId, qr, hasAdmin), {
    headers: { 'Content-Type': 'text/html;charset=UTF-8' }
  });
}

/**
 * 审批处理（盲签名验证）
 */
async function handleApproval(request, env) {
  const url = new URL(request.url);
  const token = url.searchParams.get('token');
  const action = url.searchParams.get('action') || 'approve';

  if (!token) {
    return new Response('Missing token', { status: 400 });
  }

  // 获取系统配置
  const config = await env.ASSET_KV.get('config:system', 'json') || {};
  const hmacSecret = config.hmac_secret || 'default_secret';

  // 验证签名
  const payload = await verifyToken(token, hmacSecret, 3600);
  
  if (!payload) {
    return new Response(getErrorPage('Token 无效或已过期'), {
      headers: { 'Content-Type': 'text/html;charset=UTF-8' },
      status: 401
    });
  }

  const { qr_id, request_id } = payload;
  const qr = await env.ASSET_KV.get(`qr:${qr_id}`, 'json');

  if (!qr) {
    return new Response('QR code not found', { status: 404 });
  }

  // 记录审批日志
  await logActivity(env, qr_id, action === 'approve' ? 'approved' : 'rejected', {
    approver: 'admin',
    requestId: request_id,
    via: 'wechat'
  });

  // 通知用户端（通过 WebSocket）
  await notifyUser(env, {
    type: 'approval_result',
    qrId: qr_id,
    requestId: request_id,
    action,
    qr: action === 'approve' ? qr : null
  });

  // 删除请求记录
  await env.ASSET_KV.delete(`request:${request_id}`);

  // 返回成功页面
  return new Response(getApprovalResultPage(action, qr), {
    headers: { 'Content-Type': 'text/html;charset=UTF-8' }
  });
}

/**
 * 聊天请求决策处理
 */
async function handleChatDecision(request, env) {
  const url = new URL(request.url);
  const token = url.searchParams.get('token');
  const action = url.searchParams.get('action') || 'accept';

  if (!token) {
    return new Response('Missing token', { status: 400 });
  }

  // 获取系统配置
  const config = await env.ASSET_KV.get('config:system', 'json') || {};
  const hmacSecret = config.hmac_secret || 'default_secret';

  // 验证签名
  const payload = await verifyToken(token, hmacSecret, 3600);
  
  if (!payload) {
    return new Response(getErrorPage('Token 无效或已过期'), {
      headers: { 'Content-Type': 'text/html;charset=UTF-8' },
      status: 401
    });
  }

  const { qr_id, session_id } = payload;
  const qr = await env.ASSET_KV.get(`qr:${qr_id}`, 'json');

  if (!qr) {
    return new Response('QR code not found', { status: 404 });
  }

  // 记录决策日志
  await logActivity(env, qr_id, action === 'accept' ? 'chat_accepted' : 'chat_rejected', {
    approver: 'admin',
    sessionId: session_id,
    via: 'wechat'
  });

  if (action === 'accept') {
    // 初始化聊天会话
    const chatData = await env.ASSET_KV.get(`chat:${qr_id}`, 'json') || { sessions: {} };
    chatData.sessions = chatData.sessions || {};
    chatData.sessions[session_id] = {
      accepted: true,
      messages: [],
      startedAt: Date.now()
    };
    await env.ASSET_KV.put(`chat:${qr_id}`, JSON.stringify(chatData));
  }

  // 通知用户端（通过 WebSocket）
  await notifyUser(env, {
    type: 'chat_request_result',
    qrId: qr_id,
    sessionId: session_id,
    action
  });

  // 返回成功页面
  return new Response(getChatDecisionResultPage(action, qr), {
    headers: { 'Content-Type': 'text/html;charset=UTF-8' }
  });
}

/**
 * 图片上传处理
 */
async function handleImageUpload(request, env) {
  if (request.method !== 'POST') {
    return new Response('Method not allowed', { status: 405 });
  }

  try {
    const formData = await request.formData();
    const file = formData.get('image');
    
    if (!file) {
      return jsonResponse({ error: 'No file uploaded' }, 400);
    }

    // 读取文件内容
    const arrayBuffer = await file.arrayBuffer();
    const base64 = arrayBufferToBase64(arrayBuffer);
    
    // 生成文件ID
    const fileId = generateId('img');
    const contentType = file.type || 'image/png';
    
    // 保存到KV（有大小限制，实际生产环境应该用R2）
    const imageData = {
      id: fileId,
      contentType,
      data: base64,
      size: arrayBuffer.byteLength,
      uploadedAt: Date.now()
    };
    
    // 限制大小（例如2MB）
    if (arrayBuffer.byteLength > 2 * 1024 * 1024) {
      return jsonResponse({ error: 'File too large (max 2MB)' }, 400);
    }
    
    await env.ASSET_KV.put(`img:${fileId}`, JSON.stringify(imageData));
    
    return jsonResponse({
      success: true,
      fileId,
      url: `/api/image/${fileId}`
    });
    
  } catch (error) {
    console.error('Upload error:', error);
    return jsonResponse({ error: 'Upload failed' }, 500);
  }
}

/**
 * 二维码生成
 */
async function handleQRCode(request, env) {
  const url = new URL(request.url);
  const text = url.searchParams.get('text') || '';
  const size = url.searchParams.get('size') || '300';
  
  if (!text) {
    return new Response('Missing text parameter', { status: 400 });
  }

  // 使用第三方 API 生成二维码
  const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=${size}x${size}&data=${encodeURIComponent(text)}`;
  
  const response = await fetch(qrUrl);
  return new Response(response.body, {
    headers: { 
      'Content-Type': 'image/png',
      'Cache-Control': 'public, max-age=86400'
    }
  });
}

// ==================== 辅助函数 ====================

/**
 * 检查管理员是否在线
 */
async function checkAdminOnline(env) {
  try {
    const id = env.CONNECTION_MANAGER.idFromName('global');
    const stub = env.CONNECTION_MANAGER.get(id);
    const response = await stub.fetch('http://internal/status');
    const status = await response.json();
    
    return status.hasAdmin;
  } catch (e) {
    return false;
  }
}

/**
 * 通知管理端
 */
async function notifyAdmin(env, message) {
  try {
    const id = env.CONNECTION_MANAGER.idFromName('global');
    const stub = env.CONNECTION_MANAGER.get(id);
    
    await stub.fetch('http://internal/broadcast', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...message, to: 'admin' })
    });
  } catch (e) {
    console.error('Failed to notify admin:', e);
  }
}

/**
 * 通知用户端
 */
async function notifyUser(env, message) {
  try {
    const id = env.CONNECTION_MANAGER.idFromName('global');
    const stub = env.CONNECTION_MANAGER.get(id);
    
    await stub.fetch('http://internal/broadcast', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...message, to: 'user' })
    });
  } catch (e) {
    console.error('Failed to notify user:', e);
  }
}

/**
 * 发送企业微信通知 - 授权请求
 */
async function sendWeChatNotification(env, { qrId, requestId, qrTitle, token, geo, baseUrl }) {
  const config = await env.ASSET_KV.get('config:system', 'json') || {};
  
  const base = baseUrl || config.base_url || 'https://your-worker.com';
  const approveUrl = `${base}/approve?token=${encodeURIComponent(token)}&action=approve`;
  const rejectUrl = `${base}/approve?token=${encodeURIComponent(token)}&action=reject`;
  
  // 并行发送通知到所有启用的渠道
  const notifications = [];
  
  // 1. 企业微信应用通知（如果启用）
  if (config.enable_app && config.qywx_app_url && config.qywx_app_code) {
    notifications.push(
      sendWeChatAppNotification(env, { qrId, requestId, qrTitle, token, geo, baseUrl }, 'auth')
        .then(() => console.log('WeChat App notification sent successfully'))
        .catch(e => console.error('WeChat App notification failed:', e))
    );
  }
  
  // 2. 企业微信群机器人（如果启用）
  if (config.enable_webhook && config.qywx_webhook) {
    const message = {
      msgtype: 'template_card',
      template_card: {
        card_type: 'text_notice',
        source: {
          icon_url: 'https://www.cloudflare.com/favicon.ico',
          desc: '授权二维码访问请求'
        },
        main_title: {
          title: '有人请求查看私密信息',
          desc: qrTitle
        },
        emphasis_content: {
          title: '访问位置',
          desc: `${geo.city}, ${geo.country}`
        },
        sub_title_text: `二维码ID: ${qrId}`,
        horizontal_content_list: [
          {
            keyname: '请求时间',
            value: new Date().toLocaleString('zh-CN', { timeZone: geo.timezone })
          }
        ],
        card_action: {
          type: 1,
          url: approveUrl
        },
        button_list: [
          {
            text: '✅ 批准查看',
            style: 1,
            type: 'url',
            url: approveUrl
          },
          {
            text: '❌ 拒绝',
            style: 2,
            type: 'url',
            url: rejectUrl
          }
        ]
      }
    };
    
    notifications.push(
      fetch(config.qywx_webhook, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(message)
      })
        .then(() => console.log('WeChat webhook notification sent successfully'))
        .catch(e => console.error('WeChat webhook notification failed:', e))
    );
  }
  
  // 等待所有通知发送完成（并行）
  if (notifications.length > 0) {
    await Promise.allSettled(notifications);
  }
  
  // 3. 发送自定义渠道通知
  await sendCustomChannelNotifications(env, 'auth', { qrId, requestId, qrTitle, token, geo, baseUrl });
}

/**
 * 发送企业微信应用通知（文本卡片格式）
 */
async function sendWeChatAppNotification(env, { qrId, requestId, qrTitle, token, geo, baseUrl }, type = 'auth') {
  const config = await env.ASSET_KV.get('config:system', 'json') || {};
  
  if (!config.qywx_app_url || !config.qywx_app_code) {
    throw new Error('WeChat App notification not configured');
  }

  const base = baseUrl || config.base_url || 'https://your-worker.com';
  const approveUrl = `${base}/approve?token=${encodeURIComponent(token)}&action=approve`;
  
  let title, description, url, btntxt;
  
  if (type === 'auth') {
    title = '🔐 授权二维码访问请求';
    description = `有人请求查看 "${qrTitle}" 的私密内容\n\n📍 位置：${geo.city}, ${geo.country}\n🕐 时间：${new Date().toLocaleString('zh-CN')}\n🆔 请求ID：${requestId}`;
    url = approveUrl;
    btntxt = '立即处理';
  } else if (type === 'chat') {
    title = '💬 新的聊天请求';
    description = `有人想要通过 "${qrTitle}" 联系您\n\n📍 位置：${geo.city}, ${geo.country}\n🕐 时间：${new Date().toLocaleString('zh-CN')}`;
    url = base + '/admin#chats';
    btntxt = '查看聊天';
  }
  
  const notifyUrl = config.qywx_app_url.replace(/\/$/, '') + '/api/notify/' + config.qywx_app_code + '/textcard';
  
  try {
    const response = await fetch(notifyUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title,
        description,
        url,
        btntxt
      })
    });
    
    if (!response.ok) {
      throw new Error('WeChat App API returned error: ' + response.status);
    }
    
    console.log('WeChat App notification sent successfully');
  } catch (e) {
    console.error('Failed to send WeChat App notification:', e);
    throw e;
  }
}

/**
 * 发送企业微信通知 - 聊天请求
 */
async function sendWeChatChatNotification(env, { qrId, sessionId, qrTitle, token, geo, message: userMessage, baseUrl }) {
  const config = await env.ASSET_KV.get('config:system', 'json') || {};
  
  const base = baseUrl || config.base_url || 'https://your-worker.com';
  const acceptUrl = `${base}/chat-decision?token=${encodeURIComponent(token)}&action=accept`;
  const rejectUrl = `${base}/chat-decision?token=${encodeURIComponent(token)}&action=reject`;
  
  // 并行发送通知到所有启用的渠道
  const notifications = [];
  
  // 1. 企业微信应用通知（如果启用）
  if (config.enable_app && config.qywx_app_url && config.qywx_app_code) {
    notifications.push(
      sendWeChatAppNotification(env, { qrId, requestId: sessionId, qrTitle, token, geo, baseUrl }, 'chat')
        .then(() => console.log('WeChat App chat notification sent successfully'))
        .catch(e => console.error('WeChat App chat notification failed:', e))
    );
  }
  
  // 2. 企业微信群机器人（如果启用）
  if (config.enable_webhook && config.qywx_webhook) {
    const wechatMessage = {
      msgtype: 'template_card',
      template_card: {
        card_type: 'text_notice',
        source: {
          icon_url: 'https://www.cloudflare.com/favicon.ico',
          desc: '联系二维码聊天请求'
        },
        main_title: {
          title: '有人想要联系您',
          desc: qrTitle
        },
        emphasis_content: {
          title: '消息内容',
          desc: userMessage.substring(0, 50) + (userMessage.length > 50 ? '...' : '')
        },
        sub_title_text: `来自: ${geo.city}, ${geo.country}`,
        horizontal_content_list: [
          {
            keyname: '请求时间',
            value: new Date().toLocaleString('zh-CN', { timeZone: geo.timezone })
          }
        ],
        card_action: {
          type: 1,
          url: acceptUrl
        },
        button_list: [
          {
            text: '✅ 接受并聊天',
            style: 1,
            type: 'url',
            url: acceptUrl
          },
          {
            text: '❌ 拒绝',
            style: 2,
            type: 'url',
            url: rejectUrl
          }
        ]
      }
    };
    
    notifications.push(
      fetch(config.qywx_webhook, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(wechatMessage)
      })
        .then(() => console.log('WeChat webhook chat notification sent successfully'))
        .catch(e => console.error('WeChat webhook chat notification failed:', e))
    );
  }
  
  // 等待所有通知发送完成（并行）
  if (notifications.length > 0) {
    await Promise.allSettled(notifications);
  }
  
  // 3. 发送自定义渠道通知
  await sendCustomChannelNotifications(env, 'chat', { qrId, sessionId, qrTitle, token, geo, message: userMessage, baseUrl });
}

/**
 * 发送自定义渠道通知
 * @param {object} env - 环境变量
 * @param {string} notifyType - 通知类型 'auth' | 'chat'
 * @param {object} data - 通知数据
 */
async function sendCustomChannelNotifications(env, notifyType, data) {
  // 获取所有自定义渠道
  const channelIds = await env.ASSET_KV.get('config:custom_channels', 'json') || [];
  
  if (channelIds.length === 0) {
    return;
  }
  
  const notifications = [];
  
  for (const channelId of channelIds) {
    const channel = await env.ASSET_KV.get(`channel:${channelId}`, 'json');
    
    // 跳过未启用的渠道
    if (!channel || !channel.enabled) {
      continue;
    }
    
    // 检查通知类型是否匹配
    if (channel.notifyType !== 'both' && channel.notifyType !== notifyType) {
      continue;
    }
    
    // 准备变量数据
    const templateData = prepareTemplateData(notifyType, data);
    
    // 替换模板变量
    const body = replaceTemplateVariables(channel.bodyTemplate, templateData);
    
    // 发送通知
    notifications.push(
      fetch(channel.url, {
        method: channel.method,
        headers: channel.headers || {},
        body: channel.method !== 'GET' ? body : undefined
      })
        .then(() => console.log(`Custom channel ${channel.name} notification sent successfully`))
        .catch(e => console.error(`Custom channel ${channel.name} notification failed:`, e))
    );
  }
  
  if (notifications.length > 0) {
    await Promise.allSettled(notifications);
  }
}

/**
 * 准备模板数据
 */
function prepareTemplateData(notifyType, data) {
  const base = data.baseUrl || 'https://your-worker.com';
  const timeFormatted = new Date().toLocaleString('zh-CN', { 
    timeZone: data.geo?.timezone || 'Asia/Shanghai' 
  });
  
  const commonData = {
    qr_id: data.qrId || '',
    qr_title: data.qrTitle || '',
    geo_city: data.geo?.city || '',
    geo_country: data.geo?.country || '',
    geo_timezone: data.geo?.timezone || '',
    timestamp: Date.now(),
    time_formatted: timeFormatted
  };
  
  if (notifyType === 'auth') {
    return {
      ...commonData,
      request_id: data.requestId || '',
      approve_url: `${base}/approve?token=${encodeURIComponent(data.token || '')}&action=approve`,
      reject_url: `${base}/approve?token=${encodeURIComponent(data.token || '')}&action=reject`
    };
  } else if (notifyType === 'chat') {
    return {
      ...commonData,
      session_id: data.sessionId || '',
      user_message: data.message || '',
      accept_url: `${base}/chat-decision?token=${encodeURIComponent(data.token || '')}&action=accept`,
      reject_url: `${base}/chat-decision?token=${encodeURIComponent(data.token || '')}&action=reject`
    };
  }
  
  return commonData;
}

/**
 * JSON 响应辅助函数
 */
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*'
    }
  });
}


// ==================== HTML 页面模板 ====================

/**
 * 登录页面
 */
function getLoginPage(error = '') {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>管理员登录</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .login-container {
      background: white;
      padding: 40px;
      border-radius: 16px;
      box-shadow: 0 10px 40px rgba(0,0,0,0.3);
      width: 90%;
      max-width: 400px;
    }
    h1 { font-size: 24px; margin-bottom: 30px; text-align: center; color: #333; }
    .error { background: #fee2e2; color: #991b1b; padding: 12px; border-radius: 8px; margin-bottom: 20px; font-size: 14px; }
    input[type="password"] { width: 100%; padding: 14px; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 15px; margin-bottom: 20px; }
    input[type="password"]:focus { outline: none; border-color: #667eea; }
    button { width: 100%; padding: 14px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; }
    button:hover { transform: translateY(-2px); }
  </style>
</head>
<body>
  <div class="login-container">
    <h1>🔐 管理员登录</h1>
    ${error ? `<div class="error">${error}</div>` : ''}
    <form method="POST" action="/admin">
      <input type="password" name="password" placeholder="请输入管理密码" required autofocus>
      <button type="submit">登录</button>
    </form>
  </div>
</body>
</html>`;
}

/**
 * 管理后台
 */
function getAdminDashboard() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>二维码管理后台</title>
  <script src="https://cdn.jsdelivr.net/npm/marked@11.1.1/marked.min.js"></script>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f7fa; }
    .navbar { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 16px 24px; display: flex; justify-content: space-between; align-items: center; }
    .navbar h1 { font-size: 20px; font-weight: 600; }
    .container { max-width: 1200px; margin: 0 auto; padding: 24px; }
    .tabs { display: flex; gap: 8px; margin-bottom: 24px; border-bottom: 2px solid #e0e0e0; }
    .tab { padding: 12px 24px; background: none; border: none; border-bottom: 3px solid transparent; cursor: pointer; font-size: 15px; color: #666; margin-bottom: -2px; }
    .tab.active { color: #667eea; border-bottom-color: #667eea; }
    .tab-content { display: none; }
    .tab-content.active { display: block; }
    .btn { padding: 10px 20px; border: none; border-radius: 8px; font-size: 14px; cursor: pointer; }
    .btn-primary { background: #667eea; color: white; }
    .qr-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 20px; }
    .qr-card { background: white; border-radius: 12px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }
    .qr-type { display: inline-block; padding: 4px 12px; border-radius: 6px; font-size: 12px; font-weight: 600; margin-bottom: 12px; }
    .type-normal { background: #dbeafe; color: #1e40af; }
    .type-auth { background: #fef3c7; color: #92400e; }
    .type-contact { background: #dcfce7; color: #166534; }
    .qr-title { font-size: 16px; font-weight: 600; margin-bottom: 8px; }
    .qr-actions { display: flex; gap: 8px; margin-top: 16px; }
    .qr-actions button { flex: 1; padding: 8px; font-size: 13px; }
    .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; }
    .modal.show { display: flex; align-items: center; justify-content: center; }
    .modal-content { background: white; border-radius: 16px; padding: 32px; max-width: 600px; width: 90%; max-height: 90vh; overflow-y: auto; }
    .form-group { margin-bottom: 20px; }
    .form-group label { display: block; font-size: 14px; margin-bottom: 8px; }
    .form-group input, .form-group textarea, .form-group select { width: 100%; padding: 12px; border: 2px solid #e0e0e0; border-radius: 8px; }
    .form-group textarea { min-height: 120px; }
    .notification { position: fixed; top: 24px; right: 24px; background: white; border-radius: 12px; padding: 20px; box-shadow: 0 4px 16px rgba(0,0,0,0.2); z-index: 2000; display: none; min-width: 320px; animation: slideIn 0.3s; }
    .notification.show { display: block; }
    @keyframes slideIn { from { transform: translateX(400px); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
    @keyframes slideOut { from { transform: translateX(0); opacity: 1; } to { transform: translateX(400px); opacity: 0; } }
    @keyframes pulse { 0%, 100% { transform: scale(1); } 50% { transform: scale(1.02); } }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
    .notification-header { display: flex; justify-content: space-between; margin-bottom: 12px; }
    .notification-title { font-weight: 600; font-size: 16px; }
    .notification-actions { display: flex; gap: 8px; margin-top: 16px; }
    .notification-actions button { flex: 1; padding: 10px; }
  </style>
</head>
<body>
  <div class="navbar">
    <h1>📱 二维码管理系统</h1>
    <div>在线</div>
  </div>
  
  <div class="container">
    <div class="tabs">
      <button class="tab active" onclick="switchTab('normal')">普通二维码</button>
      <button class="tab" onclick="switchTab('auth')">授权二维码</button>
      <button class="tab" onclick="switchTab('contact')">联系二维码</button>
      <button class="tab" onclick="switchTab('chats')">聊天记录</button>
      <button class="tab" onclick="switchTab('settings')">系统设置</button>
    </div>
    
    <div id="normalTab" class="tab-content active">
      <div style="margin-bottom: 20px;">
        <button class="btn btn-primary" onclick="showCreateModal('normal')">+ 创建普通二维码</button>
      </div>
      <div id="normalList" class="qr-grid"></div>
    </div>
    
    <div id="authTab" class="tab-content">
      <div style="margin-bottom: 20px;">
        <button class="btn btn-primary" onclick="showCreateModal('auth')">+ 创建授权二维码</button>
      </div>
      <div id="authList" class="qr-grid"></div>
    </div>
    
    <div id="contactTab" class="tab-content">
      <div style="margin-bottom: 20px;">
        <button class="btn btn-primary" onclick="showCreateModal('contact')">+ 创建联系二维码</button>
      </div>
      <div id="contactList" class="qr-grid"></div>
    </div>
    
    
    <div id="chatsTab" class="tab-content">
      <div style="background:white;padding:24px;border-radius:12px;margin-bottom:20px;">
        <h3 style="margin-bottom:12px;">💬 聊天记录管理</h3>
        <p style="color:#666;line-height:1.6;margin-bottom:16px;">
          查看所有联系二维码的聊天记录，支持查看详情和删除。
        </p>
        <button class="btn btn-primary" onclick="loadChatHistory()">🔄 刷新记录</button>
      </div>
      <div id="chatHistoryList" style="background:white;border-radius:12px;padding:24px;">
        <div style="text-align:center;padding:40px;color:#999;">
          点击上方"刷新记录"按钮加载聊天记录
        </div>
      </div>
    </div>
    
    <div id="settingsTab" class="tab-content">
      <div style="background:white;padding:32px;border-radius:12px;">
        <h2 style="margin-bottom:24px;">⚙️ 系统设置</h2>
        <form id="settingsForm" onsubmit="saveSettings(event)">
          <div class="form-group">
            <label>服务地址 (BASE_URL)</label>
            <input type="url" id="baseUrl" name="base_url" placeholder="https://your-worker.workers.dev" required>
            <div style="font-size:12px;color:#999;margin-top:4px;">用于生成二维码链接和通知回调</div>
          </div>
          
          <div class="form-group">
            <label>HMAC密钥 (用于签名验证)</label>
            <input type="text" id="hmacSecret" name="hmac_secret" placeholder="输入随机密钥" required>
            <div style="font-size:12px;color:#999;margin-top:4px;">用于授权请求的安全签名，建议使用复杂随机字符串</div>
          </div>
          
          <h3 style="margin:32px 0 16px;color:#333;font-size:18px;border-bottom:2px solid #e0e0e0;padding-bottom:12px;">📢 通知渠道配置</h3>
          <div style="background:#f0f9ff;padding:16px;border-radius:8px;margin-bottom:20px;border-left:4px solid #3b82f6;">
            <div style="font-size:13px;color:#1e40af;">
              💡 选择并配置通知渠道，当管理员离线时，系统将通过选中的渠道发送通知。
            </div>
          </div>
          
          <!-- 企业微信群机器人 -->
          <div style="border:2px solid #e0e0e0;border-radius:12px;padding:20px;margin-bottom:16px;transition:all 0.3s;" onmouseover="this.style.borderColor='#9ca3af'" onmouseout="this.style.borderColor='#e0e0e0'">
            <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;">
              <input type="checkbox" id="enableWebhook" name="enable_webhook" style="width:20px;height:20px;cursor:pointer;" onchange="toggleWebhookFields()">
              <span style="font-size:28px;">🤖</span>
              <div style="flex:1;">
                <div style="font-weight:600;font-size:16px;color:#333;">企业微信群机器人</div>
                <div style="font-size:12px;color:#666;margin-top:2px;">通过群机器人Webhook发送简单文本通知</div>
              </div>
            </div>
            <div id="webhookFields" style="display:none;">
              <div class="form-group" style="margin-bottom:0;">
                <input type="url" id="qywxWebhook" name="qywx_webhook" placeholder="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=...">
                <div style="font-size:12px;color:#666;margin-top:6px;">
                  ℹ️ 在企业微信群中添加机器人，复制Webhook地址
                </div>
              </div>
            </div>
          </div>
          
          <!-- 企业微信应用通知（推荐） -->
          <div style="border:2px solid #10b981;border-radius:12px;padding:20px;background:linear-gradient(135deg, #f0fdf4 0%, #ecfdf5 100%);position:relative;overflow:hidden;margin-bottom:16px;">
            <div style="position:absolute;top:8px;right:8px;background:#10b981;color:white;padding:4px 12px;border-radius:12px;font-size:11px;font-weight:600;">推荐</div>
            <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;">
              <input type="checkbox" id="enableApp" name="enable_app" style="width:20px;height:20px;cursor:pointer;" onchange="toggleAppFields()">
              <span style="font-size:28px;">📱</span>
              <div style="flex:1;">
                <div style="font-weight:600;font-size:16px;color:#065f46;">企业微信应用通知</div>
                <div style="font-size:12px;color:#059669;margin-top:2px;">支持文本卡片、Markdown、图文等多种富文本格式</div>
              </div>
            </div>
            <div id="appFields" style="display:none;">
              <div class="form-group">
                <label style="color:#065f46;">API基础地址</label>
                <input type="url" id="qywxAppUrl" name="qywx_app_url" placeholder="https://your-notify-service.com">
                <div style="font-size:12px;color:#059669;margin-top:6px;">
                  你的企业微信应用通知服务地址
                </div>
              </div>
              <div class="form-group" style="margin-bottom:0;">
                <label style="color:#065f46;">通知Code</label>
                <input type="text" id="qywxAppCode" name="qywx_app_code" placeholder="your-notification-code">
                <div style="font-size:12px;color:#059669;margin-top:6px;">
                  在你的服务中配置的通知代码 | 
                  <a href="https://vkcdavvhaure.ap-northeast-1.clawcloudrun.com/enhanced-api-docs.html" target="_blank" style="color:#10b981;font-weight:600;">📚 查看API文档</a>
                </div>
              </div>
            </div>
          </div>
          
          <!-- 自定义通知渠道 -->
          <h3 style="margin:32px 0 16px;color:#333;font-size:18px;border-bottom:2px solid #e0e0e0;padding-bottom:12px;">
            🔧 自定义通知渠道
            <button type="button" class="btn" style="float:right;padding:8px 16px;background:#667eea;color:white;font-size:13px;" onclick="showAddChannelModal()">+ 添加渠道</button>
          </h3>
          <div style="background:#fffbeb;padding:16px;border-radius:8px;margin-bottom:20px;border-left:4px solid #f59e0b;">
            <div style="font-size:13px;color:#92400e;">
              ⚡ 高级功能：配置任意HTTP通知接口，支持自定义请求模板和变量替换
            </div>
          </div>
          
          <div id="customChannelsList" style="margin-bottom:20px;">
            <!-- 自定义渠道列表将在这里动态显示 -->
          </div>
          
          <div style="display:flex;gap:12px;margin-top:24px;">
            <button type="submit" class="btn btn-primary">💾 保存设置</button>
            <button type="button" class="btn" style="background:#8b5cf6;color:white;" onclick="testNotification(event)">🧪 测试通知</button>
          </div>
        </form>
      </div>
    </div>
  </div>
  
  <!-- 创建/编辑模态框 -->
  <div id="qrModal" class="modal">
    <div class="modal-content">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;">
        <h2 id="modalTitle">创建二维码</h2>
        <button onclick="closeModal()" style="background:none;border:none;font-size:24px;cursor:pointer;">×</button>
      </div>
      <form id="qrForm" onsubmit="saveQR(event)">
        <input type="hidden" id="qrId" name="id">
        <input type="hidden" id="qrType" name="type">
        
        <div class="form-group">
          <label>标题</label>
          <input type="text" id="qrTitle" name="title" required>
        </div>
        
        <div class="form-group">
          <label>内容 (支持 Markdown 和 HTML)</label>
          <textarea id="qrContent" name="content"></textarea>
          <div style="font-size:12px;color:#999;margin-top:4px;">支持 Markdown 格式和 HTML 标签</div>
        </div>
        
        <div class="form-group" id="privateContentGroup" style="display:none;">
          <label>私密内容 (仅授权后显示)</label>
          <textarea id="qrPrivateContent" name="privateContent"></textarea>
        </div>
        
        <div class="form-group">
          <label>图片 (可选)</label>
          <input type="file" id="qrImage" accept="image/*" onchange="uploadImage(this)">
          <div id="imagePreview"></div>
        </div>
        
        <div style="display:flex;gap:8px;">
          <button type="submit" class="btn btn-primary" style="flex:1;">保存</button>
          <button type="button" class="btn" onclick="closeModal()" style="background:#e0e0e0;flex:1;">取消</button>
        </div>
      </form>
    </div>
  </div>
  
  <!-- 通知弹窗 -->
  <div id="notification" class="notification">
    <div class="notification-header">
      <div class="notification-title" id="notifTitle"></div>
      <button class="notification-close" onclick="closeNotification()">×</button>
    </div>
    <div id="notifBody"></div>
    <div class="notification-actions" id="notifActions"></div>
  </div>

  <!-- 聊天窗口 -->
  <div id="chatWindow" class="modal">
    <div class="modal-content" style="max-width:700px;max-height:85vh;">
      <div style="display:flex;justify-content:space-between;align-items:center;padding-bottom:16px;border-bottom:2px solid #e0e0e0;margin-bottom:20px;">
        <div>
          <h2 id="chatWindowTitle" style="margin:0;font-size:20px;">聊天中</h2>
          <div style="font-size:12px;color:#999;margin-top:4px;" id="chatInfo">会话ID: ...</div>
        </div>
        <button onclick="closeChatWindow()" style="background:none;border:none;font-size:28px;cursor:pointer;color:#999;line-height:1;">×</button>
      </div>
      
      <div class="chat-messages" id="adminChatMessages" style="height:450px;background:#fafafa;"></div>
      
      <div id="adminImagePreview" style="margin:12px 0;"></div>
      
      <div style="display:flex;gap:8px;margin-top:16px;align-items:flex-end;">
        <input type="file" id="adminImageInput" accept="image/*" onchange="uploadAdminImage(this)" style="display:none;">
        <button class="btn" style="background:#f0f0f0;color:#333;padding:12px 16px;border-radius:10px;" onclick="document.getElementById('adminImageInput').click()">
          📎
        </button>
        <textarea id="adminChatInput" placeholder="输入消息..." style="flex:1;padding:12px;border:2px solid #e0e0e0;border-radius:10px;font-size:14px;resize:none;font-family:inherit;" rows="2" onkeypress="if(event.key==='Enter' && !event.shiftKey) { event.preventDefault(); sendAdminMessage(); }"></textarea>
        <button class="btn btn-primary" style="padding:12px 24px;border-radius:10px;" onclick="sendAdminMessage()">发送</button>
      </div>
    </div>
  </div>

  <!-- 聊天记录详情模态框 -->
  <div id="chatHistoryModal" class="modal">
    <div class="modal-content" style="max-width:700px;max-height:85vh;">
      <div style="display:flex;justify-content:space-between;align-items:center;padding-bottom:16px;border-bottom:2px solid #e0e0e0;margin-bottom:20px;">
        <div>
          <h2 id="historyModalTitle" style="margin:0;font-size:20px;">聊天记录</h2>
          <div style="font-size:12px;color:#999;margin-top:4px;" id="historyModalInfo">...</div>
        </div>
        <button onclick="closeChatHistoryModal()" style="background:none;border:none;font-size:28px;cursor:pointer;color:#999;line-height:1;">×</button>
      </div>
      
      <div class="chat-messages" id="historyMessages" style="height:450px;background:#fafafa;"></div>
      
      <div style="display:flex;gap:8px;margin-top:16px;">
        <button class="btn" style="background:#ef4444;color:white;flex:1;" onclick="confirmDeleteChatHistory()">删除此聊天记录</button>
        <button class="btn" style="background:#e0e0e0;color:#666;flex:1;" onclick="closeChatHistoryModal()">关闭</button>
      </div>
    </div>
  </div>

  <!-- 二维码查看模态框 -->
  <div id="qrViewModal" class="modal">
    <div class="modal-content" style="max-width:550px;">
      <div style="display:flex;justify-content:space-between;align-items:center;padding-bottom:16px;border-bottom:2px solid #e0e0e0;margin-bottom:20px;">
        <div>
          <h2 id="qrViewTitle" style="margin:0;font-size:20px;color:#333;">查看二维码</h2>
          <div style="font-size:12px;color:#999;margin-top:4px;" id="qrViewType">类型</div>
        </div>
        <button onclick="closeQRViewModal()" style="background:none;border:none;font-size:28px;cursor:pointer;color:#999;line-height:1;transition:color 0.2s;" onmouseover="this.style.color='#666'" onmouseout="this.style.color='#999'">×</button>
      </div>
      
      <div style="text-align:center;padding:24px 24px 32px;">
        <!-- 二维码容器 -->
        <div style="background:linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);padding:32px;border-radius:16px;margin-bottom:20px;display:inline-block;position:relative;box-shadow:0 8px 24px rgba(0,0,0,0.12);">
          <div style="background:white;padding:16px;border-radius:12px;box-shadow:0 4px 16px rgba(0,0,0,0.08);">
            <img id="qrViewImage" src="" style="width:280px;height:280px;display:block;cursor:pointer;transition:transform 0.3s;" onclick="downloadQRCode()" onmouseover="this.style.transform='scale(1.02)'" onmouseout="this.style.transform='scale(1)'" title="点击下载二维码">
          </div>
          <div style="margin-top:12px;font-size:12px;color:#666;font-weight:500;">
            <span style="background:white;padding:6px 12px;border-radius:6px;box-shadow:0 2px 8px rgba(0,0,0,0.08);">📥 点击二维码下载高清图</span>
          </div>
        </div>
        
        <!-- 链接信息 -->
        <div style="background:linear-gradient(135deg, #e0f2fe 0%, #bae6fd 100%);padding:20px;border-radius:12px;margin-bottom:24px;text-align:left;box-shadow:0 4px 12px rgba(0,0,0,0.08);">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;">
            <span style="font-size:16px;">🔗</span>
            <span style="font-size:14px;color:#0c4a6e;font-weight:600;">二维码链接</span>
          </div>
          <div style="font-size:13px;color:#075985;word-break:break-all;background:white;padding:12px 16px;border-radius:8px;font-family:'Courier New',monospace;line-height:1.6;box-shadow:inset 0 2px 4px rgba(0,0,0,0.06);" id="qrViewUrl">URL</div>
        </div>
        
        <!-- 操作按钮 -->
        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;">
          <button class="btn" style="background:linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);color:white;padding:14px;border-radius:10px;font-weight:600;box-shadow:0 4px 12px rgba(59,130,246,0.3);transition:all 0.3s;" onclick="openQRLink()" onmouseover="this.style.transform='translateY(-2px)';this.style.boxShadow='0 6px 16px rgba(59,130,246,0.4)'" onmouseout="this.style.transform='translateY(0)';this.style.boxShadow='0 4px 12px rgba(59,130,246,0.3)'">
            🔗<br><span style="font-size:13px;">访问链接</span>
          </button>
          <button class="btn" style="background:linear-gradient(135deg, #10b981 0%, #059669 100%);color:white;padding:14px;border-radius:10px;font-weight:600;box-shadow:0 4px 12px rgba(16,185,129,0.3);transition:all 0.3s;" onclick="copyQRLink()" onmouseover="this.style.transform='translateY(-2px)';this.style.boxShadow='0 6px 16px rgba(16,185,129,0.4)'" onmouseout="this.style.transform='translateY(0)';this.style.boxShadow='0 4px 12px rgba(16,185,129,0.3)'">
            📋<br><span style="font-size:13px;">复制链接</span>
          </button>
          <button class="btn" style="background:linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%);color:white;padding:14px;border-radius:10px;font-weight:600;box-shadow:0 4px 12px rgba(139,92,246,0.3);transition:all 0.3s;" onclick="downloadQRCode()" onmouseover="this.style.transform='translateY(-2px)';this.style.boxShadow='0 6px 16px rgba(139,92,246,0.4)'" onmouseout="this.style.transform='translateY(0)';this.style.boxShadow='0 4px 12px rgba(139,92,246,0.3)'">
            ⬇️<br><span style="font-size:13px;">下载图片</span>
          </button>
        </div>
      </div>
    </div>
  </div>

  <!-- 自定义通知渠道配置模态框 -->
  <div id="channelModal" class="modal">
    <div class="modal-content" style="max-width:800px;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;">
        <h2 id="channelModalTitle">添加自定义通知渠道</h2>
        <button onclick="closeChannelModal()" style="background:none;border:none;font-size:24px;cursor:pointer;">×</button>
      </div>
      
      <form id="channelForm" onsubmit="saveChannel(event)">
        <input type="hidden" id="channelId">
        
        <div class="form-group">
          <label>渠道名称</label>
          <input type="text" id="channelName" placeholder="例如：Slack通知、钉钉机器人" required>
          <div style="font-size:12px;color:#999;margin-top:4px;">便于识别的渠道名称</div>
        </div>
        
        <div class="form-group">
          <label>通知类型</label>
          <select id="channelNotifyType">
            <option value="both">授权 + 聊天通知</option>
            <option value="auth">仅授权通知</option>
            <option value="chat">仅聊天通知</option>
          </select>
        </div>
        
        <div class="form-group">
          <label>请求方法</label>
          <select id="channelMethod">
            <option value="POST">POST</option>
            <option value="GET">GET</option>
            <option value="PUT">PUT</option>
          </select>
        </div>
        
        <div class="form-group">
          <label>请求地址 (URL)</label>
          <input type="url" id="channelUrl" placeholder="https://your-api.com/notify" required>
        </div>
        
        <div class="form-group">
          <label>请求头 (Headers) - JSON格式</label>
          <textarea id="channelHeaders" rows="3" placeholder='{"Content-Type": "application/json", "Authorization": "Bearer YOUR_TOKEN"}'></textarea>
          <div style="font-size:12px;color:#999;margin-top:4px;">可选，JSON格式的HTTP请求头</div>
        </div>
        
        <div class="form-group">
          <label>
            请求体模板 (Body Template)
            <button type="button" class="btn" style="float:right;padding:4px 12px;font-size:12px;background:#3b82f6;color:white;" onclick="showVariableHelp()">📖 查看可用变量</button>
          </label>
          <textarea id="channelBody" rows="10" placeholder='{"text": "授权请求：{{qr_title}}", "location": "{{geo_city}}"}'></textarea>
          <div style="font-size:12px;color:#999;margin-top:4px;">
            使用 <code style="background:#f5f7fa;padding:2px 6px;border-radius:4px;">{{变量名}}</code> 格式引用动态数据
          </div>
        </div>
        
        <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px;">
          <input type="checkbox" id="channelEnabled" style="width:20px;height:20px;">
          <label for="channelEnabled" style="margin:0;">启用此渠道</label>
        </div>
        
        <div style="display:flex;gap:12px;">
          <button type="submit" class="btn btn-primary">💾 保存渠道</button>
          <button type="button" class="btn" style="background:#6b7280;color:white;" onclick="testChannel()">🧪 测试发送</button>
          <button type="button" class="btn btn-secondary" onclick="closeChannelModal()">取消</button>
        </div>
      </form>
    </div>
  </div>
  
  <!-- 变量帮助模态框(续 -->
  <div id="variableHelpModal" class="modal"><div class="modal-content" style="max-width:700px;max-height:90vh;overflow-y:auto;"><h2 style="margin-bottom:20px;">📖 可用变量说明</h2><div style="text-align:right;margin-bottom:20px;"><button onclick="closeVariableHelp()" style="background:#e0e0e0;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;">关闭</button></div><div style="background:#f9fafb;padding:20px;border-radius:8px;margin-bottom:20px;"><h3 style="font-size:16px;margin-bottom:12px;color:#333;">🔐 授权通知变量</h3><table style="width:100%;font-size:13px;border-collapse:collapse;"><tr><td style="padding:8px;background:white;border:1px solid #e0e0e0;width:40%;"><code>{{qr_id}}</code></td><td style="padding:8px;background:white;border:1px solid #e0e0e0;">二维码ID</td></tr><tr><td style="padding:8px;background:white;border:1px solid #e0e0e0;"><code>{{qr_title}}</code></td><td style="padding:8px;background:white;border:1px solid #e0e0e0;">二维码标题</td></tr><tr><td style="padding:8px;background:white;border:1px solid #e0e0e0;"><code>{{request_id}}</code></td><td style="padding:8px;background:white;border:1px solid #e0e0e0;">请求ID</td></tr><tr><td style="padding:8px;background:white;border:1px solid #e0e0e0;"><code>{{approve_url}}</code></td><td style="padding:8px;background:white;border:1px solid #e0e0e0;">批准链接</td></tr><tr><td style="padding:8px;background:white;border:1px solid #e0e0e0;"><code>{{reject_url}}</code></td><td style="padding:8px;background:white;border:1px solid #e0e0e0;">拒绝链接</td></tr><tr><td style="padding:8px;background:white;border:1px solid #e0e0e0;"><code>{{geo_city}}</code></td><td style="padding:8px;background:white;border:1px solid #e0e0e0;">访问城市</td></tr><tr><td style="padding:8px;background:white;border:1px solid #e0e0e0;"><code>{{geo_country}}</code></td><td style="padding:8px;background:white;border:1px solid #e0e0e0;">访问国家</td></tr><tr><td style="padding:8px;background:white;border:1px solid #e0e0e0;"><code>{{timestamp}}</code></td><td style="padding:8px;background:white;border:1px solid #e0e0e0;">Unix时间戳</td></tr><tr><td style="padding:8px;background:white;border:1px solid #e0e0e0;"><code>{{time_formatted}}</code></td><td style="padding:8px;background:white;border:1px solid #e0e0e0;">格式化时间</td></tr></table></div><div style="background:#f0fdf4;padding:20px;border-radius:8px;margin-bottom:20px;"><h3 style="font-size:16px;margin-bottom:12px;color:#333;">💬 聊天通知变量</h3><table style="width:100%;font-size:13px;border-collapse:collapse;"><tr><td style="padding:8px;background:white;border:1px solid #e0e0e0;width:40%;"><code>{{session_id}}</code></td><td style="padding:8px;background:white;border:1px solid #e0e0e0;">会话ID</td></tr><tr><td style="padding:8px;background:white;border:1px solid #e0e0e0;"><code>{{user_message}}</code></td><td style="padding:8px;background:white;border:1px solid #e0e0e0;">用户消息内容</td></tr><tr><td style="padding:8px;background:white;border:1px solid #e0e0e0;"><code>{{accept_url}}</code></td><td style="padding:8px;background:white;border:1px solid #e0e0e0;">接受链接</td></tr></table></div><div style="background:#fffbeb;padding:16px;border-radius:8px;margin-bottom:20px;"><h3 style="font-size:14px;margin-bottom:8px;color:#92400e;">💡 示例</h3><pre style="background:white;padding:12px;border-radius:6px;overflow-x:auto;font-size:12px;line-height:1.6;"><code>{"text": "🔔 授权请求", "title": "{{qr_title}}", "location": "{{geo_city}}"}</code></pre></div></div></div>

  <script>
    let ws = null;
    let currentQRId = null;
    let currentImageUrl = '';
    
    // 连接 WebSocket
    function connectWebSocket() {
      const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
      ws = new WebSocket(\`\${protocol}//\${location.host}/ws\`);
      
      ws.onopen = () => {
        ws.send(JSON.stringify({ type: 'register_admin' }));
      };
      
      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        handleWebSocketMessage(data);
      };
      
      ws.onclose = () => {
        setTimeout(connectWebSocket, 3000);
      };
    }
    
    function handleWebSocketMessage(data) {
      // 响应心跳ping
      if (data.type === 'ping') {
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
        }
        return;
      }
      
      if (data.type === 'auth_requested') {
        showNotification('授权请求', \`有人请求查看 "\${data.qrTitle}" 的私密内容\`, [
          { text: '批准', class: 'btn-primary', onclick: \`approveRequest('\${data.qrId}', '\${data.requestId}', true)\` },
          { text: '拒绝', class: 'btn', onclick: \`approveRequest('\${data.qrId}', '\${data.requestId}', false)\` }
        ]);
      }
      
      if (data.type === 'chat_requested') {
        const messagePreview = data.message ? data.message.substring(0, 50) + (data.message.length > 50 ? '...' : '') : '(图片消息)';
        showNotification('聊天请求', \`有人想要联系您\\n\\n二维码: "\${data.qrTitle}"\\n消息: \${messagePreview}\`, [
          { text: '接受并聊天', class: 'btn-primary', onclick: \`acceptChat('\${data.qrId}', '\${data.sessionId}')\` },
          { text: '拒绝', class: 'btn', onclick: \`rejectChat('\${data.qrId}', '\${data.sessionId}')\` }
        ]);
      }
      
      // 接收用户发来的聊天消息
      if (data.type === 'chat_message' && data.from === 'user') {
        // 如果聊天窗口打开且是当前会话，显示消息
        if (currentChatSession === data.sessionId) {
          addAdminChatMessage(data.message, 'user', data.imageUrl, data.timestamp);
        } else {
          // 否则显示通知
          showNotification('新消息', \`收到来自访客的消息\`, [
            { text: '查看', class: 'btn-primary', onclick: \`openExistingChat('\${data.qrId}', '\${data.sessionId}')\` }
          ]);
        }
      }
    }
    
    async function openExistingChat(qrId, sessionId) {
      currentChatQrId = qrId;
      currentChatSession = sessionId;
      
      try {
        const response = await fetch('/api/admin/qrcodes');
        const qrcodes = await response.json();
        const qr = qrcodes.find(q => q.id === qrId);
        
        if (qr) {
          openChatWindow(qr.title, sessionId);
          
          // 加载聊天历史
          const chatResponse = await fetch(\`/api/admin/qrcodes/\${qrId}/chat\`);
          const chatData = await chatResponse.json();
          
          if (chatData.sessions && chatData.sessions[sessionId]) {
            const messages = chatData.sessions[sessionId].messages || [];
            messages.forEach(msg => {
              addAdminChatMessage(msg.message, msg.from, msg.imageUrl, msg.timestamp);
            });
          }
        }
      } catch (e) {
        console.error('Failed to open chat:', e);
      }
    }
    
    function showNotification(title, body, actions = []) {
      document.getElementById('notifTitle').textContent = title;
      document.getElementById('notifBody').textContent = body;
      
      const actionsContainer = document.getElementById('notifActions');
      actionsContainer.innerHTML = '';
      actions.forEach(action => {
        const btn = document.createElement('button');
        btn.className = 'btn ' + (action.class || '');
        btn.textContent = action.text;
        btn.onclick = () => {
          if (action.onclick) eval(action.onclick);
          closeNotification();
        };
        actionsContainer.appendChild(btn);
      });
      
      document.getElementById('notification').classList.add('show');
    }
    
    function closeNotification() {
      document.getElementById('notification').classList.remove('show');
    }
    
    let currentChatSession = null;
    let currentChatQrId = null;
    let currentAdminImageUrl = '';
    
    async function approveRequest(qrId, requestId, approve) {
      if (ws && ws.readyState === WebSocket.OPEN) {
        // 如果批准，先获取二维码数据
        let qrData = null;
        if (approve) {
          try {
            const response = await fetch('/api/admin/qrcodes');
            const qrcodes = await response.json();
            qrData = qrcodes.find(q => q.id === qrId);
          } catch (e) {
            console.error('Failed to fetch QR data:', e);
          }
        }
        
        ws.send(JSON.stringify({
          type: 'approval_decision',
          payload: {
            qrId,
            requestId,
            action: approve ? 'approve' : 'reject',
            qr: qrData
          }
        }));
      }
    }
    
    async function acceptChat(qrId, sessionId) {
      if (ws && ws.readyState === WebSocket.OPEN) {
        // 保存当前会话信息
        currentChatQrId = qrId;
        currentChatSession = sessionId;
        
        // 发送接受决策
        ws.send(JSON.stringify({
          type: 'chat_request_decision',
          payload: {
            qrId,
            sessionId,
            action: 'accept'
          }
        }));
        
        // 获取聊天请求信息（包含初始消息）
        try {
          const requestData = await fetch(\`/api/admin/chat-request/\${sessionId}\`).then(r => r.json());
          
          // 获取二维码信息
          const response = await fetch('/api/admin/qrcodes');
          const qrcodes = await response.json();
          const qr = qrcodes.find(q => q.id === qrId);
          
          if (qr) {
            // 打开聊天窗口
            openChatWindow(qr.title, sessionId);
            
            // 显示用户的初始消息
            if (requestData && (requestData.message || requestData.imageUrl)) {
              addAdminChatMessage(requestData.message, 'user', requestData.imageUrl, requestData.timestamp);
            }
          }
        } catch (e) {
          console.error('Failed to fetch chat request:', e);
        }
      }
    }
    
    async function rejectChat(qrId, sessionId) {
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
          type: 'chat_request_decision',
          payload: {
            qrId,
            sessionId,
            action: 'reject'
          }
        }));
      }
    }
    
    function openChatWindow(qrTitle, sessionId) {
      document.getElementById('chatWindowTitle').textContent = \`与访客聊天 - \${qrTitle}\`;
      document.getElementById('chatInfo').textContent = \`会话ID: \${sessionId}\`;
      document.getElementById('adminChatMessages').innerHTML = '';
      document.getElementById('chatWindow').classList.add('show');
    }
    
    function closeChatWindow() {
      document.getElementById('chatWindow').classList.remove('show');
      currentChatSession = null;
      currentChatQrId = null;
    }
    
    function addAdminChatMessage(message, from, imageUrl, time) {
      const messagesContainer = document.getElementById('adminChatMessages');
      const messageDiv = document.createElement('div');
      messageDiv.className = \`chat-message \${from}\`;
      messageDiv.style.marginBottom = '16px';
      messageDiv.style.display = 'flex';
      messageDiv.style.gap = '8px';
      
      if (from === 'admin') {
        messageDiv.style.flexDirection = 'row-reverse';
      }
      
      const bubble = document.createElement('div');
      bubble.className = 'message-bubble';
      bubble.style.maxWidth = '70%';
      bubble.style.padding = '12px 16px';
      bubble.style.borderRadius = '12px';
      bubble.style.fontSize = '14px';
      bubble.style.lineHeight = '1.5';
      bubble.style.wordBreak = 'break-word';
      
      if (from === 'user') {
        bubble.style.background = '#f0f0f0';
        bubble.style.color = '#333';
      } else {
        bubble.style.background = 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)';
        bubble.style.color = 'white';
      }
      
      if (message) {
        const contentDiv = document.createElement('div');
        contentDiv.innerHTML = marked.parse(message);
        bubble.appendChild(contentDiv);
      }
      
      if (imageUrl) {
        const img = document.createElement('img');
        img.src = imageUrl;
        img.style.maxWidth = '200px';
        img.style.borderRadius = '8px';
        img.style.marginTop = message ? '8px' : '0';
        img.style.cursor = 'pointer';
        img.onclick = () => window.open(imageUrl, '_blank');
        bubble.appendChild(img);
      }
      
      if (time) {
        const timeDiv = document.createElement('div');
        timeDiv.className = 'message-time';
        timeDiv.style.fontSize = '11px';
        timeDiv.style.marginTop = '6px';
        timeDiv.style.opacity = '0.8';
        timeDiv.textContent = new Date(time).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
        bubble.appendChild(timeDiv);
      }
      
      messageDiv.appendChild(bubble);
      messagesContainer.appendChild(messageDiv);
      messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }
    
    async function uploadAdminImage(input) {
      const file = input.files[0];
      if (!file) return;
      
      const formData = new FormData();
      formData.append('image', file);
      
      try {
        const response = await fetch('/api/upload', {
          method: 'POST',
          body: formData
        });
        
        const result = await response.json();
        if (result.success) {
          currentAdminImageUrl = result.url;
          document.getElementById('adminImagePreview').innerHTML = \`
            <div style="position:relative;display:inline-block;">
              <img src="\${result.url}" style="max-width:150px;border-radius:8px;border:2px solid #e0e0e0;">
              <button onclick="clearAdminImage()" style="position:absolute;top:4px;right:4px;background:rgba(0,0,0,0.7);color:white;border:none;border-radius:50%;width:24px;height:24px;cursor:pointer;font-size:16px;line-height:1;">×</button>
            </div>
          \`;
        }
      } catch (e) {
        console.error('Upload error:', e);
        alert('图片上传失败');
      }
    }
    
    function clearAdminImage() {
      currentAdminImageUrl = '';
      document.getElementById('adminImagePreview').innerHTML = '';
    }
    
    function sendAdminMessage() {
      const input = document.getElementById('adminChatInput');
      const message = input.value.trim();
      
      if (!message && !currentAdminImageUrl) {
        return;
      }
      
      if (ws && ws.readyState === WebSocket.OPEN && currentChatSession) {
        // 发送消息
        ws.send(JSON.stringify({
          type: 'chat_message',
          payload: {
            qrId: currentChatQrId,
            sessionId: currentChatSession,
            from: 'admin',
            message: message,
            imageUrl: currentAdminImageUrl,
            timestamp: Date.now()
          },
          to: 'user'
        }));
        
        // 在聊天窗口显示自己的消息
        addAdminChatMessage(message, 'admin', currentAdminImageUrl, Date.now());
        
        // 清空输入
        input.value = '';
        clearAdminImage();
      }
    }
    
    function switchTab(tab) {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
      
      // 找到对应的tab按钮并激活
      const tabs = document.querySelectorAll('.tab');
      tabs.forEach((t, index) => {
        const tabNames = ['normal', 'auth', 'contact', 'chats', 'settings'];
        if (tabNames[index] === tab) {
          t.classList.add('active');
        }
      });
      
      document.getElementById(tab + 'Tab').classList.add('active');
      
      // 更新URL Hash
      window.location.hash = tab;
      
      if (tab === 'settings') {
        loadSettings();
      } else if (tab === 'chats') {
        loadChatHistory();
      }
    }
    
    // 根据URL Hash恢复标签状态
    function restoreTabFromHash() {
      const hash = window.location.hash.slice(1); // 移除 #
      const validTabs = ['normal', 'auth', 'contact', 'chats', 'settings'];
      
      if (hash && validTabs.includes(hash)) {
        switchTab(hash);
      }
    }
    
    let currentHistoryQrId = null;
    let currentHistorySessionId = null;
    
    async function loadChatHistory() {
      try {
        const response = await fetch('/api/admin/qrcodes');
        const qrcodes = await response.json();
        
        const contactQrs = qrcodes.filter(qr => qr.type === 'contact');
        
        let historyHtml = '';
        
        for (const qr of contactQrs) {
          const chatResponse = await fetch(\`/api/admin/qrcodes/\${qr.id}/chat\`);
          const chatData = await chatResponse.json();
          
          if (chatData.sessions && Object.keys(chatData.sessions).length > 0) {
            historyHtml += \`
              <div style="margin-bottom:24px;padding:20px;background:#f9fafb;border-radius:12px;">
                <h4 style="margin-bottom:12px;color:#333;">\${qr.title}</h4>
            \`;
            
            for (const [sessionId, session] of Object.entries(chatData.sessions)) {
              const messageCount = session.messages ? session.messages.length : 0;
              const lastMessage = session.messages && session.messages.length > 0 
                ? session.messages[session.messages.length - 1] 
                : null;
              const lastTime = lastMessage ? new Date(lastMessage.timestamp).toLocaleString('zh-CN') : '-';
              
              historyHtml += \`
                <div style="padding:16px;background:white;border-radius:8px;margin-bottom:12px;cursor:pointer;transition:transform 0.2s;" onclick="viewChatHistory('\${qr.id}', '\${sessionId}', '\${qr.title}')" onmouseover="this.style.transform='translateY(-2px)'" onmouseout="this.style.transform='translateY(0)'">
                  <div style="display:flex;justify-content:space-between;align-items:center;">
                    <div>
                      <div style="font-weight:600;margin-bottom:4px;">会话 ID: \${sessionId.substring(0, 20)}...</div>
                      <div style="font-size:13px;color:#666;">消息数: \${messageCount} | 最后活动: \${lastTime}</div>
                    </div>
                    <button class="btn" style="background:#667eea;color:white;padding:8px 16px;" onclick="event.stopPropagation(); viewChatHistory('\${qr.id}', '\${sessionId}', '\${qr.title}')">查看</button>
                  </div>
                </div>
              \`;
            }
            
            historyHtml += '</div>';
          }
        }
        
        if (!historyHtml) {
          historyHtml = '<div style="text-align:center;padding:40px;color:#999;">暂无聊天记录</div>';
        }
        
        document.getElementById('chatHistoryList').innerHTML = historyHtml;
      } catch (e) {
        console.error('Load chat history failed:', e);
        document.getElementById('chatHistoryList').innerHTML = '<div style="text-align:center;padding:40px;color:#f56565;">加载失败，请重试</div>';
      }
    }
    
    async function viewChatHistory(qrId, sessionId, qrTitle) {
      currentHistoryQrId = qrId;
      currentHistorySessionId = sessionId;
      
      document.getElementById('historyModalTitle').textContent = \`聊天记录 - \${qrTitle}\`;
      document.getElementById('historyModalInfo').textContent = \`会话ID: \${sessionId}\`;
      
      try {
        const response = await fetch(\`/api/admin/qrcodes/\${qrId}/chat\`);
        const chatData = await response.json();
        
        const messagesContainer = document.getElementById('historyMessages');
        messagesContainer.innerHTML = '';
        
        if (chatData.sessions && chatData.sessions[sessionId]) {
          const messages = chatData.sessions[sessionId].messages || [];
          
          messages.forEach(msg => {
            addHistoryMessage(msg.message, msg.from, msg.imageUrl, msg.timestamp);
          });
        }
        
        document.getElementById('chatHistoryModal').classList.add('show');
      } catch (e) {
        console.error('Load chat detail failed:', e);
        alert('加载聊天详情失败');
      }
    }
    
    function addHistoryMessage(message, from, imageUrl, time) {
      const messagesContainer = document.getElementById('historyMessages');
      const messageDiv = document.createElement('div');
      messageDiv.style.marginBottom = '16px';
      messageDiv.style.display = 'flex';
      messageDiv.style.gap = '8px';
      
      if (from === 'admin') {
        messageDiv.style.flexDirection = 'row-reverse';
      }
      
      const bubble = document.createElement('div');
      bubble.style.maxWidth = '70%';
      bubble.style.padding = '12px 16px';
      bubble.style.borderRadius = '12px';
      bubble.style.fontSize = '14px';
      bubble.style.lineHeight = '1.5';
      bubble.style.wordBreak = 'break-word';
      
      if (from === 'user') {
        bubble.style.background = '#f0f0f0';
        bubble.style.color = '#333';
      } else {
        bubble.style.background = 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)';
        bubble.style.color = 'white';
      }
      
      if (message) {
        const contentDiv = document.createElement('div');
        contentDiv.innerHTML = marked.parse(message);
        bubble.appendChild(contentDiv);
      }
      
      if (imageUrl) {
        const img = document.createElement('img');
        img.src = imageUrl;
        img.style.maxWidth = '200px';
        img.style.borderRadius = '8px';
        img.style.marginTop = message ? '8px' : '0';
        img.style.cursor = 'pointer';
        img.onclick = () => window.open(imageUrl, '_blank');
        bubble.appendChild(img);
      }
      
      if (time) {
        const timeDiv = document.createElement('div');
        timeDiv.style.fontSize = '11px';
        timeDiv.style.marginTop = '6px';
        timeDiv.style.opacity = '0.8';
        timeDiv.textContent = new Date(time).toLocaleString('zh-CN');
        bubble.appendChild(timeDiv);
      }
      
      messageDiv.appendChild(bubble);
      messagesContainer.appendChild(messageDiv);
    }
    
    function closeChatHistoryModal() {
      document.getElementById('chatHistoryModal').classList.remove('show');
    }
    
    async function confirmDeleteChatHistory() {
      if (!confirm('确定要删除此聊天记录吗？此操作不可恢复！')) {
        return;
      }
      
      try {
        const response = await fetch(\`/api/admin/qrcodes/\${currentHistoryQrId}/chat/\${currentHistorySessionId}\`, {
          method: 'DELETE'
        });
        
        if (response.ok) {
          alert('删除成功');
          closeChatHistoryModal();
          loadChatHistory();
        } else {
          throw new Error('Delete failed');
        }
      } catch (e) {
        console.error('Delete failed:', e);
        alert('删除失败，请重试');
      }
    }
    
    function showCreateModal(type) {
      currentQRId = null;
      document.getElementById('modalTitle').textContent = '创建' + getTypeName(type);
      document.getElementById('qrType').value = type;
      document.getElementById('privateContentGroup').style.display = type === 'auth' ? 'block' : 'none';
      
      document.getElementById('qrForm').reset();
      document.getElementById('qrModal').classList.add('show');
    }
    
    function showEditModal(id) {
      // 先从缓存获取
      let qr = cachedQRCodes[id];
      
      if (qr) {
        currentQRId = id;
        document.getElementById('modalTitle').textContent = '编辑二维码';
        document.getElementById('qrId').value = id;
        document.getElementById('qrType').value = qr.type;
        document.getElementById('qrTitle').value = qr.title;
        document.getElementById('qrContent').value = qr.content || '';
        document.getElementById('qrPrivateContent').value = qr.privateContent || '';
        document.getElementById('privateContentGroup').style.display = qr.type === 'auth' ? 'block' : 'none';
        currentImageUrl = qr.image || '';
        document.getElementById('qrModal').classList.add('show');
      } else {
        // 缓存没有，从API获取
        fetch('/api/admin/qrcodes/' + id)
          .then(r => r.json())
          .then(qr => {
            cachedQRCodes[id] = qr;
            currentQRId = id;
            document.getElementById('modalTitle').textContent = '编辑二维码';
            document.getElementById('qrId').value = id;
            document.getElementById('qrType').value = qr.type;
            document.getElementById('qrTitle').value = qr.title;
            document.getElementById('qrContent').value = qr.content || '';
            document.getElementById('qrPrivateContent').value = qr.privateContent || '';
            document.getElementById('privateContentGroup').style.display = qr.type === 'auth' ? 'block' : 'none';
            currentImageUrl = qr.image || '';
            document.getElementById('qrModal').classList.add('show');
          });
      }
    }
    
    function closeModal() {
      document.getElementById('qrModal').classList.remove('show');
    }
    
    async function saveQR(event) {
      event.preventDefault();
      const formData = new FormData(event.target);
      const type = formData.get('type');
      
      const data = {
        title: formData.get('title'),
        type: type,
        content: formData.get('content'),
        privateContent: formData.get('privateContent'),
        image: currentImageUrl
      };
      
      // 普通二维码更新/创建
      const url = currentQRId ? '/api/admin/qrcodes/' + currentQRId : '/api/admin/qrcodes';
      const method = currentQRId ? 'PUT' : 'POST';
      
      const response = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      
      if (response.ok) {
        const result = await response.json();
        
        // 更新缓存
        cachedQRCodes[result.id] = result;
        
        closeModal();
        
        if (currentQRId) {
          // 更新模式：只更新那一张卡片
          updateQRCard(currentQRId, result);
          showSuccessToast('二维码更新成功！');
        } else {
          // 创建模式：直接添加新卡片到列表开头
          addQRCard(result);
          showSuccessToast('二维码创建成功！');
        }
      }
    }
    
    function addQRCard(qr) {
      const list = document.getElementById(qr.type + 'List');
      const newCard = document.createElement('div');
      newCard.className = 'qr-card';
      newCard.style.animation = 'fadeIn 0.3s ease-in';
      newCard.setAttribute('data-qr-id', qr.id);
      newCard.innerHTML = \`
        <span class="qr-type type-\${qr.type}">\${getTypeName(qr.type)}</span>
        <div class="qr-title">\${qr.title}</div>
        <div style="font-size:13px;color:#666;margin-bottom:12px;">\${formatDate(qr.created_at)}</div>
        <div class="qr-actions">
          <button class="btn btn-primary" onclick="showQR('\${qr.id}', '\${qr.type}')">查看</button>
          <button class="btn" style="background:#e0e0e0;" onclick="showEditModal('\${qr.id}')">编辑</button>
          <button class="btn" style="background:#fee2e2;color:#991b1b;" onclick="deleteQR('\${qr.id}')">删除</button>
        </div>
      \`;
      list.insertBefore(newCard, list.firstChild);
    }
    
    function updateQRCard(qrId, qr) {
      const list = document.getElementById(qr.type + 'List');
      const card = list.querySelector(\`[data-qr-id="\${qrId}"]\`);
      
      if (card) {
        card.innerHTML = \`
          <span class="qr-type type-\${qr.type}">\${getTypeName(qr.type)}</span>
          <div class="qr-title">\${qr.title}</div>
          <div style="font-size:13px;color:#666;margin-bottom:12px;">\${formatDate(qr.updated_at || qr.created_at)}</div>
          <div class="qr-actions">
            <button class="btn btn-primary" onclick="showQR('\${qr.id}', '\${qr.type}')">查看</button>
            <button class="btn" style="background:#e0e0e0;" onclick="showEditModal('\${qr.id}')">编辑</button>
            <button class="btn" style="background:#fee2e2;color:#991b1b;" onclick="deleteQR('\${qr.id}')">删除</button>
          </div>
        \`;
        card.style.animation = 'pulse 0.5s ease-in-out';
        setTimeout(() => { card.style.animation = ''; }, 500);
      }
    }
    
    function showSuccessToast(message) {
      const toast = document.createElement('div');
      toast.style.cssText = \`
        position: fixed;
        top: 80px;
        right: 24px;
        background: linear-gradient(135deg, #10b981 0%, #059669 100%);
        color: white;
        padding: 16px 24px;
        border-radius: 12px;
        box-shadow: 0 4px 16px rgba(16, 185, 129, 0.3);
        z-index: 3000;
        font-weight: 600;
        animation: slideIn 0.3s ease-out;
      \`;
      toast.textContent = message;
      document.body.appendChild(toast);
      
      setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease-in';
        setTimeout(() => toast.remove(), 300);
      }, 2000);
    }
    
    function copyToClipboard(text) {
      navigator.clipboard.writeText(text).then(() => {
        alert('链接已复制到剪贴板');
      });
    }
    
    function downloadOfflineQR(qrUrl, title) {
      const link = document.createElement('a');
      link.href = qrUrl;
      link.download = title + '_离线二维码.png';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      showSuccessToast('二维码下载成功！');
    }
    
    async function uploadImage(input) {
      const file = input.files[0];
      if (!file) return;
      
      const formData = new FormData();
      formData.append('image', file);
      
      const response = await fetch('/api/upload', {
        method: 'POST',
        body: formData
      });
      
      const result = await response.json();
      if (result.success) {
        currentImageUrl = result.url;
        document.getElementById('imagePreview').innerHTML = \`<img src="\${result.url}" style="max-width:100%;max-height:200px;margin-top:12px;">\`;
      }
    }
    
    async function loadQRCodes() {
      const response = await fetch('/api/admin/qrcodes');
      const qrcodes = await response.json();
      
      // 更新缓存
      cachedQRCodes = {};
      qrcodes.forEach(qr => {
        cachedQRCodes[qr.id] = qr;
      });
      
      ['normal', 'auth', 'contact'].forEach(type => {
        const list = document.getElementById(type + 'List');
        const filtered = qrcodes.filter(qr => qr.type === type);
        
        list.innerHTML = filtered.map(qr => \`
          <div class="qr-card" data-qr-id="\${qr.id}">
            <span class="qr-type type-\${qr.type}">\${getTypeName(qr.type)}</span>
            <div class="qr-title">\${qr.title}</div>
            <div style="font-size:13px;color:#666;margin-bottom:12px;">\${formatDate(qr.created_at)}</div>
            <div class="qr-actions">
              <button class="btn btn-primary" onclick="showQR('\${qr.id}', '\${qr.type}')">查看</button>
              <button class="btn" style="background:#e0e0e0;" onclick="showEditModal('\${qr.id}')">编辑</button>
              <button class="btn" style="background:#fee2e2;color:#991b1b;" onclick="deleteQR('\${qr.id}')">删除</button>
            </div>
          </div>
        \`).join('');
      });
    }
    
    let currentViewQRUrl = '';
    let currentViewQRTitle = '';
    
    // 缓存已加载的二维码数据
    let cachedQRCodes = {};
    
    async function showQR(id, type) {
      const prefix = type === 'normal' ? 'n' : (type === 'auth' ? 'a' : 'c');
      const url = location.origin + '/' + prefix + '/' + id;
      
      // 先从缓存获取
      let qr = cachedQRCodes[id];
      
      // 如果缓存中没有，从API获取
      if (!qr) {
        try {
          const response = await fetch('/api/admin/qrcodes/' + id);
          if (response.ok) {
            qr = await response.json();
            cachedQRCodes[id] = qr; // 缓存起来
          }
        } catch (e) {
          console.error('Failed to fetch QR code:', e);
        }
      }
      
      if (qr) {
        currentViewQRUrl = url;
        currentViewQRTitle = qr.title;
        
        // 设置模态框内容
        document.getElementById('qrViewTitle').textContent = qr.title;
        document.getElementById('qrViewType').textContent = getTypeName(qr.type);
        document.getElementById('qrViewUrl').textContent = url;
        
        // 生成高分辨率二维码图片（600x600）
        const qrImageUrl = '/qr?text=' + encodeURIComponent(url) + '&size=600';
        document.getElementById('qrViewImage').src = qrImageUrl;
        
        // 显示模态框
        document.getElementById('qrViewModal').classList.add('show');
      } else {
        alert('无法加载二维码信息');
      }
    }
    
    function closeQRViewModal() {
      document.getElementById('qrViewModal').classList.remove('show');
    }
    
    function openQRLink() {
      window.open(currentViewQRUrl, '_blank');
    }
    
    function copyQRLink() {
      navigator.clipboard.writeText(currentViewQRUrl).then(() => {
        showSuccessToast('链接已复制到剪贴板！');
      }).catch(() => {
        alert('复制失败，请手动复制');
      });
    }
    
    function downloadQRCode() {
      const img = document.getElementById('qrViewImage');
      
      // 创建一个canvas来下载更高质量的二维码
      const canvas = document.createElement('canvas');
      canvas.width = 1200;
      canvas.height = 1200;
      const ctx = canvas.getContext('2d');
      
      // 白色背景
      ctx.fillStyle = 'white';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      
      // 加载高分辨率二维码
      const highResImg = new Image();
      highResImg.crossOrigin = 'anonymous';
      highResImg.src = '/qr?text=' + encodeURIComponent(currentViewQRUrl) + '&size=1000';
      
      highResImg.onload = function() {
        // 居中绘制二维码
        const padding = 100;
        ctx.drawImage(highResImg, padding, padding, 1000, 1000);
        
        // 下载
        canvas.toBlob(function(blob) {
          const url = URL.createObjectURL(blob);
          const link = document.createElement('a');
          link.href = url;
          link.download = currentViewQRTitle + '_二维码.png';
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);
          URL.revokeObjectURL(url);
          showSuccessToast('二维码下载成功！');
        }, 'image/png');
      };
      
      highResImg.onerror = function() {
        // 降级方案：直接下载当前显示的图片
        const link = document.createElement('a');
        link.href = img.src;
        link.download = currentViewQRTitle + '_二维码.png';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        showSuccessToast('二维码下载成功！');
      };
    }
    
    async function deleteQR(id) {
      if (!confirm('确定要删除此二维码吗?')) return;
      await fetch(\`/api/admin/qrcodes/\${id}\`, { method: 'DELETE' });
      loadQRCodes();
    }
    
    function getTypeName(type) {
      const names = { normal: '普通二维码', auth: '授权二维码', contact: '联系二维码' };
      return names[type] || type;
    }
    
    async function loadSettings() {
      const response = await fetch('/api/admin/config');
      const config = await response.json();
      
      document.getElementById('baseUrl').value = config.base_url || '';
      document.getElementById('hmacSecret').value = config.hmac_secret || '';
      
      // 加载Webhook配置
      document.getElementById('qywxWebhook').value = config.qywx_webhook || '';
      document.getElementById('enableWebhook').checked = config.enable_webhook || false;
      toggleWebhookFields();
      
      // 加载应用通知配置
      document.getElementById('qywxAppUrl').value = config.qywx_app_url || '';
      document.getElementById('qywxAppCode').value = config.qywx_app_code || '';
      document.getElementById('enableApp').checked = config.enable_app || false;
      toggleAppFields();
      
      // 加载自定义渠道
      loadCustomChannels();
    }
    
    // ==================== 自定义通知渠道管理 ====================
    
    let currentChannelId = null;
    
    async function loadCustomChannels() {
      try {
        const response = await fetch('/api/admin/channels');
        const channels = await response.json();
        
        const container = document.getElementById('customChannelsList');
        
        if (!channels || channels.length === 0) {
          container.innerHTML = '<div style="text-align:center;padding:40px;color:#999;background:#f9fafb;border-radius:8px;border:2px dashed #e0e0e0;">📭 暂无自定义渠道<br><span style="font-size:13px;margin-top:8px;display:block;">点击上方"+ 添加渠道"按钮创建第一个自定义通知渠道</span></div>';
          return;
        }
        
        container.innerHTML = channels.map(function(ch) {
          const typeText = ch.notifyType === 'both' ? '授权 + 聊天' : (ch.notifyType === 'auth' ? '仅授权' : '仅聊天');
          const statusBadge = ch.enabled ? '<span style="background:#10b981;color:white;padding:4px 10px;border-radius:6px;font-size:11px;font-weight:600;">✓ 已启用</span>' : '<span style="background:#ef4444;color:white;padding:4px 10px;border-radius:6px;font-size:11px;font-weight:600;">✗ 已禁用</span>';
          
          return '<div style="border:2px solid ' + (ch.enabled ? '#10b981' : '#e0e0e0') + ';border-radius:12px;padding:20px;margin-bottom:16px;background:' + (ch.enabled ? '#f0fdf4' : 'white') + ';">' +
            '<div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:12px;">' +
              '<div style="flex:1;">' +
                '<div style="font-weight:600;font-size:16px;color:#333;margin-bottom:4px;">🔧 ' + ch.name + '</div>' +
                '<div style="font-size:13px;color:#666;">类型: ' + typeText + ' | 方法: ' + ch.method + '</div>' +
              '</div>' +
              statusBadge +
            '</div>' +
            '<div style="font-size:12px;color:#666;background:white;padding:10px;border-radius:6px;margin-bottom:12px;font-family:monospace;word-break:break-all;">' + ch.url + '</div>' +
            '<div style="display:flex;gap:8px;">' +
              '<button class="btn" style="padding:8px 16px;font-size:13px;background:#667eea;color:white;" onclick="editChannel(\\'' + ch.id + '\\')">✏️ 编辑</button>' +
              '<button class="btn" style="padding:8px 16px;font-size:13px;background:#8b5cf6;color:white;" onclick="testCustomChannel(\\'' + ch.id + '\\')">🧪 测试</button>' +
              '<button class="btn" style="padding:8px 16px;font-size:13px;background:#ef4444;color:white;" onclick="deleteChannel(\\'' + ch.id + '\\')">🗑️ 删除</button>' +
            '</div>' +
          '</div>';
        }).join('');
      } catch (error) {
        console.error('Load custom channels failed:', error);
      }
    }
    
    function showAddChannelModal() {
      currentChannelId = null;
      document.getElementById('channelModalTitle').textContent = '添加自定义通知渠道';
      document.getElementById('channelForm').reset();
      document.getElementById('channelId').value = '';
      document.getElementById('channelEnabled').checked = true;
      document.getElementById('channelModal').classList.add('show');
    }
    
    async function editChannel(channelId) {
      try {
        const response = await fetch('/api/admin/channels/' + channelId);
        const channel = await response.json();
        
        currentChannelId = channelId;
        document.getElementById('channelModalTitle').textContent = '编辑通知渠道';
        document.getElementById('channelId').value = channel.id;
        document.getElementById('channelName').value = channel.name;
        document.getElementById('channelNotifyType').value = channel.notifyType;
        document.getElementById('channelMethod').value = channel.method;
        document.getElementById('channelUrl').value = channel.url;
        document.getElementById('channelHeaders').value = JSON.stringify(channel.headers || {}, null, 2);
        document.getElementById('channelBody').value = channel.bodyTemplate;
        document.getElementById('channelEnabled').checked = channel.enabled;
        
        document.getElementById('channelModal').classList.add('show');
      } catch (error) {
        alert('加载渠道失败：' + error.message);
      }
    }
    
    function closeChannelModal() {
      document.getElementById('channelModal').classList.remove('show');
      currentChannelId = null;
    }
    
    async function saveChannel(event) {
      event.preventDefault();
      
      const channelId = document.getElementById('channelId').value;
      const channelData = {
        name: document.getElementById('channelName').value,
        notifyType: document.getElementById('channelNotifyType').value,
        method: document.getElementById('channelMethod').value,
        url: document.getElementById('channelUrl').value,
        headers: {},
        bodyTemplate: document.getElementById('channelBody').value,
        enabled: document.getElementById('channelEnabled').checked
      };
      
      // 解析Headers
      const headersText = document.getElementById('channelHeaders').value.trim();
      if (headersText) {
        try {
          channelData.headers = JSON.parse(headersText);
        } catch (e) {
          alert('请求头格式错误，请输入有效的JSON格式');
          return;
        }
      }
      
      try {
        const url = channelId ? '/api/admin/channels/' + channelId : '/api/admin/channels';
        const method = channelId ? 'PUT' : 'POST';
        
        const response = await fetch(url, {
          method: method,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(channelData)
        });
        
        if (response.ok) {
          closeChannelModal();
          loadCustomChannels();
          showSuccessToast(channelId ? '渠道更新成功！' : '渠道创建成功！');
        } else {
          const error = await response.json();
          alert('保存失败：' + (error.error || '未知错误'));
        }
      } catch (error) {
        alert('保存失败：' + error.message);
      }
    }
    
    async function deleteChannel(channelId) {
      if (!confirm('确定要删除此通知渠道吗？')) return;
      
      try {
        const response = await fetch('/api/admin/channels/' + channelId, {
          method: 'DELETE'
        });
        
        if (response.ok) {
          loadCustomChannels();
          showSuccessToast('渠道删除成功！');
        } else {
          alert('删除失败');
        }
      } catch (error) {
        alert('删除失败：' + error.message);
      }
    }
    
    async function testChannel() {
      const channelData = {
        method: document.getElementById('channelMethod').value,
        url: document.getElementById('channelUrl').value,
        headers: {},
        bodyTemplate: document.getElementById('channelBody').value
      };
      
      const headersText = document.getElementById('channelHeaders').value.trim();
      if (headersText) {
        try {
          channelData.headers = JSON.parse(headersText);
        } catch (e) {
          alert('请求头格式错误，请输入有效的JSON格式');
          return;
        }
      }
      
      try {
        const response = await fetch('/api/admin/channels/test', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(channelData)
        });
        
        const result = await response.json();
        
        if (result.success) {
          showSuccessToast('测试通知发送成功！');
        } else {
          alert('测试失败：' + (result.error || '未知错误'));
        }
      } catch (error) {
        alert('测试失败：' + error.message);
      }
    }
    
    async function testCustomChannel(channelId) {
      try {
        const response = await fetch('/api/admin/channels/' + channelId + '/test', {
          method: 'POST'
        });
        
        const result = await response.json();
        
        if (result.success) {
          showSuccessToast('测试通知发送成功！');
        } else {
          alert('测试失败：' + (result.error || '未知错误'));
        }
      } catch (error) {
        alert('测试失败：' + error.message);
      }
    }
    
    function showVariableHelp() {
      document.getElementById('variableHelpModal').classList.add('show');
    }
    
    function closeVariableHelp() {
      document.getElementById('variableHelpModal').classList.remove('show');
    }
    
    // ==================== 结束自定义通知渠道管理 ====================
    
    function toggleWebhookFields() {
      const enabled = document.getElementById('enableWebhook').checked;
      document.getElementById('webhookFields').style.display = enabled ? 'block' : 'none';
    }
    
    function toggleAppFields() {
      const enabled = document.getElementById('enableApp').checked;
      document.getElementById('appFields').style.display = enabled ? 'block' : 'none';
    }
    
    async function saveSettings(event) {
      event.preventDefault();
      const formData = new FormData(event.target);
      
      const config = {
        base_url: formData.get('base_url'),
        hmac_secret: formData.get('hmac_secret'),
        enable_webhook: document.getElementById('enableWebhook').checked,
        qywx_webhook: formData.get('qywx_webhook') || '',
        enable_app: document.getElementById('enableApp').checked,
        qywx_app_url: formData.get('qywx_app_url') || '',
        qywx_app_code: formData.get('qywx_app_code') || ''
      };
      
      const response = await fetch('/api/admin/config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config)
      });
      
      if (response.ok) {
        showSuccessToast('设置保存成功！');
      } else {
        alert('保存失败，请重试');
      }
    }
    
    async function testNotification(event) {
      event.preventDefault();
      
      const enableWebhook = document.getElementById('enableWebhook').checked;
      const enableApp = document.getElementById('enableApp').checked;
      
      const config = {
        base_url: document.getElementById('baseUrl').value,
        enable_webhook: enableWebhook,
        qywx_webhook: enableWebhook ? document.getElementById('qywxWebhook').value : '',
        enable_app: enableApp,
        qywx_app_url: enableApp ? document.getElementById('qywxAppUrl').value : '',
        qywx_app_code: enableApp ? document.getElementById('qywxAppCode').value : ''
      };
      
      // 检查是否启用了任何通知渠道
      if (!enableWebhook && !enableApp) {
        alert('请先启用至少一个通知渠道');
        return;
      }
      
      try {
        const response = await fetch('/api/admin/test-notification', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(config)
        });
        
        const result = await response.json();
        
        if (result.success) {
          showSuccessToast('测试通知已发送！请查收');
        } else {
          alert('测试通知发送失败：' + (result.error || '未知错误'));
        }
      } catch (error) {
        alert('测试失败：' + error.message);
      }
    }
    
    function formatDate(timestamp) {
      return new Date(timestamp).toLocaleString('zh-CN');
    }
    
    // 初始化
    connectWebSocket();
    loadQRCodes();
    
    // 恢复标签状态（基于URL Hash）
    restoreTabFromHash();
    
    // 监听Hash变化
    window.addEventListener('hashchange', restoreTabFromHash);
  </script>
</body>
</html>`;
}


/**
 * 普通二维码页面
 */
function getNormalQRPage(qrId, qr) {
  const renderedContent = qr.content || '';
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${qr.title}</title>
  <script src="https://cdn.jsdelivr.net/npm/marked@11.1.1/marked.min.js"></script>
  <style>${getCommonStyles()}</style>
</head>
<body>
  <div class="card">
    <h1>${qr.title}</h1>
    ${qr.image ? `<div class="image-container"><img src="${qr.image}" alt="${qr.title}"></div>` : ''}
    <div class="content" id="content"></div>
  </div>
  <script>
    const content = \`${renderedContent.replace(/`/g, '\\`')}\`;
    document.getElementById('content').innerHTML = marked.parse(content);
  </script>
</body>
</html>`;
}

/**
 * 授权二维码页面
 */
function getAuthQRPage(qrId, qr, isOnline) {
  const renderedContent = qr.content || '';
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${qr.title} - 需要授权</title>
  <script src="https://cdn.jsdelivr.net/npm/marked@11.1.1/marked.min.js"></script>
  <style>
    ${getCommonStyles('#f093fb 0%, #f5576c 100%')}
    .icon { font-size: 64px; text-align: center; margin-bottom: 20px; }
    .btn { width: 100%; padding: 16px; background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; border: none; border-radius: 12px; font-size: 16px; font-weight: 600; cursor: pointer; transition: transform 0.2s; }
    .btn:hover { transform: translateY(-2px); }
    .btn:disabled { opacity: 0.6; cursor: not-allowed; }
    .private-data { display: none; margin-top: 24px; padding: 24px; background: #f9fafb; border-radius: 12px; border: 2px solid #10b981; }
    .private-data.show { display: block; }
    .private-data h3 { font-size: 18px; margin-bottom: 12px; color: #333; }
    .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.6); z-index: 1000; align-items: center; justify-content: center; }
    .modal.show { display: flex; animation: fadeIn 0.3s; }
    @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
    .modal-content { background: white; border-radius: 20px; padding: 32px; max-width: 400px; width: 90%; text-align: center; animation: slideUp 0.3s; }
    @keyframes slideUp { from { transform: translateY(50px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
    .modal-icon { font-size: 64px; margin-bottom: 16px; }
    .modal-title { font-size: 20px; font-weight: 600; margin-bottom: 12px; color: #333; }
    .modal-body { font-size: 15px; color: #666; line-height: 1.6; margin-bottom: 24px; }
    .modal-btn { padding: 12px 24px; border: none; border-radius: 10px; font-size: 15px; font-weight: 600; cursor: pointer; transition: all 0.2s; }
    .modal-btn-primary { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; }
    .modal-btn-primary:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(240, 147, 251, 0.4); }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">🔒</div>
    <h1>${qr.title}</h1>
    ${qr.image ? `<div class="image-container"><img src="${qr.image}" alt="${qr.title}"></div>` : ''}
    <div class="content" id="content"></div>
    
    <div class="status">
      ${isOnline 
        ? '✅ 管理员在线，将实时处理您的请求' 
        : '📱 管理员离线，已通过企业微信通知'}
    </div>
    
    <button class="btn" id="requestBtn" onclick="requestAccess()">
      🔓 申请访问授权
    </button>
    
    <div id="privateData" class="private-data">
      <h3>🔓 私密信息</h3>
      <div id="privateContent"></div>
    </div>
  </div>

  <!-- 等待授权弹窗 -->
  <div id="waitingModal" class="modal">
    <div class="modal-content">
      <div class="modal-icon">⏳</div>
      <div class="modal-title">等待授权中...</div>
      <div class="modal-body">已向管理员发送授权请求，请耐心等待</div>
    </div>
  </div>

  <!-- 授权成功弹窗 -->
  <div id="successModal" class="modal">
    <div class="modal-content">
      <div class="modal-icon">✅</div>
      <div class="modal-title">授权成功！</div>
      <div class="modal-body">您已获得查看权限，私密信息已显示</div>
      <button class="modal-btn modal-btn-primary" onclick="closeSuccessModal()">知道了</button>
    </div>
  </div>

  <!-- 授权拒绝弹窗 -->
  <div id="rejectModal" class="modal">
    <div class="modal-content">
      <div class="modal-icon">❌</div>
      <div class="modal-title">授权被拒绝</div>
      <div class="modal-body">管理员拒绝了您的访问请求</div>
      <button class="modal-btn modal-btn-secondary" onclick="closeRejectModal()">关闭</button>
    </div>
  </div>

  <script>
    const qrId = '${qrId}';
    const content = \`${renderedContent.replace(/`/g, '\\`')}\`;
    let ws = null;
    let currentRequestId = null;
    let isAdminOnline = ${isOnline};
    
    document.getElementById('content').innerHTML = marked.parse(content);
    
    // 立即连接WebSocket监听管理员状态
    connectWebSocketForStatus();
    
    function connectWebSocketForStatus() {
      const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
      ws = new WebSocket(\`\${protocol}//\${location.host}/ws\`);
      
      ws.onopen = () => {
        console.log('WebSocket connected, monitoring admin status');
      };
      
      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        
        // 实时监听管理员状态变化
        if (data.type === 'admin_status_changed') {
          isAdminOnline = data.isOnline;
          updateStatusDisplay();
          console.log('Admin status updated:', isAdminOnline ? 'online' : 'offline');
        }
        
        // 监听审批结果
        if (data.type === 'approval_result' && data.requestId === currentRequestId) {
          hideWaitingModal();
          if (data.action === 'approve' && data.qr) {
            showSuccess(data.qr);
          } else {
            showReject();
          }
        }
      };
      
      ws.onclose = () => {
        console.log('WebSocket closed, reconnecting in 3s...');
        // 断线后3秒重连
        setTimeout(connectWebSocketForStatus, 3000);
      };
      
      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
      };
    }
    
    function updateStatusDisplay() {
      const statusDiv = document.querySelector('.status');
      if (isAdminOnline) {
        statusDiv.innerHTML = '✅ 管理员在线，将实时处理您的请求';
        statusDiv.style.background = '#f0fdf4';
        statusDiv.style.borderColor = '#10b981';
        statusDiv.style.color = '#065f46';
      } else {
        statusDiv.innerHTML = '📱 管理员离线，已通过企业微信通知';
        statusDiv.style.background = '#fef3c7';
        statusDiv.style.borderColor = '#f59e0b';
        statusDiv.style.color = '#92400e';
      }
    }
    
    // 点击按钮后才申请授权
    async function requestAccess() {
      const btn = document.getElementById('requestBtn');
      btn.disabled = true;
      btn.textContent = '⏳ 请求中...';
      
      try {
        // 调用API发起授权请求
        const response = await fetch('/api/request-auth', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ qrId })
        });
        
        const result = await response.json();
        
        if (result.success) {
          currentRequestId = result.requestId;
          showWaitingModal();
          
          // 30秒超时
          setTimeout(() => {
            if (document.getElementById('waitingModal').classList.contains('show')) {
              hideWaitingModal();
              showError('等待超时，请稍后重试');
              
              btn.disabled = false;
              btn.textContent = '🔓 重新申请';
            }
          }, 30000);
        } else {
          throw new Error('Request failed');
        }
      } catch (error) {
        btn.disabled = false;
        btn.textContent = '🔓 申请访问授权';
        alert('请求失败，请重试');
      }
    }
    
    function showSuccess(qr) {
      if (qr.privateContent) {
        document.getElementById('privateContent').innerHTML = marked.parse(qr.privateContent);
        document.getElementById('privateData').classList.add('show');
      }
      document.getElementById('successModal').classList.add('show');
      document.getElementById('requestBtn').style.display = 'none';
    }
    
    function showReject() {
      document.getElementById('rejectModal').classList.add('show');
      
      const btn = document.getElementById('requestBtn');
      btn.disabled = false;
      btn.textContent = '🔓 重新申请';
    }
    
    function showError(message) {
      alert(message);
    }
    
    function showWaitingModal() {
      document.getElementById('waitingModal').classList.add('show');
    }
    
    function hideWaitingModal() {
      document.getElementById('waitingModal').classList.remove('show');
    }
    
    function closeSuccessModal() {
      document.getElementById('successModal').classList.remove('show');
    }
    
    function closeRejectModal() {
      document.getElementById('rejectModal').classList.remove('show');
    }
  </script>
</body>
</html>`;
}
/**
 * 联系二维码页面
 */
function getContactQRPage(qrId, sessionId, qr, isOnline) {
  const renderedContent = qr.content || '';
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${qr.title} - 发起联系</title>
  <script src="https://cdn.jsdelivr.net/npm/marked@11.1.1/marked.min.js"></script>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: linear-gradient(135deg, #4ade80 0%, #16a34a 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .card {
      background: white;
      border-radius: 16px;
      padding: 40px;
      max-width: 600px;
      width: 100%;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
    }
    .icon { font-size: 64px; text-align: center; margin-bottom: 20px; }
    h1 { font-size: 24px; margin-bottom: 16px; color: #333; text-align: center; }
    .content {
      font-size: 16px;
      line-height: 1.8;
      color: #555;
      margin-bottom: 24px;
    }
    .content img { max-width: 100%; border-radius: 12px; margin: 20px 0; }
    .status {
      background: #f0fdf4;
      border: 2px solid #10b981;
      border-radius: 12px;
      padding: 16px;
      margin-bottom: 24px;
      font-size: 14px;
      color: #065f46;
      text-align: center;
    }
    .message-input {
      display: flex;
      gap: 12px;
      margin-bottom: 16px;
      align-items: flex-end;
    }
    .message-input textarea {
      flex: 1;
      padding: 12px;
      border: 2px solid #e0e0e0;
      border-radius: 12px;
      font-size: 15px;
      font-family: inherit;
      resize: none;
      transition: border-color 0.3s;
    }
    .message-input textarea:focus {
      outline: none;
      border-color: #10b981;
    }
    .btn {
      padding: 12px 24px;
      background: linear-gradient(135deg, #4ade80 0%, #16a34a 100%);
      color: white;
      border: none;
      border-radius: 12px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: transform 0.2s, box-shadow 0.2s;
    }
    .btn:hover { 
      transform: translateY(-2px); 
      box-shadow: 0 4px 12px rgba(74, 222, 128, 0.4);
    }
    .btn:disabled { opacity: 0.6; cursor: not-allowed; }
    
    .image-upload {
      margin-bottom: 16px;
    }
    .image-upload input {
      display: none;
    }
    .image-upload label {
      display: inline-block;
      padding: 8px 16px;
      background: #f0f0f0;
      border-radius: 8px;
      cursor: pointer;
      font-size: 14px;
    }
    .image-preview {
      margin-top: 12px;
    }
    .image-preview img {
      max-width: 200px;
      max-height: 200px;
      border-radius: 8px;
    }
    
    .chat-container {
      display: none;
      margin-top: 24px;
    }
    .chat-container.show { display: block; }
    .chat-messages {
      max-height: 400px;
      overflow-y: auto;
      border: 2px solid #e0e0e0;
      border-radius: 12px;
      padding: 16px;
      margin-bottom: 16px;
    }
    .chat-message {
      margin-bottom: 16px;
      display: flex;
      gap: 8px;
      animation: fadeIn 0.3s ease-in;
    }
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(10px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .chat-message.user {
      flex-direction: row;
    }
    .chat-message.admin {
      flex-direction: row-reverse;
    }
    .message-bubble {
      max-width: 75%;
      padding: 12px 16px;
      border-radius: 16px;
      font-size: 15px;
      line-height: 1.6;
      word-break: break-word;
      box-shadow: 0 2px 8px rgba(0,0,0,0.08);
    }
    .chat-message.user .message-bubble {
      background: linear-gradient(135deg, #f0f0f0 0%, #e8e8e8 100%);
      color: #333;
      border-bottom-left-radius: 4px;
    }
    .chat-message.admin .message-bubble {
      background: linear-gradient(135deg, #4ade80 0%, #16a34a 100%);
      color: white;
      border-bottom-right-radius: 4px;
    }
    .message-bubble img {
      max-width: 100%;
      border-radius: 8px;
      margin-top: 8px;
      cursor: pointer;
      transition: transform 0.2s;
    }
    .message-bubble img:hover {
      transform: scale(1.02);
    }
    .message-time {
      font-size: 11px;
      margin-top: 6px;
      opacity: 0.7;
    }
    
    /* 美化弹窗 */
    .modal {
      display: none;
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0,0,0,0.6);
      z-index: 1000;
      align-items: center;
      justify-content: center;
    }
    .modal.show { display: flex; animation: fadeIn 0.3s; }
    @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
    .modal-content {
      background: white;
      border-radius: 20px;
      padding: 32px;
      max-width: 400px;
      width: 90%;
      text-align: center;
      animation: slideUp 0.3s;
    }
    @keyframes slideUp { from { transform: translateY(50px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
    .modal-icon { font-size: 64px; margin-bottom: 16px; }
    .modal-title { font-size: 20px; font-weight: 600; margin-bottom: 12px; color: #333; }
    .modal-body { font-size: 15px; color: #666; line-height: 1.6; margin-bottom: 24px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">💬</div>
    <h1>${qr.title}</h1>
    ${qr.image ? `<div style="text-align:center;margin:20px 0;"><img src="${qr.image}" style="max-width:100%;border-radius:12px;"></div>` : ''}
    <div class="content" id="content"></div>
    
    <div class="status">
      ${isOnline 
        ? '✅ 管理员在线，消息将实时送达' 
        : '📱 管理员离线，已通过企业微信通知'}
    </div>
    
    <div id="initialView">
      <div class="image-upload">
        <input type="file" id="imageInput" accept="image/*" onchange="handleImageSelect(this)">
        <label for="imageInput">📎 上传图片 (可选)</label>
        <div id="imagePreview" class="image-preview"></div>
      </div>
      
      <div class="message-input">
        <textarea id="messageText" placeholder="输入您的消息..." rows="3"></textarea>
      </div>
      <button class="btn" onclick="sendInitialMessage()">发送消息</button>
    </div>
    
    <div id="chatContainer" class="chat-container">
      <div class="chat-messages" id="chatMessages"></div>
      <div class="message-input">
        <input type="file" id="chatImageInput" accept="image/*" onchange="handleChatImageSelect(this)" style="display:none;">
        <button class="btn" style="background:#e0e0e0;color:#333;padding:12px 16px;border-radius:10px;" onclick="document.getElementById('chatImageInput').click()">
          📎 图片
        </button>
        <textarea id="chatInput" placeholder="输入消息..." rows="2"></textarea>
        <button class="btn" onclick="sendChatMessage()" style="align-self:flex-end;padding:12px 24px;border-radius:10px;">发送</button>
      </div>
      <div id="chatImagePreview" style="margin-top:12px;"></div>
    </div>
  </div>

  <!-- 等待接受弹窗 -->
  <div id="waitingModal" class="modal">
    <div class="modal-content">
      <div class="modal-icon">⏳</div>
      <div class="modal-title">等待管理员响应...</div>
      <div class="modal-body">您的消息已发送，请等待管理员接受</div>
    </div>
  </div>

  <!-- 接受成功弹窗 -->
  <div id="acceptedModal" class="modal">
    <div class="modal-content">
      <div class="modal-icon">✅</div>
      <div class="modal-title">对方已接受！</div>
      <div class="modal-body">现在可以开始聊天了</div>
      <button class="btn" onclick="closeAcceptedModal()">开始聊天</button>
    </div>
  </div>

  <!-- 拒绝弹窗 -->
  <div id="rejectedModal" class="modal">
    <div class="modal-content">
      <div class="modal-icon">❌</div>
      <div class="modal-title">请求被拒绝</div>
      <div class="modal-body">管理员拒绝了您的联系请求</div>
      <button class="btn" onclick="closeRejectedModal()" style="background:#e0e0e0;color:#666;">关闭</button>
    </div>
  </div>

  <script>
    const qrId = '${qrId}';
    const sessionId = '${sessionId}';
    const content = \`${renderedContent.replace(/`/g, '\\`')}\`;
    let ws = null;
    let currentImageUrl = '';
    let chatAccepted = false;
    let currentChatImageUrl = '';
    let isAdminOnline = ${hasAdmin};
    
    document.getElementById('content').innerHTML = marked.parse(content);
    
    // 立即连接WebSocket
    connectWebSocket();
    
    function updateStatusDisplay() {
      const statusDiv = document.querySelector('.status');
      if (isAdminOnline) {
        statusDiv.innerHTML = '✅ 管理员在线，消息将实时送达';
        statusDiv.style.background = '#f0fdf4';
        statusDiv.style.borderColor = '#10b981';
        statusDiv.style.color = '#065f46';
      } else {
        statusDiv.innerHTML = '📱 管理员离线，已通过企业微信通知';
        statusDiv.style.background = '#fef3c7';
        statusDiv.style.borderColor = '#f59e0b';
        statusDiv.style.color = '#92400e';
      }
    }
    
    function connectWebSocket() {
      const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
      ws = new WebSocket(\`\${protocol}//\${location.host}/ws\`);
      
      ws.onopen = () => {
        console.log('WebSocket connected');
      };
      
      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        handleWebSocketMessage(data);
        
        // 实时监听管理员状态变化
        if (data.type === 'admin_status_changed') {
          isAdminOnline = data.isOnline;
          updateStatusDisplay();
          console.log('Admin status updated:', isAdminOnline ? 'online' : 'offline');
        }
      };
      
      ws.onclose = () => {
        if (chatAccepted) {
          setTimeout(connectWebSocket, 3000);
        }
      };
    }
    
    function handleWebSocketMessage(data) {
      if (data.type === 'chat_request_result' && data.sessionId === sessionId) {
        hideWaitingModal();
        if (data.action === 'accept') {
          showAccepted();
        } else {
          showRejected();
        }
      }
      
      if (data.type === 'chat_message' && data.sessionId === sessionId && data.from === 'admin') {
        addMessageToChat(data.message, 'admin', data.imageUrl, data.timestamp);
      }
    }
    
    async function handleImageSelect(input) {
      const file = input.files[0];
      if (!file) return;
      
      const formData = new FormData();
      formData.append('image', file);
      
      const response = await fetch('/api/upload', {
        method: 'POST',
        body: formData
      });
      
      const result = await response.json();
      if (result.success) {
        currentImageUrl = result.url;
        document.getElementById('imagePreview').innerHTML = \`<img src="\${result.url}">\`;
      }
    }
    
    async function sendInitialMessage() {
      const message = document.getElementById('messageText').value.trim();
      if (!message && !currentImageUrl) {
        alert('请输入消息或上传图片');
        return;
      }
      
      try {
        // 先连接WebSocket
        connectWebSocket();
        
        // 调用API发送聊天请求
        const response = await fetch('/api/request-chat', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            qrId,
            sessionId,
            message,
            imageUrl: currentImageUrl
          })
        });
        
        const result = await response.json();
        
        if (result.success) {
          // 保存初始消息内容（接受后要显示）
          window.initialMessage = message;
          window.initialImageUrl = currentImageUrl;
          
          showWaitingModal();
          
          // 30秒超时
          setTimeout(() => {
            if (!chatAccepted) {
              hideWaitingModal();
              alert('等待超时，请稍后重试');
            }
          }, 30000);
        } else {
          throw new Error('Request failed');
        }
      } catch (error) {
        alert('发送失败，请重试');
      }
    }
    
    let currentChatImageUrl = '';
    
    async function handleChatImageSelect(input) {
      const file = input.files[0];
      if (!file) return;
      
      const formData = new FormData();
      formData.append('image', file);
      
      try {
        const response = await fetch('/api/upload', {
          method: 'POST',
          body: formData
        });
        
        const result = await response.json();
        if (result.success) {
          currentChatImageUrl = result.url;
          document.getElementById('chatImagePreview').innerHTML = \`<div style="position:relative;display:inline-block;"><img src="\${result.url}" style="max-width:150px;border-radius:8px;"><button onclick="clearChatImage()" style="position:absolute;top:4px;right:4px;background:rgba(0,0,0,0.6);color:white;border:none;border-radius:50%;width:24px;height:24px;cursor:pointer;">×</button></div>\`;
        }
      } catch (e) {
        console.error('Image upload failed:', e);
        alert('图片上传失败');
      }
    }
    
    function clearChatImage() {
      currentChatImageUrl = '';
      document.getElementById('chatImagePreview').innerHTML = '';
    }
    
    function sendChatMessage() {
      const message = document.getElementById('chatInput').value.trim();
      if (!message && !currentChatImageUrl) return;
      
      if (ws && ws.readyState === WebSocket.OPEN) {
        const msgData = {
          qrId,
          sessionId,
          from: 'user',
          message,
          imageUrl: currentChatImageUrl,
          timestamp: Date.now()
        };
        
        ws.send(JSON.stringify({
          type: 'chat_message',
          payload: msgData,
          to: 'admin'
        }));
        
        addMessageToChat(message, 'user', currentChatImageUrl, Date.now());
        document.getElementById('chatInput').value = '';
        clearChatImage();
      }
    }
    
    function addMessageToChat(message, from, imageUrl, timestamp) {
      const messagesContainer = document.getElementById('chatMessages');
      const messageDiv = document.createElement('div');
      messageDiv.className = \`chat-message \${from}\`;
      
      const bubble = document.createElement('div');
      bubble.className = 'message-bubble';
      
      if (message) {
        const contentDiv = document.createElement('div');
        contentDiv.innerHTML = marked.parse(message);
        bubble.appendChild(contentDiv);
      }
      
      if (imageUrl) {
        const img = document.createElement('img');
        img.src = imageUrl;
        img.style.maxWidth = '200px';
        img.style.borderRadius = '8px';
        img.style.marginTop = message ? '8px' : '0';
        bubble.appendChild(img);
      }
      
      if (timestamp) {
        const timeDiv = document.createElement('div');
        timeDiv.className = 'message-time';
        timeDiv.textContent = new Date(timestamp).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
        bubble.appendChild(timeDiv);
      }
      
      messageDiv.appendChild(bubble);
      messagesContainer.appendChild(messageDiv);
      messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }
    
    function showAccepted() {
      chatAccepted = true;
      document.getElementById('acceptedModal').classList.add('show');
    }
    
    function showRejected() {
      document.getElementById('rejectedModal').classList.add('show');
    }
    
    function closeAcceptedModal() {
      document.getElementById('acceptedModal').classList.remove('show');
      document.getElementById('initialView').style.display = 'none';
      document.getElementById('chatContainer').classList.add('show');
      
      // 显示初始发送的消息
      if (window.initialMessage || window.initialImageUrl) {
        addMessageToChat(window.initialMessage, 'user', window.initialImageUrl, Date.now());
      }
    }
    
    function closeRejectedModal() {
      document.getElementById('rejectedModal').classList.remove('show');
    }
    
    function showWaitingModal() {
      document.getElementById('waitingModal').classList.add('show');
    }
    
    function hideWaitingModal() {
      document.getElementById('waitingModal').classList.remove('show');
    }
  </script>
</body>
</html>`;
}

/**
 * 404页面
 */
function getNotFoundPage() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>未找到</title>
  <style>
    ${getCommonStyles()}
    .icon { font-size: 128px; text-align: center; margin-bottom: 20px; }
    .subtitle { text-align: center; color: #666; font-size: 18px; margin-bottom: 32px; }
    .btn { display: block; width: 100%; max-width: 300px; margin: 0 auto; padding: 14px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; text-decoration: none; border-radius: 8px; text-align: center; font-weight: 600; transition: transform 0.2s; }
    .btn:hover { transform: translateY(-2px); }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">🔍</div>
    <h1>未找到二维码</h1>
    <p class="subtitle">该二维码可能已失效或不存在</p>
  </div>
</body>
</html>`;
}

/**
 * 错误页面
 */
function getErrorPage(message) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>错误</title>
  <style>
    ${getCommonStyles('#f093fb 0%, #f5576c 100%')}
    .icon { font-size: 96px; text-align: center; margin-bottom: 20px; }
    .message { text-align: center; font-size: 18px; color: #666; line-height: 1.6; margin-bottom: 24px; }
  </style>
</head>
      background: white;
      border-radius: 16px;
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">⚠️</div>
    <h1>操作失败</h1>
    <p class="message">${message}</p>
  </div>
</body>
</html>`;
}

/**
 * 审批结果页面
 */
function getApprovalResultPage(action, qr) {
  const isApproved = action === 'approve';
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${isApproved ? '已批准' : '已拒绝'}</title>
  <style>
    ${getCommonStyles(isApproved ? '#10b981 0%, #059669 100%' : '#ef4444 0%, #dc2626 100%')}
    .icon { font-size: 96px; text-align: center; margin-bottom: 20px; }
    .result-message { text-align: center; font-size: 18px; color: #666; margin-bottom: 24px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">${isApproved ? '✅' : '❌'}</div>
    <h1>${isApproved ? '授权已批准' : '授权已拒绝'}</h1>
    <p>${isApproved ? `对 "${qr.title}" 的访问请求已批准，用户已收到通知` : `对 "${qr.title}" 的访问请求已拒绝`}</p>
  </div>
</body>
</html>`;
}

/**
 * 聊天决策结果页面
 */
function getChatDecisionResultPage(action, qr) {
  const isAccepted = action === 'accept';
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${isAccepted ? '已接受' : '已拒绝'}</title>
  <style>
    ${getCommonStyles(isAccepted ? '#10b981 0%, #059669 100%' : '#ef4444 0%, #dc2626 100%')}
    .icon { font-size: 96px; text-align: center; margin-bottom: 20px; }
    .result-message { text-align: center; font-size: 18px; color: #666; margin-bottom: 24px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">${isAccepted ? '✅' : '❌'}</div>
    <h1>${isAccepted ? '已接受聊天请求' : '已拒绝聊天请求'}</h1>
    <p class="result-message">${isAccepted ? `您已接受 "${qr.title}" 的聊天请求，现在可以在后台进行对话` : `您已拒绝 "${qr.title}" 的聊天请求`}</p>
  </div>
</body>
</html>`;
}
