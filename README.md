# 📱 智能二维码管理系统

> 基于 Cloudflare Workers 的全功能二维码管理系统，支持普通、授权、联系三种类型二维码，内置实时聊天、位置导航、文件上传等功能。

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-orange.svg)](https://workers.cloudflare.com/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/xiaobaiweinuli/qr-system/pulls)

---

## ✨ 核心特性

### 📋 三种二维码类型

- **🔓 普通二维码** - 公开展示内容，支持 Markdown/HTML
- **🔐 授权二维码** - 需管理员批准才能查看私密内容
- **💬 联系二维码** - 实时聊天，支持图片、位置分享

### 🚀 强大功能

- ✅ **实时通信** - 基于 WebSocket 的实时消息推送
- ✅ **位置导航** - 支持高德/百度地图导航，自动唤起APP
- ✅ **文件上传** - 支持图片上传和预览
- ✅ **Markdown渲染** - 完整支持 Markdown 和 HTML 内容
- ✅ **企业微信通知** - 授权申请、新消息自动推送
- ✅ **自定义通知** - 灵活的HTTP通知渠道配置
- ✅ **响应式设计** - 完美适配移动端和桌面端
- ✅ **数据持久化** - 使用 Cloudflare KV 存储

---

## 📸 功能演示

### 管理后台
![管理后台](https://via.placeholder.com/800x450?text=Admin+Dashboard)

### 二维码类型
| 普通二维码 | 授权二维码 | 联系二维码 |
|----------|----------|----------|
| ![普通](https://via.placeholder.com/250x400?text=Normal+QR) | ![授权](https://via.placeholder.com/250x400?text=Auth+QR) | ![联系](https://via.placeholder.com/250x400?text=Contact+QR) |

### 地图导航
![地图选择](https://via.placeholder.com/400x600?text=Map+Selection)

---

## 🚀 快速开始

### 前置要求

- [Cloudflare](https://cloudflare.com) 账号
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/) 工具
- Node.js 16+ (用于本地开发)

### 1. 克隆项目

```bash
git clone https://github.com/xiaobaiweinuli/qr-system.git
cd qr-system
```

### 2. 安装 Wrangler

```bash
npm install -g wrangler
```

### 3. 登录 Cloudflare

```bash
wrangler login
```

### 4. 创建 KV 命名空间

```bash
# 创建生产环境 KV
wrangler kv:namespace create "ASSET_KV"

# 记录返回的 ID，例如：
# id = "abc123..."
```

### 5. 配置 wrangler.toml

创建 `wrangler.toml` 文件：

```toml
name = "qr-system"
main = "worker.js"
compatibility_date = "2024-01-01"

[[kv_namespaces]]
binding = "ASSET_KV"
id = "your-kv-namespace-id"  # 替换为步骤4中的 ID

[vars]
ADMIN_PASSWORD = "your-secure-password"  # 修改为你的管理员密码
SECRET_KEY = "your-secret-key-min-32-chars"  # 至少32字符
```

### 6. 部署到 Cloudflare Workers

```bash
wrangler deploy
```

### 7. 访问系统

部署成功后，你会得到一个 URL，例如：
```
https://qr-system.your-subdomain.workers.dev
```

管理后台：
```
https://qr-system.your-subdomain.workers.dev/admin
```

---

## 📖 使用指南

### 管理员功能

#### 1. 登录后台

访问 `/admin`，使用 `wrangler.toml` 中配置的密码登录。

#### 2. 创建二维码

**普通二维码：**
1. 点击"创建普通二维码"
2. 填写标题和内容（支持 Markdown）
3. 可选：上传图片、添加位置
4. 保存后即可扫码查看

**授权二维码：**
1. 点击"创建授权二维码"
2. 填写公开内容和私密内容
3. 可选：添加位置信息
4. 游客扫码后需申请授权
5. 管理员批准后可查看私密内容

**联系二维码：**
1. 点击"创建联系二维码"
2. 填写联系信息
3. 可选：添加位置
4. 游客扫码后可实时聊天

#### 3. 管理二维码

- **编辑**：点击卡片上的"✏️"按钮
- **删除**：点击"🗑️"按钮（带动画效果）
- **查看二维码**：点击"📱"按钮查看高清二维码
- **复制链接**：点击"🔗"按钮

#### 4. 处理授权申请

在"授权请求"标签页：
- 查看待处理的授权申请
- 点击"✅ 批准"或"❌ 拒绝"
- 实时推送结果给游客

#### 5. 查看聊天记录

在"聊天记录"标签页：
- 查看所有联系二维码的聊天记录
- 支持图片、位置消息
- 点击查看完整对话历史

#### 6. 系统设置

在"系统设置"标签页配置：
- **地图API**：选择高德或百度地图
- **企业微信通知**：配置 Webhook URL
- **自定义通知渠道**：添加HTTP接口

### 游客功能

#### 扫描普通二维码
- 直接查看内容
- 如有位置，可选择导航APP

#### 扫描授权二维码
1. 查看公开内容
2. 点击"申请访问授权"
3. 等待管理员批准
4. 批准后查看私密内容和位置

#### 扫描联系二维码
1. 查看联系信息
2. 发送消息（支持文字、图片、位置）
3. 实时接收管理员回复

---

## ⚙️ 高级配置

### 企业微信通知

1. 在企业微信创建群机器人
2. 获取 Webhook URL
3. 在系统设置中配置

通知事件：
- ✅ 新的授权申请
- ✅ 新的联系消息
- ✅ 新的位置分享

### 自定义通知渠道

支持配置自定义 HTTP 接口接收通知：

```javascript
{
  "name": "Slack通知",
  "url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
  "method": "POST",
  "headers": {
    "Content-Type": "application/json"
  },
  "bodyTemplate": {
    "text": "{{message}}"
  }
}
```

可用变量：
- 授权通知：`{{user_id}}`, `{{qr_title}}`, `{{request_time}}` 等
- 聊天通知：`{{sender}}`, `{{message}}`, `{{qr_title}}` 等

### 位置功能配置

系统支持两种地图：
- **高德地图** - 推荐国内使用
- **百度地图** - 备选方案

URL Scheme 自动唤起：
```javascript
// iOS
iosamap://navi?lat=39.90923&lon=116.397428&name=位置

// Android
androidamap://navi?lat=39.90923&lon=116.397428&name=位置
```

---

## 🏗️ 技术架构

### 技术栈

- **运行时**: Cloudflare Workers
- **存储**: Cloudflare KV
- **实时通信**: WebSocket (Durable Objects)
- **前端**: 原生 JavaScript + Markdown 渲染
- **样式**: CSS Grid + Flexbox 响应式布局

### 项目结构

```
qr-system/
├── worker.js              # 主程序文件 (5800+ 行)
├── wrangler.toml          # Cloudflare Workers 配置
├── README.md              # 项目文档
└── LICENSE                # 许可证
```

### 核心模块

```javascript
// 1. 工具函数 (Token、HMAC签名)
createToken()
verifyToken()

// 2. 路由处理
handleRequest()        // 主路由
handleAdminAPI()       // 管理API
handleWebSocket()      // WebSocket连接

// 3. 页面生成
getAdminDashboard()    // 管理后台
getNormalQRPage()      // 普通二维码页面
getAuthQRPage()        // 授权二维码页面
getContactQRPage()     // 联系二维码页面

// 4. 数据操作
CRUD operations        // KV数据库操作

// 5. 通知系统
sendWeChatNotification()   // 企业微信通知
sendCustomNotifications()  // 自定义通知
```

### 数据结构

#### 二维码对象
```javascript
{
  "id": "qr_xxx",
  "type": "normal|auth|contact",
  "title": "标题",
  "content": "Markdown内容",
  "privateContent": "私密内容(仅授权码)",
  "location": "经度,纬度",
  "image": "图片URL",
  "created_at": 1234567890,
  "updated_at": 1234567890
}
```

#### 授权请求
```javascript
{
  "id": "req_xxx",
  "qr_id": "qr_xxx",
  "user_id": "user_xxx",
  "status": "pending|approved|rejected",
  "created_at": 1234567890
}
```

#### 聊天消息
```javascript
{
  "id": "msg_xxx",
  "qr_id": "qr_xxx",
  "session_id": "session_xxx",
  "sender": "user|admin",
  "type": "text|image|location",
  "content": "消息内容",
  "timestamp": 1234567890
}
```

---

## 🎨 自定义开发

### 添加新的二维码类型

1. 在 `worker.js` 中添加新类型：
```javascript
function getNewTypePage(qrId, qr) {
  return `<!DOCTYPE html>...`;
}
```

2. 在路由中注册：
```javascript
if (qr.type === 'newtype') {
  return new Response(getNewTypePage(qrId, qr), {
    headers: { 'Content-Type': 'text/html;charset=UTF-8' }
  });
}
```

### 自定义样式

修改 `getCommonStyles()` 函数：
```javascript
function getCommonStyles(gradientColors = 'your-colors') {
  return `
    /* 你的自定义CSS */
  `;
}
```

### 添加新功能

系统采用模块化设计，可轻松扩展：
- 添加新的API端点
- 扩展WebSocket消息类型
- 集成第三方服务

---

## 🔒 安全特性

### 认证机制
- ✅ HMAC-SHA256 签名验证
- ✅ Token 过期时间控制
- ✅ 管理员密码加密存储

### 数据安全
- ✅ XSS 防护（内容转义）
- ✅ CSRF 防护
- ✅ 安全的文件上传验证

### 隐私保护
- ✅ 授权访问控制
- ✅ 聊天记录加密存储
- ✅ 敏感信息脱敏

---

## 📊 性能优化

### 前端优化
- ✅ 前端缓存机制（cachedQRCodes）
- ✅ 按需加载（lazy loading）
- ✅ 防抖和节流
- ✅ WebSocket 心跳检测

### 后端优化
- ✅ KV 读写优化
- ✅ 批量操作
- ✅ 缓存策略
- ✅ 异步处理

### 响应式设计
- ✅ 移动端优先
- ✅ 触摸优化
- ✅ 自适应布局
- ✅ 性能优化的动画

---

## 🐛 故障排除

### 常见问题

**Q: 部署后无法访问？**
```bash
# 检查 wrangler.toml 配置
# 确认 KV 命名空间 ID 正确
wrangler tail  # 查看实时日志
```

**Q: WebSocket 连接失败？**
```javascript
// 检查浏览器控制台
// 确认 Workers 支持 WebSocket
// 检查网络代理设置
```

**Q: 图片上传失败？**
```javascript
// 检查文件大小（< 5MB）
// 确认格式（jpg, png, gif）
// 查看浏览器控制台错误
```

**Q: 地图导航无法唤起APP？**
```
1. 确认已安装高德/百度地图
2. 微信中需在浏览器打开
3. 检查URL Scheme配置
```

### 调试模式

启用详细日志：
```javascript
// 在 worker.js 中添加
console.log('Debug:', data);
```

查看实时日志：
```bash
wrangler tail
```

---

## 🤝 贡献指南

欢迎贡献代码！

### 提交 Pull Request

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

### 代码规范

- 使用 2 空格缩进
- 函数和变量使用驼峰命名
- 添加必要的注释
- 遵循现有代码风格

---

## 📝 更新日志

### v1.0.0 (2024-12-20)
- ✨ 初始版本发布
- ✅ 支持三种二维码类型
- ✅ 实时聊天功能
- ✅ 位置导航功能
- ✅ 企业微信通知
- ✅ 响应式设计
- ✅ 完整的SEO优化

---

## 📄 许可证

本项目采用 [MIT](LICENSE) 许可证。

---

## 🙏 致谢

- [Cloudflare Workers](https://workers.cloudflare.com/) - 提供强大的边缘计算平台
- [Marked.js](https://marked.js.org/) - Markdown 渲染
- [高德地图](https://lbs.amap.com/) - 地图服务
- [百度地图](https://lbsyun.baidu.com/) - 地图服务

---

## 💬 联系方式

- 提交 Issue: [GitHub Issues](https://github.com/xiaobaiweinuli/qr-system/issues)
- 讨论区: [GitHub Discussions](https://github.com/xiaobaiweinuli/qr-system/discussions)

---

## ⭐ Star History

如果这个项目对你有帮助，请给个 Star ⭐️

[![Star History Chart](https://api.star-history.com/svg?repos=xiaobaiweinuli/qr-system&type=Date)](https://star-history.com/#xiaobaiweinuli/qr-system&Date)

---

<div align="center">

**📱 智能二维码管理系统**

Made with ❤️ by [Your Name](https://github.com/xiaobaiweinuli)

[⬆️ 回到顶部](#-智能二维码管理系统)

</div>
