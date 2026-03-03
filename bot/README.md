# Domain Bot (Canonical-Only)

该 Bot 使用 polling 模式运行，支持通过 Telegram 动态管理 `lists/<country>.txt`，并仅保存 canonical domain。

## 功能

- `/countries`
- `/add <country> <domain>`
- `/remove <country> <domain>`
- `/list <country>`
- `/help`

支持国家：`my`, `sg`, `th`, `np`

## Canonical 规则

输入 domain 会被规范化后再保存：

- 去掉 `http://` 或 `https://`
- 去掉 path/query/hash
- 去掉开头 `www.`
- 转小写
- 只保留 host
- 必须是合法域名（如 `example.com`, `sub.example.com`）

示例：

`https://www.Google.com/test?a=1` -> `google.com`

## 安全控制

仅允许 `ALLOW_USERS` 中的 Telegram user_id 操作。  
非白名单用户将收到：

`❌ You are not authorized.`

## 环境变量

- `TG_BOT_TOKEN`
- `GH_TOKEN`
- `GH_OWNER`
- `GH_REPO`
- `GH_BRANCH`（可选，默认 `main`）
- `ALLOW_USERS`（逗号分隔 user_id）

## 部署

```bash
cd bot
npm install
export TG_BOT_TOKEN=...
export GH_TOKEN=...
export GH_OWNER=...
export GH_REPO=...
export ALLOW_USERS=...
node bot.js
```

## PM2

```bash
pm2 start bot/bot.js --name domain-bot
```

## GH_TOKEN 创建建议

推荐使用 Fine-grained PAT，仓库权限至少包含：

- Contents: Read and write

Bot 使用 GitHub REST Contents API：

1. GET `lists/<country>.txt`（取内容与 sha）
2. 修改后 PUT 回去（base64 编码）
3. commit message 示例：
   - `bot: add google.com to sg by <user_id>`
   - `bot: remove google.com from sg by <user_id>`

## 安全提醒

- 不要把 token 写入仓库文件
- 不要把 token 发到群或 issue
