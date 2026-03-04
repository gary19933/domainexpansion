# Domain Bot (Canonical-Only)

该 Bot 使用 polling 模式运行，支持通过 Telegram 动态管理 `lists/<country>.txt`，并仅保存 canonical domain。

## 功能

- `/countries`
- `/add <country> <domains...>`（支持空格/逗号/换行批量）
- `/import <country>`（命令下一行开始粘贴大批量域名）
- `/remove <country> <domains...>`（支持空格/逗号/换行批量删除）
- `/list <country>`
- `/whoami`
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

## 批量规则（/add /import /remove）

- 国家仅允许：`my`, `sg`, `th`, `np`
- 单次最多处理 `500` 个 domain；超过返回：`❌ Too many domains.`
- `lists/<country>.txt` 每行一个 canonical domain
- 自动去重；文件不存在时会自动创建
- 输出会明确显示新增/导入/删除数量与 skipped 数量

回复示例：

```text
✅ Added 5 domains to SG
⚠️ Skipped 2 existing domains
```

```text
✅ Imported 50 domains to SG
⚠️ Skipped 3 existing domains
```

```text
✅ Removed 3 domains from SG
⚠️ Skipped 2 not found
```

## 安全控制

仅允许 `ALLOW_USERS` 中的 Telegram user_id 操作。  
非白名单用户将收到：

`❌ You are not authorized.`

## 环境变量

- `TG_BOT_TOKEN`  
  Telegram BotFather token
- `GH_TOKEN`  
  GitHub Personal Access Token（fine-grained，权限：Contents Read + Write）
- `GH_OWNER`  
  GitHub username
- `GH_REPO`  
  Repository name
- `GH_BRANCH`  
  默认 `main`
- `ALLOW_USERS`  
  允许操作 bot 的 Telegram `user_id`，多个用户用逗号分隔，例如：`123456789,987654321`

## 部署

```bash
cd bot
npm install
cp .env.example .env
# 编辑 .env
npm start
```

`.env` 已加入 `.gitignore`，请勿提交任何 token 到仓库。

## 命令示例

### /add 批量添加

空格分隔：

```text
/add sg google.com facebook.com yahoo.com
```

逗号分隔：

```text
/add sg google.com,facebook.com,yahoo.com
```

混合分隔：

```text
/add sg google.com, facebook.com yahoo.com
```

换行分隔：

```text
/add sg
google.com
facebook.com
yahoo.com
```

### /import 大批量导入（多行）

```text
/import sg
google.com
facebook.com
yahoo.com
https://www.tiktok.com/test
www.reddit.com/abc
```

如果只发送 `/import <country>` 没有列表，bot 会回复：`❌ Please paste domains below the command.`

### /remove 批量删除

空格分隔：

```text
/remove sg google.com facebook.com
```

逗号分隔：

```text
/remove sg google.com,facebook.com
```

换行分隔：

```text
/remove sg
google.com
facebook.com
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
   - `bot: add <N> domains to <country> by <user_id>`
   - `bot: import <N> domains to <country> by <user_id>`
   - `bot: remove <N> domains from <country> by <user_id>`

## 测试步骤

1. `/whoami` 获取 user_id（并确认在 `ALLOW_USERS`）
2. `/countries`
3. `/add sg https://www.google.com/test facebook.com`
4. `/import sg` 后粘贴 10 条 domain（多行）
5. 到 GitHub 仓库检查 `lists/sg.txt` 是否更新并产生 commit

## 安全提醒

- 不要把 token 写入仓库文件
- 不要把 token 发到群或 issue
