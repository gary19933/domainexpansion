# Domain Expansion Monitor

多国家（`my/sg/th/np`）域名可用性/疑似封锁检测系统，包含：

- GitHub Actions 每日自动检测 + 手动触发
- 自托管 runner（按国家标签）执行检测
- `records/ban_log.csv` 历史追加记录（不覆盖）
- 仅在发现异常时发送 Telegram 群通知（汇总一条消息）
- Telegram Bot 动态管理 `lists/*.txt` 域名列表

## 目录结构

```text
.github/workflows/daily_check.yml
scripts/check_domains.py
bot/bot.js
bot/package.json
bot/README.md
lists/my.txt
lists/sg.txt
lists/th.txt
lists/np.txt
records/ban_log.csv
README.md
```

## 域名列表规则

- 列表文件：`lists/my.txt`、`lists/sg.txt`、`lists/th.txt`、`lists/np.txt`
- 每行一个 domain
- 允许空文件
- 系统会自动 normalize：
  - 去 `http://` / `https://`
  - 去路径和端口
  - 去开头 `www.`
  - 转小写
  - 校验合法域名格式
- 系统会自动去重（检测时和 Bot 写回时）

## GitHub Actions 检测逻辑

- Workflow 文件：`.github/workflows/daily_check.yml`
- 触发方式：
  - `schedule`：每日自动
  - `workflow_dispatch`：手动触发
- 使用 matrix 国家：`my`, `sg`, `th`, `np`
- 每个国家 job 强制使用：

```yaml
runs-on:
  - self-hosted
  - linux
  - ${{ matrix.country }}
```

- 每个国家 job 会执行：
  - `nslookup <domain>`
  - `curl -L` 获取 `http_code`
- BAN 判定条件：
  - `000`
  - `403`
  - `451`
  - `52x`
  - `53x`
- 每个国家先产出 artifact，最终由汇总 job 统一追加到 `records/ban_log.csv`。

`records/ban_log.csv` 字段：

```csv
date,country,domain,http_code,status
```

> 只追加，不覆盖历史。

## 统计逻辑（first ban / 7d / 30d / 365d）

仅针对“当天检测出异常（BAN）”的 `country + domain` 计算：

- `first_ban_date`：历史最早异常日期
- 最近 `7` 天异常次数
- 最近 `30` 天异常次数
- 最近 `365` 天异常次数

统计单位是 `country + domain`，并从 `records/ban_log.csv` 历史中计算。

## Telegram 通知规则

- 仅当天有异常时才通知
- 汇总所有国家后发送 1 条消息到群
- 通知内容包含：
  - 国家
  - domain
  - http_code
  - first_ban_date
  - 7/30/365 天统计

GitHub Secrets（Actions 用）：

- `TG_BOT_TOKEN`
- `TG_CHAT_ID`

## 自托管 Runner 安装（VPS）

以 Linux x64 为例（每个国家至少一台，或一台多标签）：

1. 下载 runner 包（到目标目录）

```bash
mkdir -p actions-runner && cd actions-runner
curl -o actions-runner-linux-x64.tar.gz -L https://github.com/actions/runner/releases/latest/download/actions-runner-linux-x64.tar.gz
tar xzf ./actions-runner-linux-x64.tar.gz
```

2. 配置 runner（替换 URL 和 token）

```bash
./config.sh --url https://github.com/<OWNER>/<REPO> --token <RUNNER_TOKEN> --labels my,linux,self-hosted
```

国家标签按机器所在国家设置为 `my` / `sg` / `th` / `np`。  
如果是一台机器承担多个国家，可给多个标签。

3. 安装并启动服务

```bash
sudo ./svc.sh install
sudo ./svc.sh start
```

## Bot（动态管理 domain 列表）

Bot 脚本：`bot/bot.js`  
支持命令：

- `/countries`
- `/add <country> <domains...>`
- `/import <country>`
- `/remove <country> <domains...>`
- `/list <country>`
- `/help`

约束：

- `country` 只允许 `my/sg/th/np`
- 自动 normalize + 去重
- 非法输入会提示错误
- 仅允许 `ALLOW_USERS`（逗号分隔 Telegram `user_id`）

### Bot 环境变量

- `TG_BOT_TOKEN`
- `GH_TOKEN`
- `GH_OWNER`
- `GH_REPO`
- `ALLOW_USERS`
- `GH_BRANCH`（可选，默认 `main`）

### Bot 依赖与运行

```bash
cd bot
npm install
cp .env.example .env
# 编辑 .env
npm start
```

`.env` 已在 `bot/.gitignore` 中忽略，不要提交 token。

当执行 `/add`、`/import` 或 `/remove` 时，Bot 会通过 GitHub API 提交 `lists/<country>.txt`，并使用单次 commit（同一条命令只提交一次）。

更多 Bot 部署与 PM2 说明见 `bot/README.md`。

## 手动触发 workflow_dispatch

1. 打开 GitHub 仓库
2. 进入 `Actions` 页
3. 选择 `Daily Domain Check`
4. 点击 `Run workflow`

## 查看 records/ban_log.csv

- 直接在仓库打开 `records/ban_log.csv`
- 或本地执行：

```bash
cat records/ban_log.csv
```

## 本地测试命令

```bash
python scripts/check_domains.py --country my
```

默认会读取 `lists/my.txt` 并追加写入 `records/ban_log.csv`。  
若仅测试输出而不写历史：

```bash
python scripts/check_domains.py --country my --no-append-log --rows-output out/my_rows.csv
```
