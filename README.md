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
  - `curl -L` 获取最终 `http_code` 与跳转落点
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
- `RES_PROXY_MY`（可选，Malaysia 检测代理）
- `RES_PROXY_SG`（可选，Singapore 检测代理）
- `RES_PROXY_TH`（可选，Thailand 检测代理）
- `RES_PROXY_NP`（可选，Nepal 检测代理）

说明：

- 每个国家 job 会优先使用对应国家的代理。
- 若对应 secret 为空，则该国家会直连检测（不走代理）。

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
- `/move <from_country> <to_country> <domains...>`
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

当执行 `/add`、`/import`、`/remove` 或 `/move` 时，Bot 会通过 GitHub API 提交 `lists/<country>.txt`，并使用单次 commit（同一条命令只提交一次）。

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

## EC2 Scheduler (Systemd First)

本项目已提供 EC2 本地调度版本，避免依赖 GitHub schedule：

- 主脚本：`scripts/run_daily_check.sh`
- 汇总脚本：`scripts/merge_summary.py`
- systemd service：`deploy/systemd/domainexpansion-daily.service`
- systemd timer：`deploy/systemd/domainexpansion-daily.timer`
- cron 备用：`deploy/cron/domainexpansion.cron`

### 1) Ubuntu 24.04 安装依赖

```bash
sudo apt update
sudo apt install -y python3 python3-pip curl
```

### 2) 目录与权限

```bash
cd /home/ubuntu/domainexpansion
mkdir -p out records
sudo mkdir -p /var/log/domainexpansion
sudo touch /var/log/domainexpansion/daily.log
sudo chmod 755 /var/log/domainexpansion
sudo chmod 644 /var/log/domainexpansion/daily.log
chmod +x scripts/run_daily_check.sh
```

### 3) 服务器时区（GMT+8）

```bash
sudo timedatectl set-timezone Asia/Kuala_Lumpur
timedatectl
```

### 4) 环境变量文件

创建 `/etc/domainexpansion.env`（`root:root` + `600`）：

```bash
sudo tee /etc/domainexpansion.env >/dev/null <<'EOF'
TG_BOT_TOKEN=123456789:replace_me
TG_CHAT_ID=-1001234567890
RES_PROXY_MY=http://user:pass@proxy-host:port
RES_PROXY_SG=http://user:pass@proxy-host:port
RES_PROXY_TH=http://user:pass@proxy-host:port
RES_PROXY_NP=http://user:pass@proxy-host:port
EOF
sudo chown root:root /etc/domainexpansion.env
sudo chmod 600 /etc/domainexpansion.env
```

### 5) 启用 systemd timer（推荐）

```bash
sudo cp deploy/systemd/domainexpansion-daily.service /etc/systemd/system/
sudo cp deploy/systemd/domainexpansion-daily.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now domainexpansion-daily.timer
sudo systemctl list-timers --all | grep domainexpansion
```

`domainexpansion-daily.timer` 默认每天 `08:00`（Asia/Kuala_Lumpur）触发。

### 6) 备用 cron 方案

若不用 systemd timer，可用 root crontab：

```bash
sudo crontab -e
```

加入这一行：

```cron
0 8 * * * /bin/bash /home/ubuntu/domainexpansion/scripts/run_daily_check.sh >> /var/log/domainexpansion/daily.log 2>&1
```

### 7) 手动运行与验证

手动跑一次：

```bash
sudo /bin/bash /home/ubuntu/domainexpansion/scripts/run_daily_check.sh
```

查看最近 200 行日志：

```bash
tail -n 200 /var/log/domainexpansion/daily.log
```

查看本次输出：

```bash
ls -lah out/
head -n 5 out/my_rows.csv
head -n 5 out/sg_rows.csv
head -n 5 out/th_rows.csv
head -n 5 out/np_rows.csv
cat out/telegram_daily_summary.txt
```

检查 systemd 最近执行记录：

```bash
sudo systemctl status domainexpansion-daily.timer
sudo systemctl status domainexpansion-daily.service
sudo journalctl -u domainexpansion-daily.service -n 200 --no-pager
```

### 8) PROXY_BLOCK / ERROR 识别

`scripts/merge_summary.py` 会为每条行记录追加 `reason` 列（写回 `out/*_rows.csv`）：

- `PROXY_BLOCK`：`403 / 407 / 451 / 52x / 53x`
- `ERROR`：`000` 或其他失败状态
- `OK`：可访问

Telegram 汇总会显示 `http_code` 与 `reason`，例如：

`Domain: example.com [403 | PROXY_BLOCK]`
