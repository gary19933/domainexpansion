#!/usr/bin/env python3
import base64
import json
import os
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

ALLOWED_COUNTRIES = {"my", "sg", "th", "np"}


@dataclass
class RepoConfig:
    token: str
    owner: str
    repo: str
    branch: str


def require_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def parse_allowed_users(raw: str) -> set[int]:
    values = set()
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            values.add(int(item))
        except ValueError as exc:
            raise RuntimeError(f"Invalid user_id in ALLOW_USERS: {item}") from exc
    return values


def normalize_domain(raw: str) -> str:
    text = raw.strip().lower()
    if not text:
        return ""
    token = text.split()[0]
    probe = token if "://" in token else f"//{token}"
    parsed = urlparse(probe)
    host = parsed.netloc or parsed.path
    host = host.split("/")[0].split("@")[-1].split(":")[0].strip(".")
    if not host or " " in host:
        return ""
    return host


def github_request(
    cfg: RepoConfig, method: str, path: str, body: dict[str, Any] | None = None
) -> dict[str, Any]:
    url = f"https://api.github.com{path}"
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    req = Request(url, data=data, method=method)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("Authorization", f"Bearer {cfg.token}")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8"))


def get_domains(cfg: RepoConfig, country: str) -> tuple[list[str], str | None]:
    path = f"/repos/{cfg.owner}/{cfg.repo}/contents/lists/{country}.txt?ref={cfg.branch}"
    try:
        data = github_request(cfg, "GET", path)
    except HTTPError as exc:
        if exc.code == 404:
            return [], None
        raise

    encoded = data.get("content", "")
    decoded = base64.b64decode(encoded).decode("utf-8") if encoded else ""
    seen = set()
    domains = []
    for line in decoded.splitlines():
        domain = normalize_domain(line)
        if domain and domain not in seen:
            seen.add(domain)
            domains.append(domain)
    return domains, data.get("sha")


def put_domains(
    cfg: RepoConfig,
    country: str,
    domains: list[str],
    sha: str | None,
    user_id: int,
    action: str,
    domain: str,
) -> None:
    path = f"/repos/{cfg.owner}/{cfg.repo}/contents/lists/{country}.txt"
    content = ("\n".join(domains) + ("\n" if domains else "")).encode("utf-8")
    payload: dict[str, Any] = {
        "message": f"bot: user_id={user_id} action={action} country={country} domain={domain}",
        "content": base64.b64encode(content).decode("utf-8"),
        "branch": cfg.branch,
    }
    if sha:
        payload["sha"] = sha
    github_request(cfg, "PUT", path, payload)


def is_authorized(update: Update, allow_users: set[int]) -> bool:
    if update.effective_user is None:
        return False
    return update.effective_user.id in allow_users


async def countries_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    allow_users: set[int] = context.bot_data["allow_users"]
    if not is_authorized(update, allow_users):
        await update.message.reply_text("Unauthorized.")
        return
    await update.message.reply_text("Supported countries: my, sg, th, np")


async def list_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    allow_users: set[int] = context.bot_data["allow_users"]
    cfg: RepoConfig = context.bot_data["repo_cfg"]
    if not is_authorized(update, allow_users):
        await update.message.reply_text("Unauthorized.")
        return

    if len(context.args) != 1:
        await update.message.reply_text("Usage: /list <country>")
        return
    country = context.args[0].lower()
    if country not in ALLOWED_COUNTRIES:
        await update.message.reply_text("Invalid country. Use: my, sg, th, np")
        return

    domains, _ = get_domains(cfg, country)
    if not domains:
        await update.message.reply_text(f"{country}: (empty)")
        return
    await update.message.reply_text(f"{country}:\n" + "\n".join(domains))


async def add_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    allow_users: set[int] = context.bot_data["allow_users"]
    cfg: RepoConfig = context.bot_data["repo_cfg"]
    if not is_authorized(update, allow_users):
        await update.message.reply_text("Unauthorized.")
        return

    if len(context.args) != 2:
        await update.message.reply_text("Usage: /add <country> <domain>")
        return

    country = context.args[0].lower()
    domain = normalize_domain(context.args[1])
    if country not in ALLOWED_COUNTRIES:
        await update.message.reply_text("Invalid country. Use: my, sg, th, np")
        return
    if not domain:
        await update.message.reply_text("Invalid domain.")
        return

    user_id = update.effective_user.id
    domains, sha = get_domains(cfg, country)
    if domain in domains:
        await update.message.reply_text("Domain already exists.")
        return

    domains.append(domain)
    put_domains(cfg, country, domains, sha, user_id, "add", domain)
    await update.message.reply_text(f"Added: {country} {domain}")


async def import_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    allow_users: set[int] = context.bot_data["allow_users"]
    cfg: RepoConfig = context.bot_data["repo_cfg"]
    if not is_authorized(update, allow_users):
        await update.message.reply_text("Unauthorized.")
        return

    if len(context.args) < 2:
        await update.message.reply_text("Usage: /import <country> <domain1> <domain2> ...")
        return

    country = context.args[0].lower()
    if country not in ALLOWED_COUNTRIES:
        await update.message.reply_text("Invalid country. Use: my, sg, th, np")
        return

    user_id = update.effective_user.id
    domains, sha = get_domains(cfg, country)
    existing = set(domains)

    added = []
    skipped = []
    invalid = []
    for raw in context.args[1:]:
        domain = normalize_domain(raw)
        if not domain:
            invalid.append(raw)
        elif domain in existing:
            skipped.append(domain)
        else:
            domains.append(domain)
            existing.add(domain)
            added.append(domain)

    if added:
        put_domains(cfg, country, domains, sha, user_id, "import", ",".join(added))

    lines = []
    if added:
        lines.append(f"Added ({len(added)}): {', '.join(added)}")
    if skipped:
        lines.append(f"Already exists ({len(skipped)}): {', '.join(skipped)}")
    if invalid:
        lines.append(f"Invalid ({len(invalid)}): {', '.join(invalid)}")
    await update.message.reply_text("\n".join(lines) if lines else "Nothing to import.")


async def remove_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    allow_users: set[int] = context.bot_data["allow_users"]
    cfg: RepoConfig = context.bot_data["repo_cfg"]
    if not is_authorized(update, allow_users):
        await update.message.reply_text("Unauthorized.")
        return

    if len(context.args) != 2:
        await update.message.reply_text("Usage: /remove <country> <domain>")
        return

    country = context.args[0].lower()
    domain = normalize_domain(context.args[1])
    if country not in ALLOWED_COUNTRIES:
        await update.message.reply_text("Invalid country. Use: my, sg, th, np")
        return
    if not domain:
        await update.message.reply_text("Invalid domain.")
        return

    user_id = update.effective_user.id
    domains, sha = get_domains(cfg, country)
    if domain not in domains:
        await update.message.reply_text("Domain not found.")
        return

    updated = [d for d in domains if d != domain]
    put_domains(cfg, country, updated, sha, user_id, "remove", domain)
    await update.message.reply_text(f"Removed: {country} {domain}")


def main() -> None:
    tg_token = require_env("TG_BOT_TOKEN")
    gh_token = require_env("GH_TOKEN")
    gh_owner = require_env("GH_OWNER")
    gh_repo = require_env("GH_REPO")
    allow_users_raw = require_env("ALLOW_USERS")
    branch = os.getenv("GH_BRANCH", "main").strip() or "main"

    allow_users = parse_allowed_users(allow_users_raw)
    if not allow_users:
        raise RuntimeError("ALLOW_USERS has no valid user_id.")

    cfg = RepoConfig(token=gh_token, owner=gh_owner, repo=gh_repo, branch=branch)
    app = Application.builder().token(tg_token).build()
    app.bot_data["allow_users"] = allow_users
    app.bot_data["repo_cfg"] = cfg

    app.add_handler(CommandHandler("countries", countries_cmd))
    app.add_handler(CommandHandler("list", list_cmd))
    app.add_handler(CommandHandler("add", add_cmd))
    app.add_handler(CommandHandler("import", import_cmd))
    app.add_handler(CommandHandler("remove", remove_cmd))

    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
