"use strict";

const TelegramBot = require("node-telegram-bot-api");
const axios = require("axios");

const ALLOWED_COUNTRIES = new Set(["my", "sg", "th", "np"]);
const DOMAIN_LABEL_RE = /^[a-z0-9-]{1,63}$/;
const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

function requireEnv(name) {
  const value = (process.env[name] || "").trim();
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function parseAllowUsers(raw) {
  const values = new Set();
  for (const item of raw.split(",")) {
    const userId = item.trim();
    if (!userId) {
      continue;
    }
    if (!/^-?\d+$/.test(userId)) {
      throw new Error(`Invalid user_id in ALLOW_USERS: ${userId}`);
    }
    values.add(userId);
  }
  if (values.size === 0) {
    throw new Error("ALLOW_USERS has no valid user_id.");
  }
  return values;
}

function isValidDomain(host) {
  if (!host || host.length > 253) {
    return false;
  }
  if (IPV4_RE.test(host)) {
    return false;
  }
  const labels = host.split(".");
  if (labels.length < 2) {
    return false;
  }
  for (const label of labels) {
    if (!DOMAIN_LABEL_RE.test(label)) {
      return false;
    }
    if (label.startsWith("-") || label.endsWith("-")) {
      return false;
    }
  }
  if (/^\d+$/.test(labels[labels.length - 1])) {
    return false;
  }
  return true;
}

function normalizeDomain(rawInput) {
  const input = (rawInput || "").trim().toLowerCase();
  if (!input) {
    return null;
  }

  const token = input.split(/\s+/)[0];
  const probe = token.includes("://") ? token : `https://${token}`;

  let host = "";
  try {
    host = (new URL(probe).hostname || "").trim().toLowerCase();
  } catch {
    return null;
  }

  host = host.replace(/^\.+|\.+$/g, "");
  if (host.startsWith("www.")) {
    host = host.slice(4);
  }

  if (!isValidDomain(host)) {
    return null;
  }
  return host;
}

function parseDomainLines(content) {
  const seen = new Set();
  const result = [];
  for (const line of content.split(/\r?\n/)) {
    const domain = normalizeDomain(line);
    if (!domain || seen.has(domain)) {
      continue;
    }
    seen.add(domain);
    result.push(domain);
  }
  result.sort();
  return result;
}

function formatFileContent(domains) {
  if (!domains || domains.length === 0) {
    return "";
  }
  return `${domains.join("\n")}\n`;
}

function createGithubClient(token) {
  return axios.create({
    baseURL: "https://api.github.com",
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "X-GitHub-Api-Version": "2022-11-28",
    },
    timeout: 20000,
  });
}

function getApiErrorMessage(error) {
  if (error.response && error.response.data) {
    const apiMessage = error.response.data.message;
    if (apiMessage) {
      return `GitHub API error: ${apiMessage}`;
    }
  }
  return error.message || "unknown error";
}

async function getCountryDomains(client, owner, repo, branch, country) {
  const path = `/repos/${owner}/${repo}/contents/lists/${country}.txt`;
  try {
    const response = await client.get(path, { params: { ref: branch } });
    const payload = response.data || {};
    const content = payload.content
      ? Buffer.from(payload.content, "base64").toString("utf8")
      : "";
    return { domains: parseDomainLines(content), sha: payload.sha || null };
  } catch (error) {
    if (error.response && error.response.status === 404) {
      return { domains: [], sha: null };
    }
    throw new Error(getApiErrorMessage(error));
  }
}

async function updateCountryDomains(
  client,
  owner,
  repo,
  branch,
  country,
  domains,
  sha,
  message
) {
  const path = `/repos/${owner}/${repo}/contents/lists/${country}.txt`;
  const content = Buffer.from(formatFileContent(domains), "utf8").toString(
    "base64"
  );
  const body = { message, content, branch };
  if (sha) {
    body.sha = sha;
  }
  try {
    await client.put(path, body);
  } catch (error) {
    throw new Error(getApiErrorMessage(error));
  }
}

function usageHelp() {
  return [
    "Commands:",
    "/countries",
    "/add <country> <domain>",
    "/remove <country> <domain>",
    "/list <country>",
    "/help",
  ].join("\n");
}

async function main() {
  const tgToken = requireEnv("TG_BOT_TOKEN");
  const ghToken = requireEnv("GH_TOKEN");
  const ghOwner = requireEnv("GH_OWNER");
  const ghRepo = requireEnv("GH_REPO");
  const ghBranch = (process.env.GH_BRANCH || "main").trim() || "main";
  const allowUsers = parseAllowUsers(requireEnv("ALLOW_USERS"));

  const gh = createGithubClient(ghToken);
  const bot = new TelegramBot(tgToken, { polling: true });

  bot.on("polling_error", (error) => {
    console.error("Polling error:", error.message);
  });

  bot.on("message", async (msg) => {
    try {
      const text = (msg.text || "").trim();
      if (!text.startsWith("/")) {
        return;
      }

      const parts = text.split(/\s+/);
      const command = parts[0].split("@")[0].toLowerCase();
      const chatId = msg.chat.id;
      const userId = String(msg.from && msg.from.id ? msg.from.id : "");

      if (
        !["/countries", "/add", "/remove", "/list", "/help"].includes(command)
      ) {
        return;
      }

      if (!allowUsers.has(userId)) {
        await bot.sendMessage(chatId, "❌ You are not authorized.");
        return;
      }

      if (command === "/help") {
        await bot.sendMessage(chatId, usageHelp());
        return;
      }

      if (command === "/countries") {
        await bot.sendMessage(chatId, "my\nsg\nth\nnp");
        return;
      }

      if (command === "/list") {
        if (parts.length !== 2) {
          await bot.sendMessage(chatId, "Usage: /list <country>");
          return;
        }
        const country = parts[1].toLowerCase();
        if (!ALLOWED_COUNTRIES.has(country)) {
          await bot.sendMessage(chatId, "Invalid country. Use: my, sg, th, np");
          return;
        }

        const { domains } = await getCountryDomains(
          gh,
          ghOwner,
          ghRepo,
          ghBranch,
          country
        );
        if (domains.length === 0) {
          await bot.sendMessage(chatId, `${country}: (empty)`);
          return;
        }

        const limit = 50;
        const shown = domains.slice(0, limit);
        let message = `${country} (${domains.length})\n${shown.join("\n")}`;
        if (domains.length > limit) {
          message += "\n\n结果已截断";
        }
        await bot.sendMessage(chatId, message);
        return;
      }

      if (command === "/add" || command === "/remove") {
        if (parts.length < 3) {
          await bot.sendMessage(
            chatId,
            `Usage: ${command} <country> <domain>`
          );
          return;
        }

        const country = parts[1].toLowerCase();
        if (!ALLOWED_COUNTRIES.has(country)) {
          await bot.sendMessage(chatId, "Invalid country. Use: my, sg, th, np");
          return;
        }

        const domainInput = parts.slice(2).join("");
        const canonicalDomain = normalizeDomain(domainInput);
        if (!canonicalDomain) {
          await bot.sendMessage(chatId, "Invalid domain.");
          return;
        }

        const { domains, sha } = await getCountryDomains(
          gh,
          ghOwner,
          ghRepo,
          ghBranch,
          country
        );

        if (command === "/add") {
          if (domains.includes(canonicalDomain)) {
            await bot.sendMessage(chatId, "Domain already exists.");
            return;
          }
          const updated = [...domains, canonicalDomain].sort();
          const commitMessage = `bot: add ${canonicalDomain} to ${country} by ${userId}`;
          await updateCountryDomains(
            gh,
            ghOwner,
            ghRepo,
            ghBranch,
            country,
            updated,
            sha,
            commitMessage
          );
          await bot.sendMessage(chatId, `Added: ${country} ${canonicalDomain}`);
          return;
        }

        if (!domains.includes(canonicalDomain)) {
          await bot.sendMessage(chatId, "Domain not found.");
          return;
        }
        const updated = domains.filter((item) => item !== canonicalDomain);
        const commitMessage = `bot: remove ${canonicalDomain} from ${country} by ${userId}`;
        await updateCountryDomains(
          gh,
          ghOwner,
          ghRepo,
          ghBranch,
          country,
          updated,
          sha,
          commitMessage
        );
        await bot.sendMessage(chatId, `Removed: ${country} ${canonicalDomain}`);
      }
    } catch (error) {
      const chatId = msg && msg.chat ? msg.chat.id : null;
      const reason = error && error.message ? error.message : "unknown error";
      if (chatId !== null) {
        await bot.sendMessage(chatId, `❌ Operation failed: ${reason}`);
      }
      console.error("Command error:", error);
    }
  });

  console.log("Domain bot started (polling mode).");
}

process.on("unhandledRejection", (error) => {
  console.error("Unhandled rejection:", error);
});

main().catch((error) => {
  console.error("Fatal error:", error.message);
  process.exit(1);
});
