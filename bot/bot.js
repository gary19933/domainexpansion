"use strict";

require("dotenv").config();

const TelegramBot = require("node-telegram-bot-api");
const axios = require("axios");
const { HttpsProxyAgent } = require("https-proxy-agent");
const { SocksProxyAgent } = require("socks-proxy-agent");

const ALLOWED_COUNTRIES = new Set(["my", "sg", "th", "np"]);
const DOMAIN_LABEL_RE = /^[a-z0-9-]{1,63}$/;
const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const MAX_INPUT_DOMAINS = 500;
const MAX_SCAN_CONCURRENCY = 10;
const TELEGRAM_MESSAGE_LIMIT = 3900;
const SUPPORTED_COMMANDS = new Set([
  "/countries",
  "/add",
  "/import",
  "/remove",
  "/move",
  "/scan",
  "/list",
  "/help",
  "/whoami",
]);

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

function parseDomainsFromListFile(content) {
  return parseDomainLines(content);
}

function formatFileContent(domains) {
  if (!domains || domains.length === 0) {
    return "";
  }
  return `${domains.join("\n")}\n`;
}

function parseCommand(text) {
  const match = text.match(/^\/([a-z_]+)(?:@\S+)?(?:\s+([\s\S]*))?$/i);
  if (!match) {
    return null;
  }
  return {
    command: `/${match[1].toLowerCase()}`,
    args: match[2] || "",
  };
}

function parseCountryAndPayload(argsText) {
  const trimmed = (argsText || "").trim();
  if (!trimmed) {
    return { country: "", payload: "" };
  }
  const match = trimmed.match(/^([^\s]+)([\s\S]*)$/);
  if (!match) {
    return { country: "", payload: "" };
  }
  return {
    country: match[1].toLowerCase(),
    payload: (match[2] || "").trim(),
  };
}

function parseMoveArgs(argsText) {
  const trimmed = (argsText || "").trim();
  if (!trimmed) {
    return { fromCountry: "", toCountry: "", payload: "" };
  }
  const match = trimmed.match(/^([^\s]+)\s+([^\s]+)([\s\S]*)$/);
  if (!match) {
    return { fromCountry: "", toCountry: "", payload: "" };
  }
  return {
    fromCountry: match[1].toLowerCase(),
    toCountry: match[2].toLowerCase(),
    payload: (match[3] || "").trim(),
  };
}

function tokenizeAddPayload(payload) {
  return (payload || "")
    .split(/[\s,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function tokenizeImportPayload(payload) {
  return (payload || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

function mergeDomains(existingDomains, canonicalCandidates) {
  const merged = new Set(existingDomains);
  const added = [];
  let skippedExisting = 0;

  for (const canonical of canonicalCandidates) {
    if (merged.has(canonical)) {
      skippedExisting += 1;
      continue;
    }
    merged.add(canonical);
    added.push(canonical);
  }

  added.sort();
  return {
    updatedDomains: Array.from(merged).sort(),
    addedDomains: added,
    skippedExisting,
  };
}

function normalizeAndDedupCandidates(inputCandidates) {
  const seen = new Set();
  const normalized = [];
  let invalidCount = 0;

  for (const rawDomain of inputCandidates) {
    const canonical = normalizeDomain(rawDomain);
    if (!canonical) {
      invalidCount += 1;
      continue;
    }
    if (seen.has(canonical)) {
      continue;
    }
    seen.add(canonical);
    normalized.push(canonical);
  }

  return { normalized, invalidCount };
}

function formatAddOrImportMessage(action, count, country, skippedExisting, invalidCount) {
  const lines = [
    `✅ ${action} ${count} domains to ${country.toUpperCase()}`,
    `⚠️ Skipped ${skippedExisting} existing domains`,
  ];
  if (invalidCount > 0) {
    lines.push(`❌ Invalid skipped ${invalidCount} domains`);
  }
  return lines.join("\n");
}

function formatRemoveMessage(count, country, skippedNotFound, invalidCount) {
  const lines = [
    `✅ Removed ${count} domains from ${country.toUpperCase()}`,
    `⚠️ Skipped ${skippedNotFound} not found`,
  ];
  if (invalidCount > 0) {
    lines.push(`❌ Invalid skipped ${invalidCount} domains`);
  }
  return lines.join("\n");
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
    return { domains: parseDomainsFromListFile(content), sha: payload.sha || null };
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

async function commitCountryDomainUpdates(
  client,
  owner,
  repo,
  branch,
  updates,
  message
) {
  if (!updates || updates.length === 0) {
    return;
  }

  const refName = `heads/${branch}`;
  const refPath = `/repos/${owner}/${repo}/git/ref/${encodeURIComponent(refName)}`;

  try {
    const refResp = await client.get(refPath);
    const baseCommitSha = refResp.data && refResp.data.object ? refResp.data.object.sha : "";
    if (!baseCommitSha) {
      throw new Error("GitHub API error: missing base commit sha");
    }

    const commitResp = await client.get(
      `/repos/${owner}/${repo}/git/commits/${baseCommitSha}`
    );
    const baseTreeSha =
      commitResp.data && commitResp.data.tree ? commitResp.data.tree.sha : "";
    if (!baseTreeSha) {
      throw new Error("GitHub API error: missing base tree sha");
    }

    const tree = updates.map((item) => ({
      path: `lists/${item.country}.txt`,
      mode: "100644",
      type: "blob",
      content: formatFileContent(item.domains),
    }));

    const treeResp = await client.post(`/repos/${owner}/${repo}/git/trees`, {
      base_tree: baseTreeSha,
      tree,
    });
    const newTreeSha = treeResp.data ? treeResp.data.sha : "";
    if (!newTreeSha) {
      throw new Error("GitHub API error: failed to create tree");
    }

    const newCommitResp = await client.post(`/repos/${owner}/${repo}/git/commits`, {
      message,
      tree: newTreeSha,
      parents: [baseCommitSha],
    });
    const newCommitSha = newCommitResp.data ? newCommitResp.data.sha : "";
    if (!newCommitSha) {
      throw new Error("GitHub API error: failed to create commit");
    }

    await client.patch(refPath, { sha: newCommitSha, force: false });
  } catch (error) {
    throw new Error(getApiErrorMessage(error));
  }
}

function formatCode(httpCode) {
  if (!httpCode || httpCode === 0) {
    return "000";
  }
  return String(httpCode);
}

function isServer52xOr53x(httpCode) {
  const text = formatCode(httpCode);
  return /^\d{3}$/.test(text) && (text.startsWith("52") || text.startsWith("53"));
}

function getHttpStatusReason(httpCode) {
  if (httpCode === 0) {
    return "无法连接";
  }
  if (httpCode === 403) {
    return "被限制访问";
  }
  if (httpCode === 451) {
    return "被法律限制";
  }
  if (isServer52xOr53x(httpCode)) {
    return "服务器异常";
  }
  return "正常访问";
}

function isErrorHttpCode(httpCode) {
  if (httpCode === 0 || httpCode === 403 || httpCode === 451) {
    return true;
  }
  return isServer52xOr53x(httpCode);
}

function createScanHttpConfig(proxyUrl) {
  const value = (proxyUrl || "").trim();
  if (!value) {
    return {};
  }
  const agent = /^socks/i.test(value)
    ? new SocksProxyAgent(value)
    : new HttpsProxyAgent(value);
  return {
    proxy: false,
    httpAgent: agent,
    httpsAgent: agent,
  };
}

async function checkOneDomain(domain, scanHttpConfig) {
  const url = `https://www.${domain}`;
  try {
    const response = await axios.get(url, {
      ...(scanHttpConfig || {}),
      maxRedirects: 5,
      timeout: 10000,
      validateStatus: () => true,
    });
    const httpCode = Number.isInteger(response.status) ? response.status : 0;
    return {
      domain,
      http_code: httpCode,
      status: isErrorHttpCode(httpCode) ? "ERROR" : "OK",
      reason: getHttpStatusReason(httpCode),
    };
  } catch {
    return {
      domain,
      http_code: 0,
      status: "ERROR",
      reason: getHttpStatusReason(0),
    };
  }
}

async function mapWithConcurrency(items, concurrency, mapper) {
  const size = Math.max(1, concurrency);
  const results = new Array(items.length);
  let nextIndex = 0;

  async function worker() {
    while (true) {
      const current = nextIndex;
      nextIndex += 1;
      if (current >= items.length) {
        return;
      }
      results[current] = await mapper(items[current], current);
    }
  }

  const workerCount = Math.min(size, items.length || 1);
  await Promise.all(Array.from({ length: workerCount }, () => worker()));
  return results;
}

function formatGmt8DateTime(date) {
  const formatter = new Intl.DateTimeFormat("sv-SE", {
    timeZone: "Asia/Singapore",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
  return formatter.format(date).replace(" ", " ");
}

function formatScanReport(country, results) {
  const okRows = [];
  const errorRows = [];
  for (const row of results) {
    if (row.status === "ERROR") {
      errorRows.push(
        `${row.domain}  状态：${row.reason} (code:${formatCode(row.http_code)})`
      );
      continue;
    }
    okRows.push(`${row.domain} (code:${formatCode(row.http_code)})`);
  }

  const lines = [
    `🔎 即时检测结果：${country.toUpperCase()}`,
    `时间：${formatGmt8DateTime(new Date())} (GMT+8)`,
    "",
    `🟢 正常 (${okRows.length})`,
    ...(okRows.length > 0 ? okRows : ["(none)"]),
    "",
    `🔴 异常 (${errorRows.length})`,
    ...(errorRows.length > 0 ? errorRows : ["(none)"]),
    "",
    `总计：${results.length} | 🟢 ${okRows.length} | 🔴 ${errorRows.length}`,
  ];

  let text = lines.join("\n");
  if (text.length > TELEGRAM_MESSAGE_LIMIT) {
    text = `${text.slice(0, TELEGRAM_MESSAGE_LIMIT - 20)}\n...(truncated)`;
  }
  return text;
}

function usageHelp() {
  return [
    "Commands:",
    "/countries",
    "/add <country> <domains...>",
    "/import <country> (domains on next lines)",
    "/remove <country> <domains...>",
    "/move <from_country> <to_country> <domains...>",
    "/scan <country>",
    "/list <country>",
    "/whoami",
    "/help",
  ].join("\n");
}

async function main() {
  const tgToken = requireEnv("TG_BOT_TOKEN");
  const ghToken = requireEnv("GH_TOKEN");
  const ghOwner = requireEnv("GH_OWNER");
  const ghRepo = requireEnv("GH_REPO");
  const ghBranch = (process.env.GH_BRANCH || "main").trim() || "main";
  const scanProxyUrl = (process.env.SCAN_PROXY_URL || process.env.RES_PROXY_URL || "").trim();
  const allowUsers = parseAllowUsers(requireEnv("ALLOW_USERS"));
  const scanHttpConfig = createScanHttpConfig(scanProxyUrl);

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

      const parsed = parseCommand(text);
      if (!parsed) {
        return;
      }
      const { command, args } = parsed;
      const chatId = msg.chat.id;
      const userId = String(msg.from && msg.from.id ? msg.from.id : "");

      if (!SUPPORTED_COMMANDS.has(command)) {
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

      if (command === "/whoami") {
        await bot.sendMessage(chatId, `Your user_id: ${userId}`);
        return;
      }

      if (command === "/list") {
        const listArgs = args.trim().split(/\s+/).filter(Boolean);
        if (listArgs.length !== 1) {
          await bot.sendMessage(chatId, "Usage: /list <country>");
          return;
        }
        const country = listArgs[0].toLowerCase();
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

      if (command === "/add" || command === "/import") {
        const { country, payload } = parseCountryAndPayload(args);
        if (!country) {
          await bot.sendMessage(
            chatId,
            command === "/add"
              ? "Usage: /add <country> <domains...>"
              : "Usage: /import <country>"
          );
          return;
        }
        if (!ALLOWED_COUNTRIES.has(country)) {
          await bot.sendMessage(chatId, "Invalid country. Use: my, sg, th, np");
          return;
        }

        let candidates = [];
        if (command === "/add") {
          candidates = tokenizeAddPayload(payload);
          if (candidates.length === 0) {
            await bot.sendMessage(chatId, "Usage: /add <country> <domains...>");
            return;
          }
        } else {
          candidates = tokenizeImportPayload(payload);
          if (candidates.length === 0) {
            await bot.sendMessage(
              chatId,
              "❌ Please paste domains below the command."
            );
            return;
          }
        }

        if (candidates.length > MAX_INPUT_DOMAINS) {
          await bot.sendMessage(chatId, "❌ Too many domains.");
          return;
        }

        const { domains, sha } = await getCountryDomains(
          gh,
          ghOwner,
          ghRepo,
          ghBranch,
          country
        );

        const { normalized, invalidCount } = normalizeAndDedupCandidates(candidates);
        const mergeResult = mergeDomains(domains, normalized);
        const addedCount = mergeResult.addedDomains.length;

        if (addedCount > 0) {
          const commitAction = command === "/add" ? "add" : "import";
          const commitMessage = `bot: ${commitAction} ${addedCount} domains to ${country} by ${userId}`;
          await updateCountryDomains(
            gh,
            ghOwner,
            ghRepo,
            ghBranch,
            country,
            mergeResult.updatedDomains,
            sha,
            commitMessage
          );
        }

        const actionWord = command === "/add" ? "Added" : "Imported";
        await bot.sendMessage(
          chatId,
          formatAddOrImportMessage(
            actionWord,
            addedCount,
            country,
            mergeResult.skippedExisting,
            invalidCount
          )
        );
        return;
      }

      if (command === "/remove") {
        const { country, payload } = parseCountryAndPayload(args);
        if (!country) {
          await bot.sendMessage(chatId, "Usage: /remove <country> <domains...>");
          return;
        }
        if (!ALLOWED_COUNTRIES.has(country)) {
          await bot.sendMessage(chatId, "Invalid country. Use: my, sg, th, np");
          return;
        }

        const candidates = tokenizeAddPayload(payload);
        if (candidates.length === 0) {
          await bot.sendMessage(chatId, "Usage: /remove <country> <domains...>");
          return;
        }
        if (candidates.length > MAX_INPUT_DOMAINS) {
          await bot.sendMessage(chatId, "❌ Too many domains.");
          return;
        }

        const { domains, sha } = await getCountryDomains(
          gh,
          ghOwner,
          ghRepo,
          ghBranch,
          country
        );

        const { normalized, invalidCount } = normalizeAndDedupCandidates(candidates);
        const domainSet = new Set(domains);
        const removeList = [];
        let skippedNotFound = 0;

        for (const domain of normalized) {
          if (domainSet.has(domain)) {
            removeList.push(domain);
            continue;
          }
          skippedNotFound += 1;
        }

        const removedCount = removeList.length;
        if (removedCount > 0) {
          const removeSet = new Set(removeList);
          const updated = domains.filter((item) => !removeSet.has(item));
          const commitMessage = `bot: remove ${removedCount} domains from ${country} by ${userId}`;
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
        }

        await bot.sendMessage(
          chatId,
          formatRemoveMessage(removedCount, country, skippedNotFound, invalidCount)
        );
        return;
      }

      if (command === "/move") {
        const { fromCountry, toCountry, payload } = parseMoveArgs(args);
        if (!fromCountry || !toCountry) {
          await bot.sendMessage(
            chatId,
            "Usage: /move <from_country> <to_country> <domains...>"
          );
          return;
        }
        if (!ALLOWED_COUNTRIES.has(fromCountry) || !ALLOWED_COUNTRIES.has(toCountry)) {
          await bot.sendMessage(chatId, "Invalid country. Use: my, sg, th, np");
          return;
        }
        if (fromCountry === toCountry) {
          await bot.sendMessage(
            chatId,
            "❌ Source and target country cannot be the same."
          );
          return;
        }

        const candidates = tokenizeAddPayload(payload);
        if (candidates.length === 0) {
          await bot.sendMessage(
            chatId,
            "Usage: /move <from_country> <to_country> <domains...>"
          );
          return;
        }
        if (candidates.length > MAX_INPUT_DOMAINS) {
          await bot.sendMessage(chatId, "❌ Too many domains.");
          return;
        }

        const [fromState, toState] = await Promise.all([
          getCountryDomains(gh, ghOwner, ghRepo, ghBranch, fromCountry),
          getCountryDomains(gh, ghOwner, ghRepo, ghBranch, toCountry),
        ]);
        const fromDomains = fromState.domains;
        const toDomains = toState.domains;

        const { normalized, invalidCount } = normalizeAndDedupCandidates(candidates);
        const fromSet = new Set(fromDomains);
        const toSet = new Set(toDomains);
        const moved = [];
        let skippedNotFound = 0;

        for (const domain of normalized) {
          if (!fromSet.has(domain)) {
            skippedNotFound += 1;
            continue;
          }
          moved.push(domain);
          fromSet.delete(domain);
          toSet.add(domain);
        }

        const movedCount = moved.length;
        if (movedCount > 0) {
          const updates = [
            { country: fromCountry, domains: Array.from(fromSet).sort() },
            { country: toCountry, domains: Array.from(toSet).sort() },
          ];
          const commitMessage = `bot: move ${movedCount} domains ${fromCountry} -> ${toCountry} by ${userId}`;
          await commitCountryDomainUpdates(
            gh,
            ghOwner,
            ghRepo,
            ghBranch,
            updates,
            commitMessage
          );
        }

        const lines = [
          `✅ Moved ${movedCount} domains`,
          `${fromCountry.toUpperCase()} → ${toCountry.toUpperCase()}`,
        ];
        if (skippedNotFound > 0) {
          lines.push("");
          lines.push(`⚠️ Skipped ${skippedNotFound} not found`);
        }
        if (invalidCount > 0) {
          lines.push(`❌ Invalid skipped ${invalidCount} domains`);
        }
        await bot.sendMessage(chatId, lines.join("\n"));
        return;
      }

      if (command === "/scan") {
        const scanArgs = args.trim().split(/\s+/).filter(Boolean);
        if (scanArgs.length !== 1) {
          await bot.sendMessage(chatId, "Usage: /scan <country>");
          return;
        }
        const country = scanArgs[0].toLowerCase();
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
        if (domains.length > MAX_INPUT_DOMAINS) {
          await bot.sendMessage(chatId, "❌ Too many domains.");
          return;
        }

        const scanResults = await mapWithConcurrency(
          domains,
          MAX_SCAN_CONCURRENCY,
          (domain) => checkOneDomain(domain, scanHttpConfig)
        );
        await bot.sendMessage(chatId, formatScanReport(country, scanResults));
        return;
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
