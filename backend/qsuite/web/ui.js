"use strict";
/* Small reusable navigation model; no authorization is delegated to this file. */
globalThis.QSuiteUI = (() => {
  const navigation = [
    ["dashboard", "Dashboard", "◈", "", []],
    ["server", "Overview", "▣", "SERVER", ["system.view"]],
    ["performance", "Performance", "▥", "SERVER", ["performance.view"]],
    ["services", "Services", "⌘", "SERVER", ["services.view"]],
    ["logs", "Logs", "≡", "SERVER", ["logs.minecraft.read", "logs.crafty.read", "logs.system.read", "logs.security.read"]],
    ["terminal", "Terminal", "›_", "SERVER", ["terminal.open"]],
    ["minecraft", "Minecraft", "◆", "MINECRAFT", ["minecraft.view"]],
    ["crafty", "Crafty", "▧", "MINECRAFT", ["crafty.view"]],
    ["membernews", "Member News", "✦", "MINECRAFT", ["member_news.view"]],
    ["security", "QSecurity", "◇", "SECURITY", ["security.view"]],
    ["incidents", "Incidents", "◎", "SECURITY", ["incident.view"]],
    ["adminnews", "Admin News", "⚑", "SECURITY", ["admin_news.view"]],
    ["backups", "Backups & restore", "▤", "RECOVERY", ["backup.view"]],
    ["packages", "Packages", "⬡", "QSUITE", ["packages.view"]],
    ["notifications", "Notification routing", "⇄", "QSUITE", ["admin_news.configure", "member_news.configure"]],
    ["users", "Users & permissions", "♙", "QSUITE", ["users.view"]],
    ["audit", "Audit", "≔", "QSUITE", ["audit.read"]],
    ["settings", "Account & settings", "⚙", "QSUITE", []]
  ];
  function allowed(permissions, restricted = false) {
    return navigation.filter(n => restricted ? n[0] === "settings" : !n[4].length || n[4].some(p => permissions.includes(p)));
  }
  function page(path, query = "") {
    const target = path === "/login" ? new URLSearchParams(query).get("next") : path;
    const match = /^\/panel\/([a-z]+)$/.exec(target || "");
    return match && navigation.some(n => n[0] === match[1]) ? match[1] : "dashboard";
  }
  return {navigation, allowed, page};
})();
