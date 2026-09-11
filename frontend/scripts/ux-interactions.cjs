/**
 * Interaction check for the controls added during the UX review.
 *
 * The screenshot walkthrough only proves the pages render; this script clicks
 * the new controls and asserts the resulting state. It needs the API on :8000
 * and the Vite dev server on :5173.
 *
 * Usage: node frontend/scripts/ux-interactions.cjs [taskId]
 */
const { chromium } = require("playwright");

const TASK = process.argv[2] || "task_exploit-chain-20260910T170757Z";
const BASE = process.env.UX_BASE || "http://localhost:5173";

const results = [];
function check(name, condition, detail = "") {
  results.push({ name, ok: Boolean(condition), detail });
  console.log(`${condition ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
}

async function openSection(page, label) {
  await page.goto(`${BASE}/?task=${encodeURIComponent(TASK)}`, { waitUntil: "networkidle" });
  const nav = page.getByRole("button", { name: label, exact: true });
  if (await nav.count()) await nav.first().click();
  await page.waitForTimeout(label === "攻击图" ? 3500 : 800);
}

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  const consoleErrors = [];
  page.on("console", (message) => { if (message.type() === "error") consoleErrors.push(message.text().slice(0, 160)); });
  page.on("pageerror", (error) => consoleErrors.push(`pageerror: ${error.message}`.slice(0, 160)));

  // --- 攻击图筛选与搜索 ---
  await openSection(page, "攻击图");
  const summary = page.locator(".attack-graph-filter-summary");
  const nodePlaceholder = page.locator(".attack-graph-search input").first();
  const initialTotal = Number((await nodePlaceholder.getAttribute("placeholder") || "").replace(/\D+/g, ""));
  check("攻击图默认进入筛选视图", await summary.count() > 0, (await summary.first().textContent() || "").trim().slice(0, 48));

  const alertToggle = page.locator(".attack-graph-toggle input").first();
  check("默认开启“只看与告警相关的节点”", await alertToggle.isChecked());
  await alertToggle.uncheck();
  await page.waitForTimeout(2500);
  const expandedPlaceholder = await nodePlaceholder.getAttribute("placeholder");
  check("关闭筛选后节点数回到全量", expandedPlaceholder.includes(String(initialTotal)) && !(await summary.count()),
    `placeholder=${expandedPlaceholder}`);

  await page.locator(".type-chip", { hasText: "事件" }).first().click();
  await page.waitForTimeout(2500);
  const afterTypeFilter = await nodePlaceholder.getAttribute("placeholder");
  const filteredTotal = Number(afterTypeFilter.replace(/\D+/g, ""));
  check("按类型隐藏节点后数量下降", filteredTotal > 0 && filteredTotal < initialTotal, afterTypeFilter);

  const reset = page.locator(".attack-graph-reset");
  if (await reset.count()) {
    await reset.first().click();
    await page.waitForTimeout(2500);
    const afterReset = await nodePlaceholder.getAttribute("placeholder");
    check("重置筛选恢复全量", Number(afterReset.replace(/\D+/g, "")) === initialTotal, afterReset);
  }

  await nodePlaceholder.fill("legacyweb01");
  await nodePlaceholder.press("Enter");
  await page.waitForTimeout(1200);
  const inspectorText = (await page.locator(".attack-graph-inspector").innerText()) || "";
  check("搜索并回车定位到节点详情", inspectorText.includes("节点详情"), inspectorText.split("\n").slice(0, 2).join(" / "));

  const fullscreen = page.getByRole("button", { name: "全屏画布" });
  await fullscreen.click();
  await page.waitForTimeout(600);
  check("全屏画布生效", await page.locator(".attack-graph-view.is-expanded").count() > 0);
  await page.keyboard.press("Escape");
  await page.waitForTimeout(600);
  check("Esc 退出全屏", await page.locator(".attack-graph-view.is-expanded").count() === 0);

  // --- 告警证据展开 ---
  await openSection(page, "检测告警");
  const disclosure = page.locator(".alert-index > summary").first();
  if (await disclosure.count()) {
    await disclosure.click();
    await page.waitForTimeout(400);
    const ids = await page.locator(".alert-event-ids code").count();
    check("展开告警证据索引后列出事件 ID", ids > 0, `${ids} 条`);
  } else {
    check("展开告警证据索引后列出事件 ID", false, "未找到证据索引折叠项");
  }

  // --- 事件详情对话框 ---
  await openSection(page, "事件流");
  const detailButton = page.locator(".event-detail-button").first();
  await detailButton.click();
  await page.waitForTimeout(400);
  check("事件详情对话框打开", await page.locator(".event-detail-dialog[open]").count() > 0);
  await page.keyboard.press("Escape");
  await page.waitForTimeout(400);
  check("Esc 关闭事件详情并返回列表", await page.locator(".event-detail-dialog[open]").count() === 0);

  check("交互过程无控制台错误", consoleErrors.length === 0, consoleErrors.slice(0, 3).join(" | "));

  await browser.close();
  const failed = results.filter((item) => !item.ok);
  console.log(`\n${results.length - failed.length}/${results.length} 项通过`);
  process.exit(failed.length ? 1 : 0);
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
