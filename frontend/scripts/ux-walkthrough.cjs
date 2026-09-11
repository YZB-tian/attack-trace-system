/**
 * Capture every workspace view at desktop and mobile widths and report
 * machine-checkable UX signals (overflow, console errors, untranslated text).
 *
 * Usage: node frontend/scripts/ux-walkthrough.cjs [taskId] [outputDir]
 * Requires the API on :8000 and the Vite dev server on :5173.
 */
const fs = require("fs");
const path = require("path");
const { chromium } = require("playwright");

const TASK = process.argv[2] || "task_exploit-chain-20260910T170757Z";
const OUT = process.argv[3] || path.join(__dirname, "..", "..", "runtime", "ux");
const BASE = process.env.UX_BASE || "http://localhost:5173";
const SECTIONS = ["任务概览", "事件流", "检测告警", "攻击图", "溯源结果"];
const VIEWPORTS = [
  { name: "desktop", width: 1440, height: 900 },
  { name: "mobile", width: 390, height: 844 },
];

async function audit(page) {
  return page.evaluate(() => {
    const overflow = [];
    document.querySelectorAll("*").forEach((el) => {
      // Screen-reader-only nodes are 1px wide on purpose; not a layout defect.
      if (el.classList.contains("data-sr-only")) return;
      // 1px-wide wrappers (visually hidden captions/headers) are not defects.
      if (el.scrollWidth > el.clientWidth + 2 && el.clientWidth > 8) {
        const style = getComputedStyle(el);
        if (style.overflowX === "visible" || style.overflowX === "hidden") {
          overflow.push({
            tag: el.tagName.toLowerCase(),
            cls: String(el.className).slice(0, 60),
            text: (el.textContent || "").trim().slice(0, 60),
            scrollWidth: el.scrollWidth,
            clientWidth: el.clientWidth,
          });
        }
      }
    });
    const english = [];
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    let node;
    while ((node = walker.nextNode())) {
      const parent = node.parentElement;
      if (!parent || !parent.offsetParent) continue;
      if (["SCRIPT", "STYLE", "CODE", "PRE"].includes(parent.tagName)) continue;
      const text = (node.textContent || "").trim();
      if (text.length < 4) continue;
      if (/^[\x20-\x7E]+$/.test(text) && /[A-Za-z]{3}/.test(text)) {
        english.push(text.slice(0, 80));
      }
    }
    return {
      overflow: overflow.slice(0, 12),
      english: [...new Set(english)].slice(0, 25),
      englishCount: english.length,
      jsonish: [...document.querySelectorAll("pre, code")].filter((el) =>
        el.offsetParent && /[\{\[]/.test(el.textContent || "") && (el.textContent || "").length > 120
      ).length,
      bodyScrollWidth: document.body.scrollWidth,
      viewportWidth: window.innerWidth,
    };
  });
}

/** Total node count reported by the panel heading, e.g. "555 节点 · 1008 关系". */
async function totalNodes(page) {
  const text = (await page.locator(".panel-heading-note").first().textContent()) ?? "";
  const match = /(\d+)\s*节点/.exec(text);
  return match ? Number(match[1]) : null;
}

/** Nodes currently rendered, read back from the search box placeholder. */
async function visibleNodes(page) {
  const placeholder = await page.locator(".attack-graph-search input").first().getAttribute("placeholder");
  const match = /(\d+)\s*个节点/.exec(placeholder ?? "");
  return match ? Number(match[1]) : null;
}

/** Exercise the graph controls and assert the visible state actually changes. */
async function interactWithGraph(page, outDir) {
  const results = [];
  const check = async (name, fn) => {
    try {
      const detail = await fn();
      results.push({ name, ok: true, detail: String(detail) });
    } catch (error) {
      results.push({ name, ok: false, detail: `失败：${String(error.message).slice(0, 160)}` });
    }
  };
  const assert = (condition, detail) => {
    if (!condition) throw new Error(detail);
    return detail;
  };

  const total = await totalNodes(page);
  const initial = await visibleNodes(page);

  await check("大图默认只显示告警相关子图", async () => assert(
    total !== null && initial !== null && (initial < total || await page.locator(".attack-graph-filter-summary").count() === 0),
    `总数 ${total}，默认显示 ${initial}`,
  ));

  await check("重置筛选后恢复全图", async () => {
    const reset = page.locator(".attack-graph-reset");
    if (await reset.count() === 0) return assert(initial === total, `没有筛选，直接显示 ${initial}`);
    await reset.first().click();
    await page.waitForTimeout(1500);
    const now = await visibleNodes(page);
    return assert(now === total, `重置后显示 ${now} / ${total}`);
  });

  await check("只看与告警相关的节点开关生效", async () => {
    const toggle = page.locator(".attack-graph-toggle input");
    await toggle.check();
    await page.waitForTimeout(1500);
    const filtered = await visibleNodes(page);
    if (!(filtered < total)) throw new Error(`勾选后仍显示 ${filtered} / ${total}`);
    await toggle.uncheck();
    await page.waitForTimeout(1500);
    const restored = await visibleNodes(page);
    return assert(restored === total && filtered < total, `勾选 ${filtered} / ${total}，取消后 ${restored}`);
  });

  await check("节点类型筛选生效", async () => {
    const chip = page.locator(".type-chip").first();
    const label = ((await chip.textContent()) ?? "").trim();
    await chip.click();
    await page.waitForTimeout(1500);
    const off = await visibleNodes(page);
    const pressed = await chip.getAttribute("aria-pressed");
    await chip.click();
    await page.waitForTimeout(1500);
    const restored = await visibleNodes(page);
    return assert(off < total && pressed === "false" && restored === total,
      `关闭「${label}」后 ${off} / ${total}，恢复后 ${restored}`);
  });

  await check("搜索结果可定位节点", async () => {
    const input = page.locator(".attack-graph-search input").first();
    for (const probe of ["1", "e", "a", "0"]) {
      await input.fill(probe);
      await page.waitForTimeout(400);
      const note = (await page.locator(".attack-graph-search-note").first().textContent()) ?? "";
      if (/匹配\s*[1-9]/.test(note)) {
        await input.press("Enter");
        await page.waitForTimeout(600);
        const inspector = (await page.locator(".attack-graph-inspector").textContent()) ?? "";
        return assert(/节点详情/.test(inspector), `搜索「${probe}」后详情面板：${inspector.trim().slice(0, 40)}`);
      }
    }
    throw new Error("没有找到可匹配的搜索关键字");
  });

  await check("全屏画布可进入与退出", async () => {
    await page.getByRole("button", { name: "全屏画布" }).click();
    await page.waitForTimeout(600);
    const opened = await page.locator(".attack-graph-view.is-expanded").count();
    await page.keyboard.press("Escape");
    await page.waitForTimeout(600);
    const closed = await page.locator(".attack-graph-view.is-expanded").count();
    return assert(opened === 1 && closed === 0, `进入=${opened}，退出后=${closed}`);
  });

  await page.screenshot({ path: path.join(outDir, "desktop-graph-interactions.png"), fullPage: false });
  return results;
}

/** Exercise the event dialog, the alert evidence disclosure and the trace evidence index. */
async function interactWithDataViews(page, outDir) {
  const results = [];
  const check = async (name, fn) => {
    try {
      const detail = await fn();
      results.push({ name, ok: true, detail: String(detail) });
    } catch (error) {
      results.push({ name, ok: false, detail: `失败：${String(error.message).slice(0, 160)}` });
    }
  };
  const assert = (condition, detail) => {
    if (!condition) throw new Error(detail);
    return detail;
  };
  const go = async (label) => {
    await page.goto(`${BASE}/?task=${encodeURIComponent(TASK)}`, { waitUntil: "networkidle" });
    const nav = page.getByRole("button", { name: label, exact: true });
    if (await nav.count()) await nav.first().click();
    await page.waitForTimeout(1400);
  };

  await go("事件流");
  await check("事件详情对话框打开后可用 Esc 关闭", async () => {
    const buttons = page.locator(".event-detail-button");
    assert(await buttons.count() > 0, "没有事件详情按钮");
    await buttons.first().click();
    await page.waitForTimeout(700);
    const opened = await page.locator("dialog.event-detail-dialog[open]").count();
    assert(opened === 1, `对话框未打开（${opened}）`);
    await page.keyboard.press("Escape");
    await page.waitForTimeout(700);
    const closed = await page.locator("dialog.event-detail-dialog[open]").count();
    return assert(closed === 0, `Esc 之后仍处于打开状态（${closed}）`) && "打开后 Esc 关闭";
  });

  await go("检测告警");
  await check("告警证据索引折叠项可展开", async () => {
    const summary = page.locator("details.alert-index > summary").first();
    assert(await summary.count() > 0, "没有证据索引折叠项");
    await summary.click();
    await page.waitForTimeout(500);
    const open = await page.locator("details.alert-index[open]").count();
    return assert(open >= 1, `展开后 open 数量为 ${open}`);
  });

  await go("溯源结果");
  await check("证据索引可展开全部事件 ID", async () => {
    const before = await page.locator(".evidence-id-list li").count();
    const expand = page.getByRole("button", { name: /展开全部/ });
    if (await expand.count()) {
      await expand.first().click();
      await page.waitForTimeout(500);
    }
    const after = await page.locator(".evidence-id-list li").count();
    return assert(after > before, `展开前 ${before} 条，展开后 ${after} 条`);
  });
  await check("归因区块可展开更多候选路径", async () => {
    const disclosure = page.locator(".attribution-disclosure > summary").first();
    if (!(await disclosure.count())) return "当前任务没有更多候选路径可展开";
    await disclosure.click();
    await page.waitForTimeout(400);
    const open = await page.locator(".attribution-disclosure[open]").count();
    assert(open >= 1, "折叠项没有展开");
    return "候选路径折叠项已展开";
  });

  await page.screenshot({ path: path.join(outDir, "desktop-data-interactions.png"), fullPage: false });
  return results;
}

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const browser = await chromium.launch();
  const report = {};
  for (const viewport of VIEWPORTS) {
    const context = await browser.newContext({
      viewport: { width: viewport.width, height: viewport.height },
      deviceScaleFactor: 1,
    });
    const page = await context.newPage();
    const consoleErrors = [];
    page.on("console", (message) => {
      if (message.type() === "error" || message.type() === "warning") {
        consoleErrors.push(`${message.type()}: ${message.text()}`.slice(0, 200));
      }
    });
    page.on("pageerror", (error) => consoleErrors.push(`pageerror: ${error.message}`.slice(0, 200)));
    for (const section of SECTIONS) {
      await page.goto(`${BASE}/?task=${encodeURIComponent(TASK)}`, { waitUntil: "networkidle" });
      const nav = page.getByRole("button", { name: section, exact: true });
      if (await nav.count()) await nav.first().click();
      await page.waitForTimeout(section === "攻击图" ? 4000 : 1200);
      const file = path.join(OUT, `${viewport.name}-${SECTIONS.indexOf(section)}-${section}.png`);
      await page.screenshot({ path: file, fullPage: false });
      report[`${viewport.name}/${section}`] = await audit(page);
      report[`${viewport.name}/${section}`].screenshot = file;
      if (viewport.name === "desktop" && section === "攻击图") {
        report["interactions/攻击图"] = await interactWithGraph(page, OUT);
      }
      if (viewport.name === "desktop" && section === "溯源结果") {
        report["interactions/数据视图"] = await interactWithDataViews(page, OUT);
      }
    }
    report[`${viewport.name}/console`] = [...new Set(consoleErrors)];
    await context.close();
  }
  await browser.close();
  const file = path.join(OUT, "report.json");
  fs.writeFileSync(file, JSON.stringify(report, null, 2), "utf8");
  const interactions = Object.values(report).flat().filter((item) => item && typeof item === "object" && "name" in item && "ok" in item);
  const failed = interactions.filter((item) => !item.ok);
  console.log(JSON.stringify({
    output: file,
    views: Object.keys(report).length,
    interactions: interactions.map((item) => `${item.ok ? "PASS" : "FAIL"} ${item.name}: ${item.detail}`),
    summary: Object.fromEntries(Object.entries(report).map(([key, value]) => [
      key,
      value && typeof value === "object" && "englishCount" in value
        ? { english: value.englishCount, jsonBlocks: value.jsonish, overflow: value.overflow.length, pageWider: value.bodyScrollWidth > value.viewportWidth + 2 }
        : Array.isArray(value)
          ? (value.length > 0 && value.every((item) => item && typeof item === "object" && "ok" in item)
            ? `${value.filter((item) => item.ok).length} 项通过`
            : value)
          : value,
    ])),
  }, null, 2));
  if (failed.length) {
    console.error(`交互断言失败 ${failed.length} 项：${failed.map((item) => item.name).join("、")}`);
    process.exitCode = 1;
  }
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
