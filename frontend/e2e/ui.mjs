// End-to-end check of the web interface in a real browser.
//
// Needs a running installation that holds both sample logs and nothing else, as
// `docker compose up` gives it:
//
//     npm run e2e                                    (interface and API of the Docker setup)
//     WEB=http://localhost:5173 API=http://127.0.0.1:8000 npm run e2e      (dev servers)
//
// The demo build is checked the same way. It has no server to ask, so the
// expected numbers still come from a running API:
//
//     npm run build:demo
//     DEMO=1 WEB=file://$PWD/dist-demo/index.html npm run e2e
//
// OUT=folder saves screenshots along the way. CHROMIUM=path uses that browser
// instead of the one Playwright installed (npx playwright install chromium).
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const WEB = process.env.WEB ?? "http://localhost:8080";
const API = process.env.API ?? "http://localhost:8080/api";
// DEMO=1: WEB is the single-file demo build; routes live after the # and nothing may touch the network.
const DEMO = Boolean(process.env.DEMO);
const OUT = process.env.OUT;
const SAMPLES = process.env.SAMPLES ?? fileURLToPath(new URL("../../samples", import.meta.url));

const route = (path) => (DEMO ? `${WEB}#${path}` : WEB + path);
/** The filters in the address, wherever this build keeps them. */
const query = (address) => {
  const url = new URL(address);
  return DEMO ? new URLSearchParams(url.hash.split("?")[1] ?? "") : url.searchParams;
};
const results = [];
const problems = [];
function check(name, ok, detail = "") {
  results.push(`${ok ? "ok  " : "FAIL"} ${name}${detail ? ` — ${detail}` : ""}`);
  if (!ok) problems.push(name);
}
const api = async (path) => (await fetch(API + path)).json();
const tr = (n) => new Intl.NumberFormat("tr-TR").format(n);

const stats = await api("/stats");
const alerts = (await api("/alerts?limit=500")).items;
const byRule = (rule, key) => alerts.find((a) => a.rule_id === rule && (!key || a.group_key === key));
const SCANNER = "198.51.100.150", BRUTE = "203.0.113.45", INTRUDER = "203.0.113.99";

const browser = await chromium.launch({ executablePath: process.env.CHROMIUM || undefined });
const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: "light", locale: "tr-TR" });
const page = await context.newPage();
const shot = async (name, options = {}) => OUT && (await page.screenshot({ path: `${OUT}/${name}.png`, ...options }));
const errors = [];
page.on("pageerror", (error) => errors.push(`pageerror: ${error.message}`));
page.on("response", (r) => r.status() >= 400 && errors.push(`HTTP ${r.status()} ${r.url()}`));
page.on("console", (message) => message.type() === "error" && errors.push(`console: ${message.text()}`));
const requests = [];
page.on("request", (request) => /^https?:/.test(request.url()) && requests.push(request.url()));
const timelineSvg = () => page.locator('svg[aria-label^="Zaman çizelgesi"]');
const portSvg = () => page.locator('svg[aria-label*="hedef portlar"]');

// 1. Dashboard
await page.goto(route("/"));
await page.getByText("Kapsanan zaman").waitFor();
await timelineSvg().locator("path").first().waitFor();
check("both samples are loaded", stats.events === 1838 && stats.alerts === 8, `${stats.events} events, ${stats.alerts} alerts`);
check("dashboard shows the event total", await page.getByText(tr(stats.events), { exact: true }).isVisible());
const alertButtons = page.locator("ul button[aria-pressed]");
check("dashboard lists every alert", (await alertButtons.count()) === 8, `${await alertButtons.count()}`);
const bars = await timelineSvg().locator("path").count();
check("timeline draws bars", bars >= 40, `${bars} paths`);
check("timeline has a mark per alert", (await timelineSvg().locator("rect[role=button]").count()) === 8);
check("top sources table lists the brute-force address first", (await page.locator("tbody tr").first().innerText()).includes(BRUTE));
await shot("ui-dashboard");

// Hover a column: the tooltip reads what the API says about that hour
const hour = (await api("/timeline?bucket=1h")).buckets.find((b) => b.ts === "2026-09-09T03:00:00Z");
const plot = timelineSvg().locator("rect.cursor-crosshair");
const box = await plot.boundingBox();
await page.mouse.move(box.x + box.width * (3.5 / 48), box.y + box.height / 2); // 03:00-04:00 on day one
await page.getByText("şüpheli olay", { exact: true }).waitFor();
const tooltip = await page.locator("div.pointer-events-none").innerText();
check("tooltip reads the hovered hour", tooltip.includes("03:00") && tooltip.includes(String(hour.warnings)) && tooltip.includes(String(hour.count - hour.warnings)), tooltip.replace(/\n/g, " | "));
await page.mouse.move(0, 0);

if (DEMO) {
  check("demo says what it is", await page.getByText("Bu bir demodur").isVisible());
  check("demo offers no upload", (await page.locator("input[type=file]").count()) === 0 && (await page.getByRole("heading", { name: "Log yükle", exact: true }).count()) === 0);
} else {
  // Upload through the form: the same file again adds nothing
  await page.locator("input[type=file]").setInputFiles(`${SAMPLES}/auth.log`);
  await page.getByLabel("İlk satırın yılı").fill("2026");
  await page.getByRole("button", { name: "Log yükle" }).click();
  await page.getByText(/auth\.log yüklendi/).waitFor();
  const report = await page.locator("form p[aria-live]").innerText();
  check("uploading a file again reports its lines as already stored", /1\.057 tanesi zaten kayıtlıydı/.test(report) && /8 uyarı var/.test(report), report);
}

// 2. Click an alert: timeline moves to its range, evidence rows are highlighted
await page.locator("ul").getByRole("button", { name: /85 sn içinde 71 başarısız giriş/ }).click();
await page.waitForURL(/\/inceleme\?/);
const url = query(page.url());
check("alert click sets range and alert in the address", url.has("start") && url.has("end") && url.has("alert"), url.toString());
check("range starts a minute before the burst", url.get("start") === "2026-09-09T03:11:39Z", url.get("start"));
await page.locator("[data-evidence]").first().waitFor();
const label = await timelineSvg().getAttribute("aria-label");
check("timeline covers the alert's range", /03:11:39/.test(label) && /03:15:0\d/.test(label), label);
check("zoom can be undone", await page.getByRole("button", { name: "Tüm aralığı göster" }).isVisible());
const evidenceRows = page.locator("[data-evidence]");
const evidenceCount = await evidenceRows.count();
check("evidence rows are marked in the table", evidenceCount > 5, `${evidenceCount} visible`);
const marks = await page.locator("[data-evidence] mark").allInnerTexts();
check("the attacker's address is highlighted in every evidence row", marks.length === evidenceCount && marks.every((t) => t === BRUTE), `${marks.length} marks`);
check("evidence rows carry the rule tag and the severity edge", (await evidenceRows.first().innerText()).includes("SSH-001") && (await evidenceRows.first().getAttribute("data-severity-edge")) === "high");
const allRows = await page.locator("[role=listitem]").count();
check("rows around the burst are shown too, unmarked", allRows > evidenceCount, `${allRows} rows, ${evidenceCount} evidence`);
check("selected alert is summarized above the table", await page.getByText("71 kanıt satırı").isVisible());
check("selected alert is pressed in the panel", (await page.locator("ul button[aria-pressed=true]").count()) === 1);
await page.getByText(`Hedef portlar: ${BRUTE}`).waitFor();
check("the alert's address gets a port view", (await portSvg().count()) === 1 && (await page.getByText("22 SSH").count()) >= 1);
await shot("ui-investigate");

// 3. Only evidence
await page.getByLabel("Yalnızca kanıt satırları").click();
await page.waitForURL(/evidence=1/);
await page.getByText("71 satır", { exact: true }).waitFor();
check("evidence-only shows exactly the alert's 71 lines", query(page.url()).get("evidence") === "1");
check("every visible row is evidence", (await page.locator("[role=listitem]").count()) === (await page.locator("[data-evidence]").count()));

// Row detail
await page.locator("[role=listitem]").first().click();
check("clicking a row shows the raw line and its position", await page.getByText(/auth\.log, satır \d+/).isVisible());
const raw = await page.locator("pre").innerText();
check("raw line is shown", raw.startsWith("Sep  9 03:12:39 web-01 sshd["), raw.slice(0, 40));
check("the raw line carries the highlight too", (await page.locator("pre mark").allInnerTexts()).join() === BRUTE);
await page.getByRole("button", { name: `Yalnızca ${BRUTE} adresinin olaylarını göster` }).click();
await page.waitForURL(/ip=203\.0\.113\.45/);
// The field follows the address one frame later.
await page.waitForFunction((ip) => [...document.querySelectorAll("input")].some((input) => input.value === ip), BRUTE);
check("a row's address can become the filter", (await page.getByLabel("IP adresi").inputValue()) === BRUTE);

// 4. Whole range + paging
await page.getByRole("button", { name: "Filtreleri temizle" }).click();
await page.getByText(/200 satır yüklendi/).waitFor();
check("first page of the whole log is loaded", query(page.url()).toString() === "");
check("without an address in focus there is no port view", (await portSvg().count()) === 0);
const list = page.locator("[role=list]");
await list.evaluate((element) => element.scrollTo(0, element.scrollHeight));
await page.getByText(/400 satır yüklendi/).waitFor({ timeout: 10000 });
check("scrolling to the end fetches the next page", true);

// Filters: IP + level
const ofIntruder = (await api(`/events?ip=${INTRUDER}&limit=500`)).items;
const suspicious = ofIntruder.filter((e) => e.level === "warning").length;
await page.getByLabel("IP adresi").fill(INTRUDER);
await page.getByLabel("IP adresi").press("Enter");
await page.getByText(`${ofIntruder.length} satır`, { exact: true }).waitFor();
check("IP filter narrows the table and lands in the address", query(page.url()).get("ip") === INTRUDER, `${ofIntruder.length} rows`);
await page.getByLabel("Düzey").selectOption("warning");
await page.getByText(`${suspicious} satır`, { exact: true }).waitFor();
check("level filter combines with it", query(page.url()).get("level") === "warning", `${suspicious} rows`);
await page.reload();
await page.getByText(`${suspicious} satır`, { exact: true }).waitFor();
check("the view survives a reload", (await page.getByLabel("IP adresi").inputValue()) === INTRUDER);
await page.getByRole("button", { name: "Filtreleri temizle" }).click();
await page.getByText(/200 satır yüklendi/).waitFor();
check("clearing filters empties the address", query(page.url()).toString() === "");

// Filter by what a line says happened
const logins = (await api("/events?action=auth_ok&limit=500")).items.length;
await page.getByLabel("Eylem").selectOption("auth_ok");
await page.getByText(`${logins} satır`, { exact: true }).waitFor();
check("action filter lists the successful logins", query(page.url()).get("action") === "auth_ok" && logins === 13, `${logins} rows`);
await page.getByRole("button", { name: "Filtreleri temizle" }).click();
await page.getByText(/200 satır yüklendi/).waitFor();

// 5. Brush
const plot2 = await timelineSvg().locator("rect.cursor-crosshair").boundingBox();
await page.mouse.move(plot2.x + plot2.width * 0.25, plot2.y + 40);
await page.mouse.down();
await page.mouse.move(plot2.x + plot2.width * 0.5, plot2.y + 40, { steps: 5 });
await page.mouse.up();
await page.waitForURL(/start=/);
const brushed = query(page.url());
const hours = (Date.parse(brushed.get("end")) - Date.parse(brushed.get("start"))) / 3_600_000;
check("dragging across the timeline selects that stretch", Math.abs(hours - 12) < 0.2 && brushed.get("start").startsWith("2026-09-09T12:0"), `${brushed.get("start")} +${hours.toFixed(2)}h`);
await page.goBack();
check("back button undoes the selection", query(page.url()).toString() === "");

// 6. The port scan
await page.goto(route("/"));
await page.locator("ul").getByRole("button", { name: /120 farklı portu denedi/ }).click();
await page.waitForURL(/\/inceleme\?/);
await page.getByText(`Hedef portlar: ${SCANNER}`).waitFor();
await portSvg().locator("g[stroke-linecap=round]").first().waitFor();
const figures = await page.locator("section", { hasText: "Hedef portlar" }).locator("dl").innerText();
check("port view reports the scan's numbers", figures.replace(/\s+/g, " ") === "Farklı port 120 Paket 120 Engellenen 117 Geçirilen 3", figures.replace(/\s+/g, " "));
const blockedMarks = await portSvg().locator("g[stroke-linecap=round]").count();
const allowedMarks = await portSvg().locator("circle[paint-order=stroke]").count();
check("every packet of the scan is drawn", blockedMarks === 117 && allowedMarks === 3, `${blockedMarks} blocked, ${allowedMarks} allowed`);
check("a scan of single packets is said in words, not bars", await page.getByText("Hiçbir porta birden çok paket gelmedi.").isVisible());
const open = await page.locator("div", { hasText: /^Güvenlik duvarının geçirdiği portlar/ }).last().locator("p").innerText();
check("the ports the firewall let through are listed", open === "22 SSH, 80 HTTP, 443 HTTPS", open);
const scanRows = page.locator("[data-evidence]");
const firstRow = await scanRows.first().innerText();
const rowMarks = await scanRows.first().locator("mark").allInnerTexts();
const cells = await scanRows.first().locator(":scope > span").allInnerTexts();
check("scan evidence marks the address and the port", rowMarks.length === 2 && rowMarks[0] === SCANNER && rowMarks[1] === cells[4], rowMarks.join(" + "));
check("long packet lines are shortened around the marks", /^\[UFW BLOCK\] … SRC=198\.51\.100\.150 … DPT=\d+/.test(cells[5].replace(/\n.*/s, "")), cells[5].replace(/\n/g, " | ").slice(0, 70));
const markBox = await scanRows.first().locator("mark").nth(1).boundingBox();
const cellBox = await scanRows.first().locator(":scope > span").nth(5).boundingBox();
check("both marks are inside the visible part of the row", markBox.x + markBox.width <= cellBox.x + cellBox.width + 1, `${Math.round(markBox.x + markBox.width)} <= ${Math.round(cellBox.x + cellBox.width)}`);
check("the port column shows the destination port", /^\d+$/.test(cells[4]) && firstRow.includes("conn_block"), cells[4]);

// Hover a mark of the scan
const target = await portSvg().locator("circle[paint-order=stroke]").first().boundingBox();
await page.mouse.move(target.x + target.width / 2, target.y + target.height / 2);
await page.getByText("geçirildi").waitFor();
const tip = (await page.locator("div.pointer-events-none").innerText()).replace(/\n/g, " | ");
check("hovering a mark reads its time, port and verdict", /9 Eyl 05:20:\d\d \| (22 \| SSH|80 \| HTTP|443 \| HTTPS) \| geçirildi/.test(tip), tip);
await page.mouse.move(0, 0);
await shot("ui-portscan", { fullPage: true });

// Bars and their link to the marks
await page.goto(route(`/inceleme?ip=${BRUTE}`));
await page.getByText(`Hedef portlar: ${BRUTE}`).waitFor();
await portSvg().locator("circle[paint-order=stroke]").first().waitFor();
const barRows = page.locator("section", { hasText: "Hedef portlar" }).locator("ol li");
check("busiest ports are ranked as bars", (await barRows.allInnerTexts()).map((t) => t.replace(/\s+/g, " ")).join(" ; ") === "22 SSH 49 ; 135 MS RPC 1", (await barRows.allInnerTexts()).map((t) => t.replace(/\s+/g, " ")).join(" ; "));
const clusterCount = await portSvg().locator("circle[paint-order=stroke]").count();
check("packets that fall on one spot are drawn as one larger mark", clusterCount < 49 && (await portSvg().locator("circle[paint-order=stroke]").first().getAttribute("r")) > "4", `${clusterCount} marks for 49 packets`);
await barRows.first().hover();
const dimmed = await portSvg().locator('g[stroke-linecap=round][opacity="0.16"]').count();
check("pointing at a port dims the marks of the others", dimmed === 1, `${dimmed} dimmed`);
await page.mouse.move(0, 0);

// 7. Dark theme
await page.getByRole("button", { name: /temaya geç/ }).click();
check("theme switches to dark", (await page.evaluate(() => document.documentElement.dataset.theme)) === "dark");
const breakIn = byRule("SSH-002");
await page.goto(route(`/inceleme?start=2026-09-10T02%3A30%3A40Z&end=2026-09-10T02%3A38%3A00Z&alert=${breakIn.id}`));
await page.locator("[data-evidence]").first().waitFor();
check("theme is remembered across pages", (await page.evaluate(() => document.documentElement.dataset.theme)) === "dark");
check("an event that is evidence for two alerts carries both tags", /SSH-001/.test(await page.locator("[data-evidence]").first().innerText()) && /SSH-002/.test(await page.locator("[data-evidence]").first().innerText()));
await shot("ui-dark");
await page.getByRole("button", { name: /temaya geç/ }).click();

// 8. Rules
await page.getByRole("link", { name: "Kurallar" }).click();
await page.getByText("SSH kaba kuvvet denemesi").waitFor();
const loaded = (await api("/rules")).rules;
const taken = loaded.filter((rule) => rule.source).length;
const listed = await page.locator("li h3").count();
check("rules page lists every rule", listed === loaded.length && taken > 20, `${listed} listed, ${loaded.length} loaded`);
check(
  "own rules and taken rules are listed apart",
  (await page.getByRole("heading", { name: `Bu kurulumun kuralları (${loaded.length - taken})` }).count()) === 1 &&
    (await page.getByRole("heading", { name: `Başka koleksiyonlardan alınan kurallar (${taken})` }).count()) === 1,
);
const shell = page.locator("li", { has: page.getByRole("heading", { name: "Suspicious Reverse Shell Command Line" }) });
check("a taken rule names its author, licence and source", (await shell.getByText("Florian Roth (Nextron Systems)").count()) === 1 && (await shell.getByText("Detection Rule License 1.1").count()) === 1 && (await shell.getByRole("link", { name: "github.com/…/lnx_shell_susp_rev_shells.yml" }).count()) === 1);
check("its keywords are marked, eight shown", (await shell.locator("mark:visible").count()) === 8, `${await shell.locator("mark:visible").count()} visible`);
await shell.getByText("17 metin daha").click();
check("the rest unfold", (await shell.locator("mark:visible").count()) === 25, `${await shell.locator("mark:visible").count()} visible`);
check("the switched-off rule says so", (await page.locator("li", { has: page.getByRole("heading", { name: "Cleartext Protocol Usage" }) }).getByText("Kapalı", { exact: true }).count()) === 1);
for (const sentence of [
  "Aynı kaynak adres için 60 sn içinde 5 eşleşen olay",
  "Aynı kaynak adres için 600 sn içinde sırayla: 5 kez eylem auth_fail, ardından eylem auth_ok",
  "Aynı kaynak adres için 60 sn içinde 15 farklı hedef port",
  "Şu portlardan birine bağlantı: 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379",
  "Bakılan olaylar: eylem conn_allow",
]) {
  check(`rule described in words: ${sentence.slice(0, 44)}…`, await page.getByText(sentence, { exact: true }).first().isVisible());
}
if (DEMO) {
  check("demo offers no rule reload", (await page.getByRole("button", { name: "Kuralları yeniden yükle" }).count()) === 0 && (await page.getByText("Demoda değiştirilemezler").count()) === 1);
} else {
  await page.getByRole("button", { name: "Kuralları yeniden yükle" }).click();
  await page.getByText(/Yeniden yüklendi: 8 uyarı var/).waitFor();
  check("reload reports the alert count", true);
}
await shot("ui-rules");

// 9. Phone width
await page.setViewportSize({ width: 390, height: 844 });
for (const [name, path, ready] of [
  ["dashboard", "/", "Kapsanan zaman"],
  ["port view", `/inceleme?ip=${SCANNER}&start=2026-09-09T05%3A19%3A00Z&end=2026-09-09T05%3A22%3A00Z`, `Hedef portlar: ${SCANNER}`],
  ["rules", "/kurallar", "SSH kaba kuvvet denemesi"],
]) {
  await page.goto(route(path));
  await page.getByText(ready).first().waitFor();
  await page.waitForTimeout(300);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  check(`no sideways scrolling at phone width: ${name}`, overflow <= 0, `${overflow}px`);
}
await page.goto(route("/"));
await page.getByText("Kapsanan zaman").waitFor();
await shot("ui-phone", { fullPage: true });

// 10. Unknown page, console
await page.goto(route("/yok"));
await page.getByText("Böyle bir sayfa yok").waitFor();
check("unknown address shows a way back", await page.getByText("Böyle bir sayfa yok").isVisible());
if (DEMO) check("the demo never talks to a server", requests.length === 0, requests.slice(0, 3).join(" ; "));
check("no errors in the browser console", errors.length === 0, errors.slice(0, 3).join(" ; "));

console.log(results.join("\n"));
console.log(problems.length ? `\n${problems.length} PROBLEM(S)` : "\nall checks passed");
await browser.close();
process.exit(problems.length ? 1 : 0);
