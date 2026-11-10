import assert from "node:assert/strict";
import { mkdir } from "node:fs/promises";
import { chromium } from "playwright";
import AxeBuilder from "@axe-core/playwright";

const origin = process.env.SMOKE_ORIGIN ?? "http://127.0.0.1:4321";
const base = (
    process.env.SITE_BASE ?? "/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN"
).replace(/\/$/, "");
const url = (path = "") => `${origin}${base}/${path}`;
const browser = await chromium.launch({ channel: "chrome", headless: true });
const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
});
const page = await context.newPage();
const errors = [];
page.on("pageerror", (error) => errors.push(error.message));
page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
});

try {
    await mkdir(".screenshots", { recursive: true });
    for (const width of [320, 768, 1440]) {
        await page.setViewportSize({ width, height: 900 });
        await page.goto(url(), { waitUntil: "networkidle" });
        assert.match(await page.title(), /Network Anomaly Detection/);
        assert.equal(await page.locator("h1").count(), 1);
        const overflow = await page.evaluate(
            () => document.documentElement.scrollWidth - innerWidth,
        );
        assert.ok(
            overflow <= 1,
            `horizontal overflow at ${width}px: ${overflow}px`,
        );
        if (width === 320) {
            await page.locator(".mobile-menu summary").click();
            assert.ok(
                await page
                    .getByRole("navigation", { name: "Mobile navigation" })
                    .getByText("Research")
                    .isVisible(),
            );
            await page.screenshot({
                path: ".screenshots/home-mobile.png",
                fullPage: true,
            });
        }
        if (width === 1440)
            await page.screenshot({
                path: ".screenshots/home-desktop.png",
                fullPage: true,
            });
    }

    await page.goto(url("dataset/"), { waitUntil: "networkidle" });
    assert.match(await page.locator("h1").innerText(), /NF-UNSW-NB15-v3/);
    await page.reload({ waitUntil: "networkidle" });
    assert.ok(await page.getByText("2,365,424 rows").count());

    await page.goto(url("docs/"), { waitUntil: "networkidle" });
    await page.locator("#docs-search").fill("split");
    assert.ok((await page.locator(".doc-card:visible").count()) > 0);
    await page.locator("#docs-search").fill("zz-no-matching-guide");
    assert.ok(await page.locator("#search-empty").isVisible());

    await page.goto(url("docs/installation/"), { waitUntil: "networkidle" });
    assert.ok(await page.locator(".toc").isVisible());
    await page.locator(".copy-code").first().click();
    assert.match(
        await page.locator(".copy-code").first().innerText(),
        /Copied|Unavailable/,
    );

    await page.locator(".theme-toggle").click();
    assert.equal(
        await page.locator("html").getAttribute("data-theme"),
        "light",
    );
    await page.reload({ waitUntil: "networkidle" });
    assert.equal(
        await page.locator("html").getAttribute("data-theme"),
        "light",
    );
    await page.locator(".theme-toggle").click();

    for (const width of [320, 768, 1440]) {
        await page.setViewportSize({ width, height: 900 });
        for (const path of [
            "research/",
            "dataset/",
            "models/",
            "results/",
            "architecture/",
            "docs/",
            "docs/installation/",
            "roadmap/",
        ]) {
            await page.goto(url(path), { waitUntil: "networkidle" });
            assert.equal(
                await page.locator("h1").count(),
                1,
                `${path}: expected one page heading`,
            );
            const overflow = await page.evaluate(
                () => document.documentElement.scrollWidth - innerWidth,
            );
            const offenders =
                overflow > 1
                    ? await page.evaluate(() =>
                          [...document.querySelectorAll("*")]
                              .filter(
                                  (el) =>
                                      el.getBoundingClientRect().right >
                                      innerWidth + 1,
                              )
                              .slice(0, 8)
                              .map(
                                  (el) =>
                                      `${el.tagName}.${String(el.className).slice(0, 60)}=${Math.round(el.getBoundingClientRect().right)}`,
                              ),
                      )
                    : [];
            assert.ok(
                overflow <= 1,
                `${path}: horizontal overflow at ${width}px: ${overflow}px; ${offenders.join(", ")}`,
            );
        }
    }

    for (const theme of ["dark", "light"]) {
        await page.evaluate((value) => {
            document.documentElement.dataset.theme = value;
            localStorage.setItem("research-theme", value);
        }, theme);
        for (const path of ["", "dataset/", "results/", "docs/installation/"]) {
            await page.goto(url(path), { waitUntil: "networkidle" });
            const result = await new AxeBuilder({ page })
                .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
                .analyze();
            assert.equal(
                result.violations.length,
                0,
                `${theme}/${path || "home"}: ${result.violations.map((v) => `${v.id}: ${v.nodes.map((n) => `${n.target.join(",")} (${n.failureSummary})`).join(";")}`).join(" | ")}`,
            );
        }
    }
    assert.deepEqual(errors, []);
    console.log(
        `PASS: responsive, navigation, search, theme persistence, code copy and axe on ${base || "/"} .`,
    );
} finally {
    await browser.close();
}
