/**
 * A static server for the repository as it would be published.
 *
 * The page is an ES module that fetches `data/portfolio.enc`, so `file://` cannot host
 * it: modules are blocked by CORS there and the fetch fails before any check runs.
 * Written by hand rather than pulled in as a dependency, because the one thing this
 * server has to do that an off-the-shelf one does not is answer for the payload out of
 * memory — a scenario needs to serve a 500, a truncated body or a resealed envelope
 * without any of it touching the working tree.
 */

import { createServer } from "node:http";
import { createReadStream, statSync } from "node:fs";
import path from "node:path";

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".enc": "application/json; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
};

export const PAYLOAD_PATH = "/data/portfolio.enc";
// The live quote layer lives in an R2 bucket in production. Here it is served from
// the harness origin instead, which `connect-src 'self'` already allows, so the
// scenarios exercise the page's own fetch/decrypt/render path without depending on
// a network the runner may not have.
export const LIVE_QUOTES_PATH = "/data/quotes.enc";
// Куда браузер PUT-ит правила алертов. Тело запоминается: без него проверка могла
// подтвердить только то, что запись не упала, но не то, ЧТО именно записалось —
// ошибка в цене или пустое тело проходили все проверки.
export const ALERTS_SINK_PATH = "/data/alerts-sink";

export async function startSite(root) {
  // The one mutable thing in here. A scenario assigns to `.payload` before navigating
  // and every request for the encrypted blob is answered from it.
  const state = {
    payload: { status: 200, body: "{}", type: MIME[".enc"] },
    // 404 until a scenario says otherwise: the ordinary state of this route in a
    // check that is not about the live layer is "there is nothing there", and that
    // is exactly the case the page has to survive.
    liveQuotes: { status: 404, body: "not found", type: "text/plain" },
    alertPuts: [],
    alertsSinkStatus: 200,
  };

  const server = createServer((request, response) => {
    // Parsed as a URL rather than used raw: the page asks for `app.js?v=20260729-1`
    // and `styles.css?v=…`, and a server that treats the cache-busting query as part
    // of the filename answers 404 to every asset the page needs.
    const url = new URL(request.url, "http://localhost");
    const pathname = decodeURIComponent(url.pathname);

    if (pathname === ALERTS_SINK_PATH) {
      const chunks = [];
      request.on("data", (chunk) => chunks.push(chunk));
      request.on("end", () => {
        state.alertPuts.push({
          method: request.method,
          body: Buffer.concat(chunks).toString("utf8"),
        });
        response.writeHead(state.alertsSinkStatus, {
          "content-type": "text/plain",
          "cache-control": "no-store",
        });
        response.end("ok");
      });
      return;
    }

    if (pathname === LIVE_QUOTES_PATH) {
      // The delay exists for one scenario and could not be simulated without it:
      // the layer refreshes every twenty seconds, so a check that locks the page and
      // looks a moment later never observes a tick at all — it passes on code with
      // no lock guard whatsoever. Holding the response open puts the lock squarely
      // inside an unfinished fetch, which is the race the guard is there for.
      const send = () => {
        response.writeHead(state.liveQuotes.status, {
          "content-type": state.liveQuotes.type,
          "cache-control": "no-store",
        });
        response.end(state.liveQuotes.body);
      };
      if (state.liveQuotes.delayMs) setTimeout(send, state.liveQuotes.delayMs);
      else send();
      return;
    }

    if (pathname === PAYLOAD_PATH) {
      // No-store, because two scenarios in one run serve different bodies from the
      // same URL and the second one must not be answered out of the memory cache.
      response.writeHead(state.payload.status, {
        "content-type": state.payload.type,
        "cache-control": "no-store",
      });
      response.end(state.payload.body);
      return;
    }

    const relative = pathname === "/" ? "index.html" : pathname.replace(/^\/+/, "");
    const resolved = path.resolve(root, relative);
    // Refuse anything that escapes the site root. The harness only ever asks for files
    // the page asks for, but a server that will read `../../../etc/passwd` on request
    // is not something to leave lying in a repository whatever its intended use.
    if (resolved !== root && !resolved.startsWith(root + path.sep)) {
      response.writeHead(403).end("forbidden");
      return;
    }
    let stats;
    try {
      stats = statSync(resolved);
    } catch {
      response.writeHead(404, { "content-type": "text/plain" }).end("not found");
      return;
    }
    if (!stats.isFile()) {
      response.writeHead(404, { "content-type": "text/plain" }).end("not found");
      return;
    }
    response.writeHead(200, {
      "content-type": MIME[path.extname(resolved).toLowerCase()] || "application/octet-stream",
      "content-length": stats.size,
      "cache-control": "no-store",
    });
    createReadStream(resolved).pipe(response);
  });

  // Port 0: the runner picks a free one. A fixed port turns two runs on one machine
  // into a confusing EADDRINUSE instead of two runs.
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();

  return {
    origin: `http://127.0.0.1:${port}`,
    state,
    serve(body, { status = 200, type = MIME[".enc"] } = {}) {
      state.payload = {
        status,
        type,
        body: typeof body === "string" ? body : JSON.stringify(body),
      };
    },
    serveLiveQuotes(body, { status = 200, type = MIME[".enc"], delayMs = 0 } = {}) {
      state.liveQuotes = {
        status,
        type,
        delayMs,
        body: typeof body === "string" ? body : JSON.stringify(body),
      };
    },
    alertPuts() {
      return state.alertPuts;
    },
    resetAlertPuts(status = 200) {
      state.alertPuts = [];
      state.alertsSinkStatus = status;
    },
    /** Back to "there is nothing there", which is most scenarios' correct state. */
    withdrawLiveQuotes() {
      state.liveQuotes = { status: 404, body: "not found", type: "text/plain" };
    },
    async close() {
      await new Promise((resolve) => server.close(resolve));
    },
  };
}
