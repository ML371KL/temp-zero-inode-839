/**
 * `/data/alerts.enc` — правила алертов, как их видит сервер.
 *
 * Этот путь обязан существовать, и его отсутствие стоило девяти часов молчащих алертов.
 * Агент котировок выводит адрес правил из `LIVE_QUOTES_URL`, отрезая последний сегмент:
 * переезд живого слоя на `/data/quotes.enc` автоматически переселил и правила на
 * `/data/alerts.enc`. Функции здесь не было, Cloudflare Pages ответил на неизвестный путь
 * **200 и HTML главной страницы**, разбор JSON упал, и вся секция alerts заменилась на
 * `alertsError`. Страница увидела отсутствие `writeUrl` и честно погасила панель, а
 * движок алертов перестал что-либо проверять — при полностью зелёных прогонах.
 *
 * Отсюда правило: 404 у статики — это не «нет данных», это HTML. Любой адрес, который
 * читает не браузер, а программа, обязан иметь свою функцию.
 *
 * Запись сюда идёт мимо этой функции — подписанной ссылкой прямо в R2, чтобы ключ не
 * появлялся ни на странице, ни здесь. Поэтому у бакета остаётся правило CORS на PUT.
 */

export async function onRequestGet({ env, request }) {
  const object = await env.DATA.get("alerts.enc", { onlyIf: request.headers });

  if (object === null) {
    // Правил ещё не ставили. Именно 404, а не пустой конверт: агент отличает «правил нет»
    // от «правила не прочитались» по коду ответа, и подменять первое вторым значило бы
    // прятать поломку за нормальным состоянием.
    return new Response(
      JSON.stringify({ error: "no alert rules have been published yet" }),
      {
        status: 404,
        headers: {
          "content-type": "application/json; charset=utf-8",
          "cache-control": "no-store",
        },
      },
    );
  }

  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("etag", object.httpEtag);
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("cache-control", "no-store");
  // Last-Modified, а не только собственный заголовок. Это стандартный признак возраста
  // публикации, и его отсутствие — не мелочь: канарейка 839 определяет по нему, не встал ли
  // публикатор, и без него отказывается выносить вердикт вовсе, чтобы остановившаяся
  // публикация не пряталась за неполным заголовком. `writeHttpMetadata` его не пишет — она
  // переносит только httpMetadata объекта, а время выгрузки лежит отдельным полем.
  if (object.uploaded) {
    headers.set("x-alerts-uploaded", object.uploaded.toISOString());
    headers.set("last-modified", object.uploaded.toUTCString());
  }

  if (!("body" in object) || object.body === null) {
    return new Response(null, { status: 304, headers });
  }
  return new Response(object.body, { headers });
}
