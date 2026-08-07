/**
 * `/data/quotes.enc` — живой слой котировок, тоже из R2 и тоже со своего origin.
 *
 * Адрес, по которому страница его просит, приходит внутри расшифрованного payload
 * (`LIVE_QUOTES_URL` у конвейера), поэтому переезд сюда — это правка одной переменной
 * окружения на сервере, а не кода страницы.
 *
 * Зачем переезжать, если публичный адрес бакета работал: этот объект запрашивается
 * каждые двадцать секунд каждой открытой вкладкой — самый частый запрос во всей
 * системе, и ровно тот случай, против которого Cloudflare ограничивает `r2.dev` и
 * называет его путём для разработки. Со своего origin ограничения нет, CORS не нужен,
 * а из CSP уходит внешний хост.
 *
 * Ключи здесь по-прежнему не лежат: объект зашифрован тем же ключом, что и payload,
 * ключ приходит внутри payload, а payload открывается паролем владельца.
 */

export async function onRequestGet({ env, request }) {
  const object = await env.DATA.get("quotes.enc", { onlyIf: request.headers });

  if (object === null) {
    // Живой слой необязателен: страница переживает его отсутствие и говорит об этом
    // строкой. Явный JSON, чтобы она сказала именно это, а не «конверт не разобрался».
    return new Response(
      JSON.stringify({ error: "the live quote layer has not been published yet" }),
      {
        status: 503,
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
  // Агент переписывает объект чаще, чем истёк бы любой кэш; страница и так просит без
  // кэша. Единственный честный ответ на «какая сейчас цена» — тот, что пришёл сейчас.
  headers.set("cache-control", "no-store");
  // Last-Modified, а не только собственный заголовок. Это стандартный признак возраста
  // публикации, и его отсутствие — не мелочь: канарейка 839 определяет по нему, не встал ли
  // публикатор, и без него отказывается выносить вердикт вовсе, чтобы остановившаяся
  // публикация не пряталась за неполным заголовком. `writeHttpMetadata` его не пишет — она
  // переносит только httpMetadata объекта, а время выгрузки лежит отдельным полем.
  if (object.uploaded) {
    headers.set("x-quotes-uploaded", object.uploaded.toISOString());
    headers.set("last-modified", object.uploaded.toUTCString());
  }

  if (!("body" in object) || object.body === null) {
    return new Response(null, { status: 304, headers });
  }
  return new Response(object.body, { headers });
}

// HEAD — это GET без тела, и обслуживать его обязана та же функция. Без этого экспорта
// Pages не находит обработчика на метод и уходит к статике, а та на неизвестный путь
// отвечает 200 и HTML главной страницы. Сторож свежести, спрашивающий Last-Modified
// именно методом HEAD, получал заглушку и объявлял живую панель мёртвой — проверено
// на себе в первый же прогон.
export async function onRequestHead(context) {
  const response = await onRequestGet(context);
  return new Response(null, { status: response.status, headers: response.headers });
}
