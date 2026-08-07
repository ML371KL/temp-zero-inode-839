/**
 * `/data/portfolio.enc` — зашифрованный payload отдаётся из R2, а не из публикации.
 *
 * Раньше он ехал к читателю веткой `payload` этого репозитория: пуш запускал сборку
 * GitHub Pages, и она клала файл на сайт. Между конвейером и страницей стояла очередь,
 * и 6 августа эта очередь встала — публикации четыре часа падали по десятиминутному
 * потолку, унося с собой уже готовые данные.
 *
 * Задержка была не главным. Живой слой котировок привязан к тому payload, для которого
 * посчитан: сервер уходил на новое поколение, страница держала предыдущее, и
 * перекрытие отбрасывалось каждый тик — панель молча показывала последний полный
 * обход котировок вместо рынка. Из бакета payload доезжает за секунды, и привязка
 * держится.
 *
 * Payload шифруется на клиенте, поэтому публичный объект в бакете ровно так же
 * безопасен, как публичная страница: без пароля это шум. Функция, а не публичный адрес
 * бакета — потому что `r2.dev` ограничен по частоте и назван в документации Cloudflare
 * путём для разработки, а тот же origin избавляет ещё и от CORS и от лишнего хоста в
 * CSP.
 *
 * Путь совпадает со старым намеренно: `app.js` как забирал `data/portfolio.enc`, так и
 * забирает.
 */

export async function onRequestGet({ env, request }) {
  const object = await env.DATA.get("portfolio.enc", { onlyIf: request.headers });

  if (object === null) {
    // Страница ждёт JSON-конверт и разбирает ответ как JSON. HTML-заглушка 404 упала бы
    // у неё на разборе и сказала бы владельцу совсем не то, что случилось.
    return new Response(
      JSON.stringify({ error: "payload has not been published to R2 yet" }),
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
  // Конвейер переписывает объект каждые полчаса, а страница спрашивает «что сейчас».
  headers.set("cache-control", "no-store");
  // Last-Modified, а не только собственный заголовок. Это стандартный признак возраста
  // публикации, и его отсутствие — не мелочь: канарейка 839 определяет по нему, не встал ли
  // публикатор, и без него отказывается выносить вердикт вовсе, чтобы остановившаяся
  // публикация не пряталась за неполным заголовком. `writeHttpMetadata` его не пишет — она
  // переносит только httpMetadata объекта, а время выгрузки лежит отдельным полем.
  if (object.uploaded) {
    headers.set("x-payload-uploaded", object.uploaded.toISOString());
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
