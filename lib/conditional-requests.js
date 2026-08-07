/**
 * Условные запросы: отличить «не изменилось» от «условие не выполнено».
 *
 * R2 принимает заголовки условий целиком и на невыполненное условие возвращает объект
 * БЕЗ тела — одинаково для всех четырёх заголовков. Функции читали это как 304, и для
 * `If-None-Match`/`If-Modified-Since` это верно: клиент спросил «изменилось ли», ответ —
 * «нет».
 *
 * Для `If-Match`/`If-Unmodified-Since` тот же ответ — ложь. Эти два заголовка спрашивают
 * не «изменилось ли», а «отдай только если ЭТО ещё та версия», и отрицательный ответ на
 * них по RFC 9110 §13.2.2 — 412 Precondition Failed. Разница не косметическая: 304
 * означает «бери свою копию, она актуальна», а у клиента, пришедшего с `If-Match`,
 * актуальной копии как раз и нет — он получил бы указание использовать заведомо
 * устаревшие данные.
 *
 * Сегодня таких клиентов нет. Заголовок появится в тот день, когда кто-нибудь напишет
 * дозагрузку по Range или сверку версии перед записью, и обнаруживать разницу тогда
 * будет некому: оба ответа выглядят как успех без тела.
 */

/**
 * Сильное сравнение валидаторов — то, которого требует `If-Match`. Слабый валидатор
 * (`W/"…"`) в сильном сравнении не совпадает ни с чем, включая самого себя: он говорит
 * «это семантически то же самое», а `If-Match` спрашивает «это побайтово то же самое».
 */
function matchesStrong(header, etag) {
  if (header.trim() === "*") return Boolean(etag);
  if (!etag || etag.startsWith("W/")) return false;
  return header.split(",").some((candidate) => candidate.trim() === etag);
}

/**
 * Ответ без тела пришёл из-за невыполненного `If-Match`/`If-Unmodified-Since`?
 *
 * Порядок разбора — из RFC: `If-Match` перекрывает `If-Unmodified-Since`, и когда есть
 * оба, второй не смотрят вовсе.
 */
export function preconditionFailed(request, object) {
  const ifMatch = request.headers.get("if-match");
  if (ifMatch !== null) return !matchesStrong(ifMatch, object.httpEtag);

  const ifUnmodifiedSince = request.headers.get("if-unmodified-since");
  if (ifUnmodifiedSince === null || !object.uploaded) return false;
  const limit = Date.parse(ifUnmodifiedSince);
  // Неразобранную дату RFC велит игнорировать, а не считать условие проваленным:
  // иначе опечатка в заголовке превращается в отказ отдавать данные.
  if (!Number.isFinite(limit)) return false;
  // Точность заголовка — секунда. Сравнение с миллисекундами объявляло бы условие
  // проваленным для объекта, выгруженного в ту же секунду, что и указанная граница.
  return Math.floor(object.uploaded.getTime() / 1000) * 1000 > limit;
}

/** Статус для ответа без тела: 412, если условие не выполнено, иначе честные 304. */
export function bodilessStatus(request, object) {
  return preconditionFailed(request, object) ? 412 : 304;
}
