/*
 * Тема до первой отрисовки — и вечернее правило.
 *
 * Отдельным файлом, а не инлайном в <head>, потому что политика этой страницы
 * говорит `script-src 'self'`: инлайн запрещён, а ослаблять политику ради оформления
 * нельзя — это страница, на которой вводится пароль от портфеля.
 *
 * Загружается синхронно и до стилей: если поставить тему из app.js в конце body,
 * вечером будет вспышка светлого перед затемнением, и заметна она ровно тогда, когда
 * панель и открывают.
 *
 * Правило: с 20:00 до 07:00 по времени устройства панель открывается тёмной, что бы
 * ни было выбрано раньше. Постоянный выбор при этом НЕ затирается — утром вернётся он.
 * Переключение вечером живёт в sessionStorage: переживает перезагрузку страницы,
 * исчезает с закрытием вкладки и не трогает утреннюю память.
 *
 * Здесь же единственная копия правила: app.js берёт его отсюда, а не повторяет, иначе
 * две копии однажды разойдутся и вечер начнётся в разное время в разных местах.
 */
(function () {
  "use strict";

  var THEME_KEY = "portfolio-ledger:theme";
  var NIGHT_KEY = "portfolio-ledger:theme-tonight";
  var NIGHT_FROM = 20;
  var NIGHT_TO = 7;

  function isNight(date) {
    var hour = (date || new Date()).getHours();
    return hour >= NIGHT_FROM || hour < NIGHT_TO;
  }

  function read(storage, key) {
    try {
      var value = window[storage].getItem(key);
      return value === "light" || value === "dark" ? value : null;
    } catch (error) {
      return null;
    }
  }

  /* Постоянный выбор владельца, без вечерней подмены. */
  function stored() {
    return read("localStorage", THEME_KEY);
  }

  /* Что показать сейчас: null значит «как в системе». */
  function resolve() {
    if (isNight()) return read("sessionStorage", NIGHT_KEY) || "dark";
    return stored();
  }

  function remember(theme) {
    try {
      if (isNight()) window.sessionStorage.setItem(NIGHT_KEY, theme);
      else window.localStorage.setItem(THEME_KEY, theme);
    } catch (error) {
      /* приватный режим: выбор просто не переживёт вкладку */
    }
  }

  var initial = resolve();
  if (initial === "light" || initial === "dark") {
    document.documentElement.setAttribute("data-theme", initial);
  }

  window.__theme = {
    isNight: isNight,
    stored: stored,
    resolve: resolve,
    remember: remember,
    NIGHT_FROM: NIGHT_FROM,
    NIGHT_TO: NIGHT_TO,
  };
})();
