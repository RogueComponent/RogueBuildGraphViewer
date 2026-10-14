/* Applies a remembered theme before first paint.
 *
 * A classic script on purpose, not a module: modules are deferred and would
 * run after the first frame, so an explicit light-or-dark choice would flash
 * the OS theme for a moment on every load. All the theme logic lives in
 * app.js (which also writes the stored value); this only replays its result.
 * No markup is touched -- one attribute on <html>, nothing else (V48). */
(function () {
  try {
    var mode = localStorage.getItem("bgview-theme");
    if (mode === "light" || mode === "dark") {
      document.documentElement.setAttribute("data-theme", mode);
    }
  } catch (e) {
    /* storage unavailable (private mode, blocked): follow the OS */
  }
})();
