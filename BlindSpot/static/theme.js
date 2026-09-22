// Reads the visitor's saved theme choice (or their OS preference the first
// time) and applies it. The toggle button flips between dark and light and
// remembers the choice for next time using localStorage.
(function () {
  function getPreferredTheme() {
    var saved = localStorage.getItem("blindspot-theme");
    if (saved === "dark" || saved === "light") return saved;
    return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    var button = document.getElementById("theme-toggle-btn");
    if (button) {
      button.textContent = theme === "dark" ? "☀️" : "🌙";
      button.setAttribute("aria-label", theme === "dark" ? "Switch to light mode" : "Switch to dark mode");
    }
  }

  // Apply immediately, before the page paints, so there's no flash of the
  // wrong theme.
  applyTheme(getPreferredTheme());

  document.addEventListener("DOMContentLoaded", function () {
    var button = document.getElementById("theme-toggle-btn");
    if (!button) return;

    applyTheme(getPreferredTheme());

    button.addEventListener("click", function () {
      var current = document.documentElement.getAttribute("data-theme") || "dark";
      var next = current === "dark" ? "light" : "dark";
      localStorage.setItem("blindspot-theme", next);
      applyTheme(next);
    });
  });
})();
