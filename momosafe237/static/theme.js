// This file remembers whether the user prefers light or dark mode
// and applies it. "localStorage" is the browser's own small
// storage box that keeps a value even after the page is closed.

function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    const button = document.getElementById("theme-toggle-btn");
    if (button) {
        button.textContent = theme === "dark" ? "☀️ Light" : "🌙 Dark";
    }
}

function toggleTheme() {
    const current = document.documentElement.getAttribute("data-theme") || "light";
    const next = current === "dark" ? "light" : "dark";
    localStorage.setItem("momosafe_theme", next);
    applyTheme(next);
}

// Run as soon as the page loads: use the saved preference,
// or fall back to the visitor's system preference.
(function () {
    const saved = localStorage.getItem("momosafe_theme");
    if (saved) {
        applyTheme(saved);
    } else if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) {
        applyTheme("dark");
    } else {
        applyTheme("light");
    }
})();

// Copy a piece of text (like a phone number) to the clipboard,
// and briefly change the button text to confirm it worked.
function copyText(text, button) {
    navigator.clipboard.writeText(text).then(function () {
        const original = button.textContent;
        button.textContent = "Copied!";
        setTimeout(function () {
            button.textContent = original;
        }, 1500);
    });
}
