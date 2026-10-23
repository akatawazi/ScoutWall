// Applied before the page paints so there is no flash of the wrong theme.
(function () {
    var storedTheme = null;
    try {
        storedTheme = localStorage.getItem("scoutwall-theme");
    } catch (error) {
        storedTheme = null;
    }

    var prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    var theme = storedTheme || (prefersDark ? "dark" : "light");
    document.documentElement.setAttribute("data-bs-theme", theme);
})();
