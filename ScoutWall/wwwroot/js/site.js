// ScoutWall client behaviour: theme toggle, local times, confirmations, auto refresh, sortable tables, the map and charts.
(function () {
    "use strict";

    function readStorage(key) {
        try {
            return localStorage.getItem(key);
        } catch (error) {
            return null;
        }
    }

    function writeStorage(key, value) {
        try {
            localStorage.setItem(key, value);
        } catch (error) {
            // Storage unavailable (private window); the setting simply is not remembered.
        }
    }

    function initializeThemeToggle() {
        document.querySelectorAll("[data-theme-toggle]").forEach(function (button) {
            button.addEventListener("click", function () {
                var current = document.documentElement.getAttribute("data-bs-theme");
                var next = current === "dark" ? "light" : "dark";
                document.documentElement.setAttribute("data-bs-theme", next);
                writeStorage("scoutwall-theme", next);
                renderCharts();
            });
        });
    }

    function localizeTimes() {
        var formatter = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "medium" });
        document.querySelectorAll("time[data-local-time]").forEach(function (element) {
            var date = new Date(element.getAttribute("datetime"));
            if (!isNaN(date.getTime())) {
                element.textContent = formatter.format(date);
                element.title = date.toISOString();
            }
        });
    }

    function initializeConfirmations() {
        document.querySelectorAll("form[data-confirm]").forEach(function (form) {
            form.addEventListener("submit", function (event) {
                if (!window.confirm(form.getAttribute("data-confirm"))) {
                    event.preventDefault();
                }
            });
        });
    }

    // Long-running form posts (the assistant can take a few seconds) show that something is happening.
    function initializeBusyForms() {
        document.querySelectorAll("form[data-busy-text]").forEach(function (form) {
            form.addEventListener("submit", function () {
                var button = form.querySelector("button[type=submit]");
                if (button) {
                    button.disabled = true;
                    button.textContent = form.getAttribute("data-busy-text");
                }
            });
        });
    }

    function initializeAutoRefresh() {
        var container = document.querySelector("[data-auto-refresh]");
        if (!container) {
            return;
        }

        var seconds = parseInt(container.getAttribute("data-auto-refresh"), 10) || 30;
        var toggle = document.querySelector("[data-auto-refresh-toggle]");
        var paused = readStorage("scoutwall-refresh-paused") === "true";
        var timer = null;

        function updateToggle() {
            if (toggle) {
                toggle.textContent = paused ? "Resume auto refresh" : "Pause auto refresh (" + seconds + "s)";
            }
        }

        function schedule() {
            window.clearTimeout(timer);
            if (!paused) {
                timer = window.setTimeout(function () { window.location.reload(); }, seconds * 1000);
            }
        }

        if (toggle) {
            toggle.addEventListener("click", function () {
                paused = !paused;
                writeStorage("scoutwall-refresh-paused", paused ? "true" : "false");
                updateToggle();
                schedule();
            });
        }

        updateToggle();
        schedule();
    }

    function formatBytes(value) {
        var units = ["B", "KB", "MB", "GB", "TB"];
        var unitIndex = 0;
        while (Math.abs(value) >= 1024 && unitIndex < units.length - 1) {
            value /= 1024;
            unitIndex++;
        }
        return (unitIndex === 0 || value >= 100 ? value.toFixed(0) : value.toFixed(1)) + " " + units[unitIndex];
    }

    function cssToken(name) {
        return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    }

    var charts = [];

    function buildChart(canvas, data) {
        var timeFormatter = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
        var labels = data.labels.map(function (label) {
            return data.labelsAreTimes ? timeFormatter.format(new Date(parseInt(label, 10) * 1000)) : label;
        });

        var textSecondary = cssToken("--sw-text-secondary");
        var grid = cssToken("--sw-grid");
        var surface = cssToken("--sw-surface");
        var valueAxis = data.horizontal ? "x" : "y";
        var categoryAxis = data.horizontal ? "y" : "x";

        var datasets = data.series.map(function (series, seriesIndex) {
            var color = cssToken("--sw-series-" + series.slot);
            return {
                borderDash: data.type === "line" && seriesIndex > 0 ? [6, 4] : [],
                label: series.label,
                data: series.values,
                borderColor: data.type === "line" ? color : surface,
                backgroundColor: data.type === "line" ? color + "22" : color,
                borderWidth: data.type === "line" ? 2 : (data.stacked ? { top: 2, right: 0, bottom: 0, left: 0 } : 0),
                borderRadius: data.type === "bar" ? 4 : 0,
                borderSkipped: data.horizontal ? "start" : "bottom",
                pointRadius: 0,
                pointHoverRadius: 5,
                pointHoverBorderColor: surface,
                pointHoverBorderWidth: 2,
                fill: data.type === "line",
                tension: 0.25,
                maxBarThickness: 28
            };
        });

        var scales = {};
        scales[valueAxis] = {
            beginAtZero: true,
            stacked: data.stacked,
            grid: { color: grid },
            border: { display: false },
            ticks: {
                color: textSecondary,
                callback: function (value) { return formatValue(value, data.unit); }
            }
        };
        scales[categoryAxis] = {
            stacked: data.stacked,
            grid: { display: false },
            border: { color: grid },
            ticks: { color: textSecondary, maxRotation: 0, autoSkip: true, autoSkipPadding: 16 }
        };

        return new Chart(canvas, {
            type: data.type,
            data: { labels: labels, datasets: datasets },
            options: {
                maintainAspectRatio: false,
                animation: false,
                indexAxis: data.horizontal ? "y" : "x",
                interaction: { mode: "index", intersect: false },
                plugins: {
                    legend: {
                        display: data.series.length > 1,
                        position: "top",
                        align: "start",
                        labels: { color: textSecondary, boxWidth: 12, boxHeight: 12, useBorderRadius: true, borderRadius: 3 }
                    },
                    tooltip: {
                        callbacks: {
                            label: function (context) {
                                var value = context.parsed[valueAxis];
                                return " " + context.dataset.label + ": " + formatValue(value, data.unit);
                            }
                        }
                    }
                },
                scales: scales
            }
        });
    }

    // Presence strip segments get a local-time tooltip: "Away: 01:04 to 07:32 (6 h 28 min)".
    function initializePresenceStrips() {
        var formatter = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
        document.querySelectorAll("[data-presence-label]").forEach(function (segment) {
            var text = segment.getAttribute("data-presence-label") + ": " +
                formatter.format(new Date(segment.getAttribute("data-start"))) + " to " +
                formatter.format(new Date(segment.getAttribute("data-end"))) + " (" + segment.getAttribute("data-duration") + ")";
            segment.title = text;
            segment.setAttribute("aria-label", text);
            segment.tabIndex = 0;
        });
    }

    // Tables marked data-sortable sort in the browser when a column heading is clicked. Cells may carry
    // data-sort-value with the raw number, so "1.2 GB" sorts by bytes. The choice survives auto refresh.
    function initializeSortableTables() {
        document.querySelectorAll("table[data-sortable]").forEach(function (table) {
            var storageKey = "scoutwall-sort-" + (table.getAttribute("data-sortable") || "table");
            var headings = Array.prototype.slice.call(table.querySelectorAll("thead th[data-sort]"));

            function cellValue(row, index, numeric) {
                var cell = row.children[index];
                var text = cell ? (cell.getAttribute("data-sort-value") || cell.textContent.trim()) : "";
                return numeric ? (parseFloat(text) || 0) : text.toLowerCase();
            }

            function sortBy(heading, descending) {
                // Tables with grouped (two-row) headings name the body column each heading sorts.
                var index = heading.hasAttribute("data-sort-column")
                    ? parseInt(heading.getAttribute("data-sort-column"), 10)
                    : Array.prototype.indexOf.call(heading.parentElement.children, heading);
                var numeric = heading.getAttribute("data-sort") === "number";
                var body = table.tBodies[0];
                var rows = Array.prototype.slice.call(body.rows);
                rows.sort(function (first, second) {
                    var a = cellValue(first, index, numeric);
                    var b = cellValue(second, index, numeric);
                    var order = a < b ? -1 : a > b ? 1 : 0;
                    return descending ? -order : order;
                });
                rows.forEach(function (row) { body.appendChild(row); });
                headings.forEach(function (other) { other.setAttribute("aria-sort", other === heading ? (descending ? "descending" : "ascending") : "none"); });
            }

            headings.forEach(function (heading, position) {
                var button = document.createElement("button");
                button.type = "button";
                button.className = "sw-sort-button";
                while (heading.firstChild) {
                    button.appendChild(heading.firstChild);
                }
                heading.appendChild(button);
                heading.setAttribute("aria-sort", "none");
                button.addEventListener("click", function () {
                    // Numbers start largest first, names start A to Z.
                    var current = heading.getAttribute("aria-sort");
                    var descending = current === "none" ? heading.getAttribute("data-sort") === "number" : current === "ascending";
                    sortBy(heading, descending);
                    try {
                        sessionStorage.setItem(storageKey, position + ":" + (descending ? "d" : "a"));
                    } catch (error) {
                        // Storage unavailable; the order is simply not remembered.
                    }
                });
            });

            var saved = null;
            try {
                saved = sessionStorage.getItem(storageKey);
            } catch (error) {
                saved = null;
            }
            if (saved) {
                var parts = saved.split(":");
                var heading = headings[parseInt(parts[0], 10)];
                if (heading) {
                    sortBy(heading, parts[1] === "d");
                }
            }
        });
    }

    // Map dots carry their description in data-map-label; it follows the pointer and is read by keyboard focus.
    function initializeMapTooltips() {
        document.querySelectorAll("[data-world-map]").forEach(function (map) {
            var tooltip = map.querySelector(".sw-map-tooltip");
            if (!tooltip) {
                return;
            }

            function show(dot, clientX, clientY) {
                var bounds = map.getBoundingClientRect();
                tooltip.textContent = dot.getAttribute("data-map-label");
                tooltip.hidden = false;
                var left = Math.min(Math.max(clientX - bounds.left + 12, 4), bounds.width - tooltip.offsetWidth - 4);
                var top = clientY - bounds.top - tooltip.offsetHeight - 12;
                tooltip.style.left = left + "px";
                tooltip.style.top = (top < 4 ? clientY - bounds.top + 16 : top) + "px";
            }

            map.querySelectorAll("[data-map-label]").forEach(function (dot) {
                dot.addEventListener("mousemove", function (event) { show(dot, event.clientX, event.clientY); });
                dot.addEventListener("focus", function () {
                    var box = dot.getBoundingClientRect();
                    show(dot, box.left + box.width / 2, box.top);
                });
                dot.addEventListener("mouseleave", function () { tooltip.hidden = true; });
                dot.addEventListener("blur", function () { tooltip.hidden = true; });
            });
        });
    }

    function formatValue(value, unit) {
        if (unit === "bytes") {
            return formatBytes(value);
        }

        return unit === "percent" ? value + "%" : value;
    }

    function renderCharts() {
        if (typeof Chart === "undefined") {
            return;
        }

        charts.forEach(function (chart) { chart.destroy(); });
        charts = [];

        document.querySelectorAll("canvas[data-chart]").forEach(function (canvas) {
            var source = document.getElementById(canvas.getAttribute("data-chart"));
            if (!source) {
                return;
            }

            var data = JSON.parse(source.textContent);
            var hasValues = data.series.some(function (series) { return series.values.some(function (value) { return value > 0; }); });
            if (!hasValues) {
                // Keep the container: clearing it detaches the canvas, so its parent can't be reached afterwards.
                var container = canvas.parentElement;
                container.innerHTML = "";
                var emptyMessage = document.createElement("p");
                emptyMessage.className = "text-body-secondary small m-0 py-5 text-center";
                emptyMessage.textContent = "No data in this time range yet.";
                container.appendChild(emptyMessage);
                return;
            }

            charts.push(buildChart(canvas, data));
        });
    }

    document.addEventListener("DOMContentLoaded", function () {
        initializeThemeToggle();
        localizeTimes();
        initializeConfirmations();
        initializeBusyForms();
        initializeAutoRefresh();
        initializeSortableTables();
        initializePresenceStrips();
        initializeMapTooltips();
        renderCharts();
    });
})();
