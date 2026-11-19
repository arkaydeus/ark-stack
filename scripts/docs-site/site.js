// Ark Stack docs site behaviour: theme toggle, mobile navigation, copy buttons, the "On this page"
// highlight, Mermaid diagrams and offline full-text search. Plain script so pages also work from file://.
(function () {
  "use strict";
  var root = document.documentElement;
  var body = document.body;
  var base = body.dataset.base || "";

  // Theme: system preference unless the reader picked one.
  var themeButton = document.querySelector(".theme-toggle");
  function currentTheme() {
    if (root.dataset.theme) return root.dataset.theme;
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  if (themeButton) {
    themeButton.addEventListener("click", function () {
      var next = currentTheme() === "dark" ? "light" : "dark";
      root.dataset.theme = next;
      try {
        localStorage.setItem("ark-docs-theme", next);
      } catch {
        // Storage can be unavailable (private mode, file://); the choice then lasts for this page only.
      }
    });
  }

  // Mobile navigation drawer.
  var menuButton = document.querySelector(".menu-toggle");
  if (menuButton) {
    menuButton.addEventListener("click", function () {
      var open = body.classList.toggle("nav-open");
      menuButton.setAttribute("aria-expanded", String(open));
    });
  }

  // Sidebar sections start open; remember the ones the reader collapses (never the current page's).
  var closed = [];
  try {
    closed = JSON.parse(localStorage.getItem("ark-docs-closed") || "[]");
  } catch {
    closed = [];
  }
  document.querySelectorAll(".nav-section").forEach(function (section) {
    var name = section.dataset.section;
    if (closed.indexOf(name) >= 0 && !section.querySelector("a.active")) section.open = false;
    section.addEventListener("toggle", function () {
      closed = closed.filter(function (other) {
        return other !== name;
      });
      if (!section.open) closed.push(name);
      try {
        localStorage.setItem("ark-docs-closed", JSON.stringify(closed));
      } catch {
        // Not persisted when storage is unavailable.
      }
    });
  });

  // Keep the active page visible in a long sidebar.
  // Scroll only the sidebar: scrollIntoView would also scroll the page past its title.
  var sidebarPanel = document.querySelector(".sidebar");
  var active = document.querySelector(".sidebar a.active");
  if (sidebarPanel && active) {
    var offset = active.getBoundingClientRect().top - sidebarPanel.getBoundingClientRect().top;
    if (offset > sidebarPanel.clientHeight * 0.7)
      sidebarPanel.scrollTop = offset - sidebarPanel.clientHeight / 2;
  }

  // Copy buttons on code blocks.
  document.querySelectorAll(".prose pre:not(.mermaid)").forEach(function (pre) {
    var button = document.createElement("button");
    button.type = "button";
    button.className = "copy";
    button.textContent = "Copy";
    button.addEventListener("click", function () {
      var code = pre.querySelector("code");
      var text = (code || pre).textContent || "";
      var done = function () {
        button.textContent = "Copied";
        setTimeout(function () {
          button.textContent = "Copy";
        }, 1500);
      };
      if (navigator.clipboard) navigator.clipboard.writeText(text).then(done, function () {});
    });
    pre.appendChild(button);
  });

  // Highlight the section being read in "On this page".
  var tocLinks = Array.prototype.slice.call(document.querySelectorAll(".toc a"));
  if (tocLinks.length && "IntersectionObserver" in window) {
    var byId = {};
    tocLinks.forEach(function (link) {
      byId[decodeURIComponent(link.getAttribute("href").slice(1))] = link;
    });
    var visible = {};
    var observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          visible[entry.target.id] = entry.isIntersecting;
        });
        var first = tocLinks.find(function (link) {
          return visible[decodeURIComponent(link.getAttribute("href").slice(1))];
        });
        if (!first) return;
        tocLinks.forEach(function (link) {
          link.classList.toggle("active", link === first);
        });
      },
      { rootMargin: "-64px 0px -60% 0px" },
    );
    Object.keys(byId).forEach(function (id) {
      var heading = document.getElementById(id);
      if (heading) observer.observe(heading);
    });
  }

  // Mermaid diagrams: loaded only on pages that have one. Without network access the source stays visible.
  if (body.dataset.mermaid) {
    import(body.dataset.mermaid)
      .then(function (module) {
        var mermaid = module.default;
        mermaid.initialize({
          startOnLoad: false,
          securityLevel: "strict",
          theme: currentTheme() === "dark" ? "dark" : "neutral",
        });
        return mermaid.run({ querySelector: "pre.mermaid" });
      })
      .catch(function () {});
  }

  // Search over a prebuilt index (assets/search-index.js), loaded on first use.
  var input = document.getElementById("search");
  var results = document.getElementById("search-results");
  if (!input || !results) return;
  var index = null;
  var loading = null;
  var selected = -1;

  function loadIndex() {
    if (index) return Promise.resolve(index);
    if (loading) return loading;
    loading = new Promise(function (resolve, reject) {
      var script = document.createElement("script");
      script.src = base + "assets/search-index.js";
      script.addEventListener("load", function () {
        index = window.ARK_DOCS_INDEX || [];
        resolve(index);
      });
      script.addEventListener("error", reject);
      document.head.appendChild(script);
    });
    return loading;
  }

  function terms(query) {
    return query
      .toLowerCase()
      .split(/\s+/)
      .filter(function (term) {
        return term.length > 1 || /\d/.test(term);
      });
  }

  function score(entry, words) {
    var title = entry.title.toLowerCase();
    var page = entry.page.toLowerCase();
    var text = entry.text.toLowerCase();
    var total = 0;
    for (var i = 0; i < words.length; i += 1) {
      var word = words[i];
      var inTitle = title.indexOf(word) >= 0;
      var inPage = page.indexOf(word) >= 0;
      var inText = text.indexOf(word) >= 0;
      if (!inTitle && !inPage && !inText) return 0;
      total += (inTitle ? 10 : 0) + (inPage ? 4 : 0) + (inText ? 1 : 0);
    }
    if (title.indexOf(words.join(" ")) >= 0) total += 15;
    return total;
  }

  function appendHighlighted(parent, text, words) {
    var lower = text.toLowerCase();
    var position = 0;
    while (position < text.length) {
      var next = -1;
      var length = 0;
      for (var i = 0; i < words.length; i += 1) {
        var found = lower.indexOf(words[i], position);
        if (found >= 0 && (next < 0 || found < next)) {
          next = found;
          length = words[i].length;
        }
      }
      if (next < 0) {
        parent.appendChild(document.createTextNode(text.slice(position)));
        return;
      }
      parent.appendChild(document.createTextNode(text.slice(position, next)));
      var mark = document.createElement("mark");
      mark.textContent = text.slice(next, next + length);
      parent.appendChild(mark);
      position = next + length;
    }
  }

  function snippet(text, words) {
    var lower = text.toLowerCase();
    var at = -1;
    for (var i = 0; i < words.length && at < 0; i += 1) at = lower.indexOf(words[i]);
    var start = Math.max(0, at - 60);
    var piece = text.slice(start, start + 180);
    return (start > 0 ? "…" : "") + piece + (start + 180 < text.length ? "…" : "");
  }

  function render(query) {
    var words = terms(query);
    results.textContent = "";
    selected = -1;
    if (!words.length) {
      results.hidden = true;
      return;
    }
    var matches = index
      .map(function (entry) {
        return { entry: entry, score: score(entry, words) };
      })
      .filter(function (match) {
        return match.score > 0;
      })
      .toSorted(function (a, b) {
        return b.score - a.score;
      })
      .slice(0, 12);
    if (!matches.length) {
      var empty = document.createElement("div");
      empty.className = "empty";
      empty.textContent = "No results for “" + query + "”";
      results.appendChild(empty);
    }
    matches.forEach(function (match) {
      var entry = match.entry;
      var link = document.createElement("a");
      link.href = base + entry.url;
      link.setAttribute("role", "option");
      var title = document.createElement("span");
      title.className = "result-title";
      appendHighlighted(title, entry.title, words);
      var path = document.createElement("span");
      path.className = "result-path";
      path.textContent = entry.section + " › " + entry.page;
      var text = document.createElement("span");
      text.className = "result-text";
      appendHighlighted(text, snippet(entry.text, words), words);
      link.appendChild(title);
      link.appendChild(path);
      link.appendChild(text);
      results.appendChild(link);
    });
    results.hidden = false;
  }

  function move(step) {
    var links = results.querySelectorAll("a");
    if (!links.length) return;
    selected = (selected + step + links.length) % links.length;
    links.forEach(function (link, i) {
      link.setAttribute("aria-selected", String(i === selected));
    });
    links[selected].scrollIntoView({ block: "nearest" });
  }

  input.addEventListener("focus", function () {
    loadIndex().catch(function () {});
  });
  input.addEventListener("input", function () {
    var query = input.value.trim();
    loadIndex().then(function () {
      if (input.value.trim() === query) render(query);
    });
  });
  input.addEventListener("keydown", function (event) {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      move(1);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      move(-1);
    } else if (event.key === "Enter") {
      var links = results.querySelectorAll("a");
      var target = links[selected >= 0 ? selected : 0];
      if (target) window.location.href = target.href;
    } else if (event.key === "Escape") {
      results.hidden = true;
      input.blur();
    }
  });
  document.addEventListener("click", function (event) {
    if (!event.target.closest(".search")) results.hidden = true;
  });
  document.addEventListener("keydown", function (event) {
    var typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
    if (event.key === "/" && !typing) {
      event.preventDefault();
      input.focus();
    }
  });
})();
