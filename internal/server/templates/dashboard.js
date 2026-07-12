// Dashboard behaviors: clipboard copy, destructive-action confirm,
// live uptime tick, section-nav highlight. Served separately because the
// dashboard CSP disallows inline scripts. Everything uses event delegation
// so htmx swaps need no rebinding.
(function () {
  "use strict";

  document.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-copy]");
    if (!btn) {
      return;
    }
    var done = function () {
      btn.classList.add("copied");
      setTimeout(function () { btn.classList.remove("copied"); }, 1200);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(btn.getAttribute("data-copy")).then(done, done);
    } else {
      done();
    }
  });

  // Forms marked data-confirm get an inline yes/cancel step before
  // submitting. Without JS they submit directly.
  document.addEventListener("submit", function (e) {
    var form = e.target;
    if (!(form instanceof HTMLFormElement) || !form.hasAttribute("data-confirm")) {
      return;
    }
    e.preventDefault();
    if (form.querySelector(".confirm")) {
      return;
    }
    var trigger = form.querySelector("button[type=submit], button:not([type])");
    if (trigger) {
      trigger.hidden = true;
    }
    var wrap = document.createElement("span");
    wrap.className = "confirm";
    var label = document.createElement("span");
    label.textContent = form.getAttribute("data-confirm") || "sure?";
    var yes = document.createElement("button");
    yes.type = "button";
    yes.className = "cbtn";
    yes.textContent = "yes";
    yes.addEventListener("click", function () {
      form.submit();
    });
    var no = document.createElement("button");
    no.type = "button";
    no.className = "xbtn";
    no.textContent = "cancel";
    no.addEventListener("click", function () {
      wrap.remove();
      if (trigger) {
        trigger.hidden = false;
      }
    });
    wrap.append(label, yes, no);
    form.appendChild(wrap);
  });

  // Skip the tunnel-list poll while a disconnect confirm is open so the
  // swap doesn't wipe it out from under the user.
  document.body.addEventListener("htmx:beforeRequest", function (e) {
    if (e.detail.elt.id === "tunnel-list" && document.querySelector("#tunnel-list .confirm")) {
      e.preventDefault();
    }
  });

  // Elements with data-connected="<unix seconds>" tick as h:mm:ss.
  function pad(n) {
    return String(n).padStart(2, "0");
  }
  function tick() {
    var now = Math.floor(Date.now() / 1000);
    document.querySelectorAll("[data-connected]").forEach(function (el) {
      var s = now - parseInt(el.getAttribute("data-connected"), 10);
      if (!isFinite(s) || s < 0) {
        return;
      }
      var h = Math.floor(s / 3600);
      var m = Math.floor((s % 3600) / 60);
      if (h >= 24) {
        el.textContent = Math.floor(h / 24) + "d " + (h % 24) + "h";
      } else {
        el.textContent = h + ":" + pad(m) + ":" + pad(s % 60);
      }
    });
  }
  tick();
  setInterval(tick, 1000);

  document.querySelectorAll(".sect-nav a").forEach(function (a) {
    a.addEventListener("click", function () {
      document.querySelectorAll(".sect-nav a").forEach(function (o) {
        o.classList.remove("on");
      });
      a.classList.add("on");
    });
  });
})();
