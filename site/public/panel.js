// sOMP relay panel: one authored interaction. Breakers drive lamps + readout.
// Reduced-motion: state still changes, lever snaps without transition (CSS).
(function () {
  var STATES = {
    strict: {
      lamps: { vm: "lit green", guard: "lit green", srt: "lit green" },
      text: "level strict · runtime firecracker\ndispatched work: GOVERNED\nplacement refused without KVM — fail closed",
    },
    standard: {
      lamps: { vm: "", guard: "lit", srt: "lit" },
      text: "level standard · runtime docker\nno microVM boundary — dev only, stated plainly\ndispatch: GOVERNED (worker-side boundary)",
    },
    off: {
      lamps: { vm: "lit red", guard: "", srt: "" },
      text: "level OFF · no sandboxing\ndispatch + session up: REFUSED (fail-closed)\nsomp level strict|standard to re-engage",
    },
  };

  function setLevel(btn) {
    var level = btn.getAttribute("data-level");
    var panel = btn.closest(".panel");
    var breakers = panel.querySelectorAll(".breaker");
    var readout = panel.querySelector(".readout");
    breakers.forEach(function (b) {
      var on = b === btn;
      b.classList.toggle("on", on);
      b.setAttribute("aria-checked", on ? "true" : "false");
    });
    var st = STATES[level];
    Object.keys(st.lamps).forEach(function (k) {
      var lamp = panel.querySelector('[data-lamp="' + k + '"]');
      if (lamp) lamp.className = "lamp " + st.lamps[k];
    });
    // Typewriter readout unless reduced-motion prefers the full text at once.
    var full = st.text;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      readout.textContent = full;
      return;
    }
    readout.textContent = "";
    var i = 0;
    (function tick() {
      i += 3;
      readout.textContent = full.slice(0, i);
      if (i < full.length) requestAnimationFrame(tick);
      else readout.textContent = full;
    })();
  }

  document.querySelectorAll(".panel .breaker").forEach(function (btn) {
    btn.addEventListener("click", function () { setLevel(btn); });
  });
  // Init lamp state for the default engaged breaker.
  document.querySelectorAll(".panel").forEach(function (panel) {
    var on = panel.querySelector(".breaker.on") || panel.querySelector(".breaker");
    if (on) {
      var st = STATES[on.getAttribute("data-level")];
      Object.keys(st.lamps).forEach(function (k) {
        var lamp = panel.querySelector('[data-lamp="' + k + '"]');
        if (lamp) lamp.className = "lamp " + st.lamps[k];
      });
    }
  });

  // Copy buttons (both cmdboxes).
  function copyFor(btn) {
    var box = btn.closest(".cmdbox");
    var code = box ? box.querySelector("code") : null;
    if (!code) return;
    var done = function () {
      btn.textContent = "copied ✓";
      setTimeout(function () { btn.textContent = "copy"; }, 1600);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(code.textContent).then(done, done);
    } else {
      var ta = document.createElement("textarea");
      ta.value = code.textContent;
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy"); } catch (e) {}
      document.body.removeChild(ta);
      done();
    }
  }
  document.querySelectorAll(".cmdbox button").forEach(function (btn) {
    btn.addEventListener("click", function () { copyFor(btn); });
  });
})();
