/* Pemilih provider & model AI dinamis tanpa inline script (patuh CSP default-src 'self'). */
(function () {
  function isiModel(box) {
    var raw = box.getAttribute("data-ai-profil");
    if (!raw) return;
    var profil;
    try { profil = JSON.parse(raw); } catch (e) { return; }
    var selProf = box.querySelector('select[name="profil_id"]');
    var selMod = box.querySelector('select[name="model_pilih"]');
    var inpKustom = box.querySelector('input[name="model_kustom"]');
    var wrapKustom = box.querySelector('[data-ai-kustom-bungkus]') || inpKustom;
    if (!selMod || !profil.length) return;

    function toggleKustom(fokus) {
      if (!inpKustom) return;
      var kustom = selMod.value === "__kustom__";
      if (wrapKustom) wrapKustom.hidden = !kustom;
      inpKustom.hidden = !kustom;
      if (kustom && fokus) inpKustom.focus();
      else if (!kustom) inpKustom.value = "";
    }

    function segarkanSelect() {
      var pid = selProf ? selProf.value : profil[0].id;
      var target = profil.find(function (x) { return x.id === pid; }) || profil[0];
      var daftar = Array.isArray(target.models) && target.models.length ? target.models : [target.model];
      var pilihanLama = selMod.getAttribute("data-model-awal") || target.model;
      selMod.innerHTML = "";
      daftar.forEach(function (m) {
        var opt = document.createElement("option");
        opt.value = m;
        opt.textContent = m;
        if (m === pilihanLama) opt.selected = true;
        selMod.appendChild(opt);
      });
      var optLain = document.createElement("option");
      optLain.value = "__kustom__";
      optLain.textContent = "Ketik ID model lain...";
      selMod.appendChild(optLain);
      toggleKustom(false);
      selMod.removeAttribute("data-model-awal");
    }

    if (selProf) {
      selProf.addEventListener("change", segarkanSelect);
    }
    if (inpKustom) {
      selMod.addEventListener("change", function () { toggleKustom(true); });
    }
    segarkanSelect();
  }

  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("[data-ai-pemilih]").forEach(isiModel);
    document.querySelectorAll("[data-ai-contoh]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var card = btn.closest(".ai-chat-card") || btn.closest("form") || document;
        var ta = card.querySelector('textarea[name="pertanyaan"]');
        if (ta) {
          ta.value = btn.getAttribute("data-ai-contoh") || "";
          ta.focus();
        }
      });
    });
  });
})();
