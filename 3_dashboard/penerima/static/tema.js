// Tema terang/gelap + menu samping. Dipasang di <head> agar tema diterapkan sebelum halaman tampil (tanpa kedipan).
(function () {
  var KUNCI_TEMA = "nids-tema", KUNCI_SISI = "nids-sisi";
  var akar = document.documentElement;
  function baca(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function simpan(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* penyimpanan diblokir: abaikan */ } }

  var gelapSistem = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  akar.setAttribute("data-theme", baca(KUNCI_TEMA) || (gelapSistem ? "dark" : "light"));
  if (baca(KUNCI_SISI) === "ciut") akar.setAttribute("data-sisi", "ciut");

  function layarKecil() { return window.matchMedia("(max-width: 860px)").matches; }

  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("[data-ganti-tema]").forEach(function (b) {
      b.addEventListener("click", function () {
        var baru = akar.getAttribute("data-theme") === "dark" ? "light" : "dark";
        akar.setAttribute("data-theme", baru);
        simpan(KUNCI_TEMA, baru);
      });
    });
    // Tombol menu: di layar lebar menciutkan menu menjadi ikon saja; di ponsel membuka/menutup menu.
    document.querySelectorAll("[data-ganti-sisi]").forEach(function (b) {
      b.addEventListener("click", function (ev) {
        ev.stopPropagation();
        var s = akar.getAttribute("data-sisi");
        if (layarKecil()) {
          akar.setAttribute("data-sisi", s === "buka" ? "" : "buka");
        } else {
          var baru = s === "ciut" ? "" : "ciut";
          akar.setAttribute("data-sisi", baru);
          simpan(KUNCI_SISI, baru);
        }
      });
    });
    document.addEventListener("click", function (ev) {
      if (akar.getAttribute("data-sisi") === "buka" && !ev.target.closest(".sisi")) akar.setAttribute("data-sisi", "");
    });
  });
})();
