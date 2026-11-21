// Tooltip + garis silang untuk grafik garis (halaman Ringkasan). Tanpa pustaka; posisi diatur lewat CSSOM
// (diizinkan CSP, berbeda dengan atribut style di HTML). Tanpa JavaScript, <title> tiap jam tetap tampil.
document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll("[data-grafik]").forEach(function (wadah) {
    var svg = wadah.querySelector("svg"), tip = wadah.querySelector("[data-tip-kotak]");
    var silang = wadah.querySelector("[data-silang]"), sorot = wadah.querySelector("[data-sorot]");
    var lebarVB = svg.viewBox.baseVal.width;

    function tampil(r) {
      var x = parseFloat(r.dataset.x), y = parseFloat(r.dataset.y), skala = svg.clientWidth / lebarVB;
      var bagian = r.dataset.tip.split("|");
      silang.setAttribute("x1", x); silang.setAttribute("x2", x);
      sorot.setAttribute("cx", x); sorot.setAttribute("cy", y);
      tip.textContent = "";
      var b = document.createElement("b"); b.textContent = bagian[1] || ""; tip.appendChild(b);
      tip.appendChild(document.createTextNode(bagian[0]));
      tip.hidden = false;
      var kiri = x * skala, min = tip.offsetWidth / 2 + 4, maks = svg.clientWidth - tip.offsetWidth / 2 - 4;
      tip.style.left = Math.max(min, Math.min(maks, kiri)) + "px";
      tip.style.top = (y * skala) + "px";
      wadah.classList.add("sorot");
    }
    function sembunyi() { tip.hidden = true; wadah.classList.remove("sorot"); }

    wadah.querySelectorAll(".g-sasaran").forEach(function (r) {
      var t = r.querySelector("title"); if (t) t.remove();            // tooltip sendiri menggantikan tooltip bawaan
      r.addEventListener("mouseenter", function () { tampil(r); });
    });
    svg.addEventListener("mouseleave", sembunyi);
  });
});
