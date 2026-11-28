# -*- coding: utf-8 -*-
"""
Asisten Analisis Multi-AI Dinamis (on-demand) untuk Dashboard ASUNA dan Bot Telegram.

* Admin cukup memasukkan kredensial / API Key per provider (OpenAI, Gemini, Anthropic Claude, atau
  OpenAI-Compatible seperti Groq/OpenRouter/DeepSeek/Ollama); daftar model diambil otomatis
  secara dinamis dari endpoint `/models` provider tersebut (dengan daftar bawaan sebagai fallback).
* Saat melakukan chat atau analisis, admin/analis bebas memilih Koneksi API maupun Model ID apa saja
  dari daftar model dinamis maupun mengetik ID model lain secara langsung.
* Mendukung percakapan multi-turn dengan konteks log deteksi terkini.
* HANYA mengirim ringkasan metadata statistik (tanpa payload paket, tanpa kredensial) dan HANYA
  dipanggil on-demand, sehingga tidak mempengaruhi deteksi maupun latensi notifikasi.

Hanya memakai pustaka standar Python.
"""
import contextlib
import hashlib
import ipaddress
import json
import os
import re
import ssl
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None

from .dugaan import dugaan
from .umpan_balik import ambang_model, kedekatan

PATH_BAWAAN = "/var/lib/nids-bersama/ai_konfig.json"

PROVIDER_OPSI = [
    ("openai", "OpenAI", "https://api.openai.com/v1/chat/completions", "gpt-4o-mini", True),
    ("openai_compat", "OpenAI-Compatible (Groq / OpenRouter / DeepSeek / Ollama)", "", "llama-3.3-70b-versatile", False),
    ("gemini", "Google Gemini", "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent", "gemini-2.5-flash", True),
    ("anthropic", "Anthropic Claude", "https://api.anthropic.com/v1/messages", "claude-3-5-haiku-latest", True),
]
PROVIDER_PETA = {k: {"label": lab, "url_bawaan": u, "model_bawaan": m, "wajib_kunci": w}
                 for k, lab, u, m, w in PROVIDER_OPSI}
PROVIDER_VALID = tuple(PROVIDER_PETA.keys())

MODEL_BAWAAN_DAFTAR = {
    "openai": ["gpt-4o-mini", "gpt-4o", "gpt-4.1-mini", "gpt-4.1", "o4-mini", "o3-mini"],
    "gemini": ["gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash"],
    "anthropic": ["claude-sonnet-4-20250514", "claude-3-7-sonnet-latest", "claude-3-5-haiku-latest"],
    "openai_compat": ["llama-3.3-70b-versatile", "deepseek-chat", "qwen-2.5-72b-instruct"],
}

_CACHE = {}           # kunci -> (ts_monotonic, hasil_dict)
CACHE_TTL_DETIK = 300
BATAS_WAKTU_HTTP = 25
_NAMA_MODEL_RE = re.compile(r"^[A-Za-z0-9._:/+-]{2,120}$")
_OPENAI_CHAT_AWALAN = ("gpt-", "o1", "o3", "o4", "chatgpt-")
_OPENAI_ABAIKAN = ("-audio", "-realtime", "-tts", "-transcribe", "whisper", "dall-e",
                   "embedding", "moderation", "-image", "sora", "babbage", "davinci", "instruct")

PROMPT_SISTEM = (
    "Anda adalah asisten analis keamanan jaringan (SOC Analyst) untuk sistem ASUNA NIDS yang menggunakan "
    "model unsupervised Isolation Forest Dual-IF (IF-Flow 68 fitur aliran + IF-Agg 7 fitur agregasi jendela 300 detik). "
    "Deteksi anomali sepenuhnya dilakukan oleh Isolation Forest lokal; tugas Anda adalah membantu administrator "
    "menafsirkan metrik dan log statistik secara objektif, ringkas, dan dapat ditindaklanjuti dalam Bahasa Indonesia "
    "profesional. Jangan mengarang fakta di luar data yang diberikan."
)


def sekarang_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def samarkan_kunci(kunci):
    k = (kunci or "").strip()
    if not k:
        return "(tanpa kunci)"
    if len(k) <= 8:
        return "••••" + k[-2:]
    return "%s••••%s" % (k[:4], k[-4:])


def _host_lokal(host):
    return (host or "").lower() in ("127.0.0.1", "localhost", "::1")


def validasi_url(url, provider):
    u = (url or "").strip()
    if not u:
        u = PROVIDER_PETA[provider]["url_bawaan"]
    if not u:
        raise ValueError("Endpoint / Base URL wajib diisi untuk provider %s." % PROVIDER_PETA[provider]["label"])
    p = urllib.parse.urlsplit(u)
    if p.scheme not in ("https", "http"):
        raise ValueError("URL API harus menggunakan https:// (atau http:// khusus localhost).")
    if p.scheme == "http" and not _host_lokal(p.hostname):
        raise ValueError("Endpoint eksternal wajib menggunakan HTTPS.")
    if not p.hostname:
        raise ValueError("Hostname endpoint API tidak valid.")
    try:
        ip = ipaddress.ip_address(p.hostname)
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            raise ValueError("Alamat endpoint tidak diizinkan.")
    except ValueError as ex:
        if "tidak diizinkan" in str(ex):
            raise
    return u


@contextlib.contextmanager
def _kunci(path):
    if fcntl is None:
        yield
        return
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    lock_path = os.path.join(folder, ".ai_konfig.lock")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o660)
    try:
        try:
            os.fchmod(fd, 0o660)
        except OSError:
            pass
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _kosong():
    return {"aktif": None, "profil": []}


def _normalisasi_profil(p):
    p = dict(p)
    prov = p["provider"]
    models = [m for m in (p.get("models") or []) if isinstance(m, str) and _NAMA_MODEL_RE.match(m)]
    if p.get("model") and p["model"] not in models:
        models.insert(0, p["model"])
    if not models:
        models = list(MODEL_BAWAAN_DAFTAR.get(prov, [PROVIDER_PETA[prov]["model_bawaan"]]))
    p["models"] = list(dict.fromkeys(models))
    if not p.get("model"):
        p["model"] = p["models"][0]
    return p


def _baca_tanpa_kunci(path):
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
    except (FileNotFoundError, ValueError, OSError):
        return _kosong()
    if not isinstance(d, dict):
        return _kosong()
    out = _kosong()
    out["aktif"] = d.get("aktif")
    out["profil"] = [_normalisasi_profil(p) for p in (d.get("profil") or [])
                     if isinstance(p, dict) and p.get("id") and p.get("provider") in PROVIDER_PETA]
    return out


def _simpan_tanpa_kunci(path, data):
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    fd, sementara = tempfile.mkstemp(prefix=".aikonf-", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=1, ensure_ascii=False)
        try:
            os.chmod(sementara, 0o660)
        except OSError:
            pass
        os.replace(sementara, path)
    except BaseException:
        if os.path.exists(sementara):
            os.unlink(sementara)
        raise


def _profil_env():
    key = (os.environ.get("OPENAI_API_KEY") or "").strip()
    if not key:
        return None
    model = (os.environ.get("OPENAI_MODEL") or "gpt-4o-mini").strip()
    url = (os.environ.get("OPENAI_BASE_URL") or PROVIDER_PETA["openai"]["url_bawaan"]).strip()
    return _normalisasi_profil({
        "id": "env-openai",
        "nama": "OpenAI (Env Server)",
        "provider": "openai",
        "model": model,
        "models": MODEL_BAWAAN_DAFTAR["openai"],
        "base_url": url,
        "api_key": key,
        "dari_env": True,
        "dibuat_utc": None,
        "oleh": "env",
    })


def baca(path=PATH_BAWAAN):
    with _kunci(path):
        data = _baca_tanpa_kunci(path)
    if not data["profil"]:
        env_p = _profil_env()
        if env_p:
            data["profil"] = [env_p]
            data["aktif"] = env_p["id"]
    elif data["aktif"] and not any(p["id"] == data["aktif"] for p in data["profil"]):
        data["aktif"] = data["profil"][0]["id"]
    elif not data["aktif"] and data["profil"]:
        data["aktif"] = data["profil"][0]["id"]
    return data


def daftar_aman(path=PATH_BAWAAN):
    """Daftar koneksi AI untuk tampilan UI/Telegram: API key selalu disamarkan."""
    data = baca(path)
    hasil = []
    for p in data["profil"]:
        item = {k: v for k, v in p.items() if k != "api_key"}
        item["kunci_samar"] = samarkan_kunci(p.get("api_key"))
        item["provider_label"] = PROVIDER_PETA[p["provider"]]["label"]
        item["aktif"] = (p["id"] == data.get("aktif"))
        hasil.append(item)
    return {"aktif": data.get("aktif"), "profil": hasil}


def cari_profil(data, kunci_atau_nama=None):
    profil = data.get("profil") or []
    if not profil:
        return None
    if not kunci_atau_nama:
        for p in profil:
            if p["id"] == data.get("aktif"):
                return p
        return profil[0]
    q = str(kunci_atau_nama).strip().lower()
    for p in profil:
        if p["id"].lower() == q or p.get("nama", "").lower() == q:
            return p
    for p in profil:
        if q in p.get("nama", "").lower() or q in p.get("model", "").lower():
            return p
    return None


# ------------------------------------------------------------------ HTTP helper & penemuan model dinamis
def _http_req(url, payload=None, headers=None, method=None, batas_waktu=BATAS_WAKTU_HTTP):
    met = method or ("POST" if payload is not None else "GET")
    hdrs = dict(headers or {})
    data = None
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, method=met, headers=hdrs)
    ctx = ssl.create_default_context() if url.startswith("https://") else None
    try:
        with urllib.request.urlopen(req, timeout=batas_waktu, context=ctx) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", errors="replace")[:260]
        except Exception:
            pass
        raise RuntimeError("HTTP %d dari API AI: %s" % (e.code, detail or e.reason))
    except Exception as e:
        raise RuntimeError("Gagal menghubungi API AI: %s" % e)
    try:
        return json.loads(raw)
    except ValueError:
        raise RuntimeError("Respons API AI bukan JSON yang valid.")


def _http_json(url, payload, headers, batas_waktu=BATAS_WAKTU_HTTP):
    """Kompatibilitas pemanggilan lama POST-only untuk transport mock pada unit test."""
    return _http_req(url, payload=payload, headers=headers, method="POST", batas_waktu=batas_waktu)


def _panggil_transport(transport, url, payload=None, headers=None, method="GET"):
    """Panggil transport mock (bisa menerima 3 arg atau keyword method) maupun _http_req nyata."""
    if transport is _http_req or transport is _http_json:
        return _http_req(url, payload=payload, headers=headers, method=method)
    try:
        return transport(url, payload, headers or {}, method=method)
    except TypeError:
        return transport(url, payload, headers or {})


def _url_models_compat(base_url):
    u = base_url.rstrip("/")
    if u.endswith("/chat/completions"):
        return u[:-len("/chat/completions")] + "/models"
    if u.endswith("/completions"):
        return u[:-len("/completions")] + "/models"
    if u.endswith("/models"):
        return u
    return u + "/models"


def ambil_daftar_model(provider, api_key="", base_url="", transport=_http_req):
    """Ambil daftar model resmi langsung dari API provider (GET /models), dengan fallback kurasi."""
    url_base = validasi_url(base_url, provider)
    kunci = (api_key or "").strip()

    if provider == "openai":
        url = _url_models_compat(url_base) if base_url else "https://api.openai.com/v1/models"
        j = _panggil_transport(transport, url, None, {"Authorization": "Bearer %s" % kunci} if kunci else {}, method="GET")
        semua = [str(m.get("id", "")).strip() for m in (j.get("data") or []) if isinstance(m, dict)]
        cocok = [m for m in semua if _NAMA_MODEL_RE.match(m)
                 and m.startswith(_OPENAI_CHAT_AWALAN)
                 and not any(a in m for a in _OPENAI_ABAIKAN)]
        pilihan = sorted(set(cocok or semua), key=lambda x: (0 if "gpt-4o" in x else (1 if "gpt-4" in x or "gpt-5" in x else 2), x))
        return pilihan or list(MODEL_BAWAAN_DAFTAR["openai"])

    if provider == "openai_compat":
        url = _url_models_compat(url_base)
        j = _panggil_transport(transport, url, None, {"Authorization": "Bearer %s" % kunci} if kunci else {}, method="GET")
        semua = [str(m.get("id", "")).strip() for m in (j.get("data") or []) if isinstance(m, dict) and m.get("id")]
        return sorted(set(m for m in semua if _NAMA_MODEL_RE.match(m))) or list(MODEL_BAWAAN_DAFTAR["openai_compat"])

    if provider == "gemini":
        url = "https://generativelanguage.googleapis.com/v1beta/models"
        if kunci:
            url += "?key=" + urllib.parse.quote(kunci, safe="")
        j = _panggil_transport(transport, url, None, {}, method="GET")
        hasil = []
        for m in (j.get("models") or []):
            if not isinstance(m, dict):
                continue
            metode = m.get("supportedGenerationMethods") or []
            if metode and "generateContent" not in metode:
                continue
            nama_m = str(m.get("name") or "").replace("models/", "", 1).strip()
            if _NAMA_MODEL_RE.match(nama_m):
                hasil.append(nama_m)
        return list(dict.fromkeys(hasil)) or list(MODEL_BAWAAN_DAFTAR["gemini"])

    if provider == "anthropic":
        hdr = {"x-api-key": kunci, "anthropic-version": "2023-06-01"} if kunci else {"anthropic-version": "2023-06-01"}
        j = _panggil_transport(transport, "https://api.anthropic.com/v1/models", None, hdr, method="GET")
        hasil = [str(m.get("id", "")).strip() for m in (j.get("data") or []) if isinstance(m, dict) and m.get("id")]
        return list(dict.fromkeys(m for m in hasil if _NAMA_MODEL_RE.match(m))) or list(MODEL_BAWAAN_DAFTAR["anthropic"])

    return list(MODEL_BAWAAN_DAFTAR.get(provider, []))


def tambah_profil(path, nama, provider, model="", api_key="", base_url="", oleh="",
                  jadikan_aktif=False, transport=_http_req):
    nama = (nama or "").strip()[:60]
    if not nama:
        raise ValueError("Nama koneksi AI wajib diisi.")
    provider = (provider or "").strip().lower()
    if provider not in PROVIDER_PETA:
        raise ValueError("Provider AI tidak dikenal.")
    model = (model or "").strip()
    if model and not _NAMA_MODEL_RE.match(model):
        raise ValueError("Nama model bawaan tidak valid.")
    url = validasi_url(base_url, provider)
    kunci = (api_key or "").strip()
    if PROVIDER_PETA[provider]["wajib_kunci"] and not kunci:
        raise ValueError("API Key wajib diisi untuk %s." % PROVIDER_PETA[provider]["label"])
    if provider == "openai_compat" and not kunci and not _host_lokal(urllib.parse.urlsplit(url).hostname):
        raise ValueError("API Key wajib diisi untuk endpoint eksternal.")

    # Muat daftar model dari API secara dinamis (fallback aman bila offline)
    sync_ok = False
    try:
        daftar_model = ambil_daftar_model(provider, api_key=kunci, base_url=base_url, transport=transport)
        sync_ok = True
    except (RuntimeError, ValueError):
        daftar_model = list(MODEL_BAWAAN_DAFTAR.get(provider, [PROVIDER_PETA[provider]["model_bawaan"]]))

    model_def = model or (daftar_model[0] if daftar_model else PROVIDER_PETA[provider]["model_bawaan"])
    if model_def not in daftar_model:
        daftar_model = [model_def] + list(daftar_model)

    pid = "ai-%d" % int(time.time() * 1000)
    entri = _normalisasi_profil({
        "id": pid,
        "nama": nama,
        "provider": provider,
        "model": model_def,
        "models": daftar_model,
        "models_sync_ok": sync_ok,
        "models_sync_utc": sekarang_utc() if sync_ok else None,
        "base_url": url,
        "api_key": kunci,
        "dibuat_utc": sekarang_utc(),
        "oleh": oleh,
    })
    with _kunci(path):
        data = _baca_tanpa_kunci(path)
        if any(p.get("nama", "").lower() == nama.lower() for p in data["profil"]):
            raise ValueError("Nama koneksi AI “%s” sudah digunakan." % nama)
        while any(p["id"] == pid for p in data["profil"]):
            time.sleep(0.002)
            pid = "ai-%d" % int(time.time() * 1000)
            entri["id"] = pid
        data["profil"].append(entri)
        if jadikan_aktif or not data.get("aktif"):
            data["aktif"] = pid
        _simpan_tanpa_kunci(path, data)
    return {k: v for k, v in entri.items() if k != "api_key"}


def segarkan_model(path, pid, transport=_http_req):
    """Tarik ulang daftar model dinamis langsung dari endpoint API provider untuk koneksi `pid`."""
    data = baca(path)
    p = cari_profil(data, pid)
    if p is None or p.get("dari_env"):
        raise ValueError("Koneksi AI tidak ditemukan atau berasal dari variabel server.")
    daftar_model = ambil_daftar_model(p["provider"], api_key=p.get("api_key", ""),
                                      base_url=p.get("base_url", ""), transport=transport)
    with _kunci(path):
        d2 = _baca_tanpa_kunci(path)
        target = cari_profil(d2, p["id"])
        if target is None:
            raise ValueError("Koneksi AI tidak ditemukan.")
        target["models"] = list(dict.fromkeys(daftar_model))
        if target.get("model") and target["model"] not in target["models"]:
            target["models"].insert(0, target["model"])
        elif not target.get("model") and target["models"]:
            target["model"] = target["models"][0]
        target["models_sync_ok"] = True
        target["models_sync_utc"] = sekarang_utc()
        _simpan_tanpa_kunci(path, d2)
        return {k: v for k, v in target.items() if k != "api_key"}


def aktifkan_profil(path, pid, model_default=None):
    if model_default is not None:
        model_default = model_default.strip()
        if model_default and not _NAMA_MODEL_RE.match(model_default):
            raise ValueError("Nama model AI tidak valid.")
    with _kunci(path):
        data = _baca_tanpa_kunci(path)
        p = cari_profil(data, pid)
        if p is None:
            raise ValueError("Profil AI tidak ditemukan.")
        data["aktif"] = p["id"]
        if model_default:
            p["model"] = model_default
            if model_default not in p["models"]:
                p["models"].insert(0, model_default)
        _simpan_tanpa_kunci(path, data)
        return {k: v for k, v in p.items() if k != "api_key"}


def hapus_profil(path, pid):
    with _kunci(path):
        data = _baca_tanpa_kunci(path)
        ada = [p for p in data["profil"] if p["id"] == pid]
        if not ada:
            return None
        data["profil"] = [p for p in data["profil"] if p["id"] != pid]
        if data.get("aktif") == pid:
            data["aktif"] = data["profil"][0]["id"] if data["profil"] else None
        _simpan_tanpa_kunci(path, data)
        return {k: v for k, v in ada[0].items() if k != "api_key"}


# ------------------------------------------------------------------ pemanggilan HTTP API (multi-provider + multi-turn)
def _pakai_token_reasoning(model):
    m = (model or "").lower()
    return m.startswith(("o1", "o3", "o4", "gpt-5"))


def panggil_ai(profil, prompt_pengguna, prompt_sistem=PROMPT_SISTEM, maks_token=750,
               model_override=None, riwayat_chat=None, transport=_http_req):
    """Kirim permintaan ke koneksi AI (OpenAI / OpenAI-Compatible / Gemini / Anthropic) dengan
    pemilihan model dinamis (`model_override`) dan dukungan percakapan multi-turn."""
    prov = profil["provider"]
    model = (model_override or "").strip() or profil["model"]
    if not _NAMA_MODEL_RE.match(model):
        raise ValueError("Nama model AI tidak valid.")
    url = profil.get("base_url") or PROVIDER_PETA[prov]["url_bawaan"]
    kunci = profil.get("api_key") or ""

    pesan_hist = [m for m in (riwayat_chat or [])
                  if isinstance(m, dict) and m.get("role") in ("user", "assistant") and (m.get("content") or "").strip()]

    if prov in ("openai", "openai_compat"):
        if not url.rstrip("/").endswith("/chat/completions"):
            url = url.rstrip("/") + "/chat/completions"
        headers = {"Authorization": "Bearer %s" % kunci} if kunci else {}
        msgs = [{"role": "system", "content": prompt_sistem}]
        for h in pesan_hist[-10:]:
            msgs.append({"role": h["role"], "content": h["content"]})
        msgs.append({"role": "user", "content": prompt_pengguna})
        payload = {"model": model, "messages": msgs}
        if prov == "openai" and _pakai_token_reasoning(model):
            payload["max_completion_tokens"] = maks_token
        else:
            payload["temperature"] = 0.2
            payload["max_tokens"] = maks_token
        j = _panggil_transport(transport, url, payload, headers, method="POST")
        pilihan = (j.get("choices") or [{}])[0]
        teks = ((pilihan.get("message") or {}).get("content") or "").strip()
        if not teks:
            raise RuntimeError("API AI mengembalikan respons kosong.")
        return teks, model

    if prov == "gemini":
        url_f = url.replace("{model}", urllib.parse.quote(model, safe=""))
        sep = "&" if "?" in url_f else "?"
        url_full = "%s%skey=%s" % (url_f, sep, urllib.parse.quote(kunci, safe="")) if kunci else url_f
        contents = []
        for h in pesan_hist[-10:]:
            contents.append({"role": "model" if h["role"] == "assistant" else "user",
                             "parts": [{"text": h["content"]}]})
        contents.append({"role": "user", "parts": [{"text": prompt_pengguna}]})
        payload = {
            "system_instruction": {"parts": [{"text": prompt_sistem}]},
            "contents": contents,
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": maks_token},
        }
        j = _panggil_transport(transport, url_full, payload, {}, method="POST")
        kand = (j.get("candidates") or [{}])[0]
        bagian = ((kand.get("content") or {}).get("parts") or [])
        teks = "\n".join(str(b.get("text") or "") for b in bagian).strip()
        if not teks:
            raise RuntimeError("API Gemini mengembalikan respons kosong.")
        return teks, model

    if prov == "anthropic":
        headers = {"x-api-key": kunci, "anthropic-version": "2023-06-01"}
        msgs = [{"role": h["role"], "content": h["content"]} for h in pesan_hist[-10:]]
        msgs.append({"role": "user", "content": prompt_pengguna})
        payload = {
            "model": model,
            "max_tokens": maks_token,
            "temperature": 0.2,
            "system": prompt_sistem,
            "messages": msgs,
        }
        j = _panggil_transport(transport, url, payload, headers, method="POST")
        bagian = j.get("content") or []
        teks = "\n".join(str(b.get("text") or "") for b in bagian if b.get("type") == "text").strip()
        if not teks:
            raise RuntimeError("API Anthropic mengembalikan respons kosong.")
        return teks, model

    raise RuntimeError("Provider AI %s belum didukung." % prov)


def uji_profil(path, pid, model_override=None, transport=_http_req):
    data = baca(path)
    p = cari_profil(data, pid)
    if p is None:
        raise ValueError("Profil AI tidak ditemukan.")
    t0 = time.monotonic()
    balas, model_dipakai = panggil_ai(p, "Balas singkat dalam 1 kalimat: koneksi API ASUNA NIDS berhasil.",
                                      maks_token=40, model_override=model_override, transport=transport)
    dt = time.monotonic() - t0
    return {"ok": True, "profil": p["nama"], "model": model_dipakai,
            "latensi_detik": round(dt, 2), "balasan": balas[:160]}


# ------------------------------------------------------------------ pengumpul konteks log (tanpa payload!)
def kumpulkan_konteks_ip(db, ip, diblokir=None, tepercaya=None):
    r = db.execute("SELECT COUNT(*) AS aliran, SUM(oleh != '') AS ditandai, COUNT(DISTINCT dst_port) AS port, "
                   "MIN(waktu_selesai_us) AS awal, MAX(waktu_selesai_us) AS akhir FROM aliran WHERE src_ip = ?",
                   (ip,)).fetchone()
    if not r or not r["aliran"]:
        return None
    ports = [{"port": row["dst_port"], "aliran": row["n"], "ditandai": row["ditandai"] or 0}
             for row in db.execute("SELECT dst_port, COUNT(*) AS n, SUM(oleh != '') AS ditandai FROM aliran "
                                   "WHERE src_ip = ? GROUP BY dst_port ORDER BY n DESC LIMIT 8", (ip,))]
    am, skor_puncak = ambang_model(db), {}
    for mid, ma, mc in db.execute("SELECT model_id, MAX(skor_a), MAX(skor_c) FROM aliran WHERE src_ip = ? "
                                  "GROUP BY model_id", (ip,)):
        for s in kedekatan(am, mid, ma, mc):
            if s["model"] not in skor_puncak or s["persentil"] > skor_puncak[s["model"]]["persentil"]:
                skor_puncak[s["model"]] = {
                    "model": "IF-Flow" if s["model"] == "A" else "IF-Agg",
                    "skor": round(float(s["skor"]), 4),
                    "ambang": round(float(s["ambang"]), 4),
                    "persentil_latih": round(float(s["persentil"]) * 100, 2),
                }
    anom_rows = db.execute("SELECT dst_port, oleh, agg_ip_aliran, agg_ip_port_unik, agg_ip_rasio_gagal, "
                           "agg_ip_aliran_ssh, agg_s24_ip_unik FROM anomali WHERE src_ip = ? "
                           "ORDER BY waktu_selesai_us DESC LIMIT 10", (ip,)).fetchall()
    dug_hitung = {}
    maks_agg = {"aliran_5m": 0, "port_unik_5m": 0, "ssh_5m": 0, "rasio_gagal_maks": 0.0, "ip_subnet_5m": 0}
    for a in anom_rows:
        d = dugaan(dict(a))
        dug_hitung[d] = dug_hitung.get(d, 0) + 1
        maks_agg["aliran_5m"] = max(maks_agg["aliran_5m"], int(a["agg_ip_aliran"] or 0))
        maks_agg["port_unik_5m"] = max(maks_agg["port_unik_5m"], int(a["agg_ip_port_unik"] or 0))
        maks_agg["ssh_5m"] = max(maks_agg["ssh_5m"], int(a["agg_ip_aliran_ssh"] or 0))
        maks_agg["rasio_gagal_maks"] = max(maks_agg["rasio_gagal_maks"], round(float(a["agg_ip_rasio_gagal"] or 0.0), 2))
        maks_agg["ip_subnet_5m"] = max(maks_agg["ip_subnet_5m"], int(a["agg_s24_ip_unik"] or 0))

    durasi_jam = round(max(0, (r["akhir"] - r["awal"]) / 3.6e9), 2) if r["awal"] and r["akhir"] else 0.0
    return {
        "ip_sumber": ip,
        "total_aliran": int(r["aliran"]),
        "aliran_ditandai_anomali": int(r["ditandai"] or 0),
        "persen_anomali": round((r["ditandai"] or 0) / max(r["aliran"], 1) * 100, 2),
        "jumlah_port_tujuan_unik": int(r["port"] or 0),
        "rentang_aktivitas_jam": durasi_jam,
        "status_diblokir": bool(diblokir),
        "status_ip_tepercaya": bool(tepercaya),
        "port_terbanyak": ports,
        "skor_tertinggi": list(skor_puncak.values()),
        "dugaan_kategori_anomali": dug_hitung,
        "puncak_perilaku_5_menit": maks_agg,
    }


def kumpulkan_konteks_ringkasan(db, hari=1):
    st = {r["kunci"]: r["nilai"] for r in db.execute("SELECT kunci, nilai FROM status")}
    akhir = db.execute("SELECT MAX(waktu_selesai_us) FROM aliran").fetchone()[0]
    if not akhir:
        akhir = int(time.time() * 1_000_000)
    awal = akhir - int(hari) * 24 * 3600 * 1_000_000
    n = db.execute("SELECT COALESCE(SUM(aliran),0), COALESCE(SUM(anomali),0) FROM ringkasan WHERE menit_utc >= ?",
                   (awal // 1_000_000,)).fetchone()
    anom = db.execute("SELECT src_ip, oleh, agg_ip_aliran, agg_ip_port_unik, agg_ip_aliran_ssh FROM anomali "
                      "WHERE waktu_selesai_us >= ?", (awal,)).fetchall()
    per_kat, per_model = {}, {"IF-Flow": 0, "IF-Agg": 0, "Dual-IF": 0}
    petam = {"A": "IF-Flow", "C": "IF-Agg", "A+C": "Dual-IF"}
    for a in anom:
        d = dugaan(dict(a))
        per_kat[d] = per_kat.get(d, 0) + 1
        k = petam.get(a["oleh"])
        if k:
            per_model[k] += 1
    top_ip = [{"ip": row[0], "anomali": row[1], "port_unik": row[2], "model": row[3]}
              for row in db.execute(
                  "SELECT src_ip, COUNT(*) AS n, COUNT(DISTINCT dst_port), GROUP_CONCAT(DISTINCT oleh) "
                  "FROM anomali WHERE waktu_selesai_us >= ? GROUP BY src_ip ORDER BY n DESC LIMIT 6", (awal,))]
    return {
        "server": st.get("nama_server") or "VPS",
        "rentang_hari": int(hari),
        "model_versi": st.get("model_versi") or "-",
        "model_mode": st.get("model_mode") or "A+C",
        "total_aliran_diperiksa": int(n[0]),
        "total_anomali": int(n[1]),
        "persen_anomali": round(n[1] / max(n[0], 1) * 100, 2),
        "anomali_per_kategori": per_kat,
        "anomali_per_model": per_model,
        "ip_penyerang_teratas": top_ip,
    }


def _jalankan_tercache(path_konfig, jenis, konteks, prompt_user, profil_id=None, model_override=None,
                       paksa_baru=False, riwayat_chat=None, transport=_http_req):
    data = baca(path_konfig)
    profil = cari_profil(data, profil_id)
    if profil is None:
        raise ValueError("Belum ada koneksi AI. Tambahkan OpenAI atau provider lain di menu Asisten AI.")
    model_req = (model_override or "").strip() or profil["model"]
    kunci_hash = hashlib.sha256(json.dumps(konteks, sort_keys=True).encode("utf-8")).hexdigest()[:16]
    cache_key = (profil["id"], model_req, jenis, kunci_hash)
    kini = time.monotonic()
    if not paksa_baru and not riwayat_chat and cache_key in _CACHE:
        ts, cached = _CACHE[cache_key]
        if kini - ts <= CACHE_TTL_DETIK:
            return dict(cached, dari_cache=True)
    teks, model_dipakai = panggil_ai(profil, prompt_user, model_override=model_req,
                                     riwayat_chat=riwayat_chat, transport=transport)
    hasil = {
        "teks": teks,
        "profil_id": profil["id"],
        "profil_nama": profil["nama"],
        "provider": PROVIDER_PETA[profil["provider"]]["label"],
        "model": model_dipakai,
        "waktu_utc": sekarang_utc(),
        "dari_cache": False,
    }
    if not riwayat_chat:
        _CACHE[cache_key] = (kini, hasil)
    return hasil


def analisis_ip(path_konfig, db, ip, profil_id=None, model_override=None, diblokir=None, tepercaya=None,
                paksa_baru=False, transport=_http_req):
    konteks = kumpulkan_konteks_ip(db, ip, diblokir=diblokir, tepercaya=tepercaya)
    if konteks is None:
        raise ValueError("Alamat IP %s belum memiliki catatan aliran pada log deteksi." % ip)
    prompt = (
        "Analisis ringkasan log lalu lintas dari satu IP sumber berikut (hasil deteksi Isolation Forest Dual-IF):\n"
        + json.dumps(konteks, ensure_ascii=False, indent=1)
        + "\n\nBerikan jawaban ringkas dengan 3 bagian jelas:\n"
        "1. Indikasi Perilaku (pola serangan atau kemungkinan lalu lintas normal/false positive)\n"
        "2. Tingkat Risiko (Rendah / Sedang / Tinggi beserta alasan singkat dari skor & port)\n"
        "3. Rekomendasi Tindakan untuk Administrator (blokir sementara/permanen, pantau, jadikan IP tepercaya, atau lapor alarm palsu)."
    )
    return _jalankan_tercache(path_konfig, "ip:" + ip, konteks, prompt, profil_id=profil_id,
                              model_override=model_override, paksa_baru=paksa_baru, transport=transport)


def analisis_ringkasan(path_konfig, db, hari=1, profil_id=None, model_override=None,
                       paksa_baru=False, transport=_http_req):
    konteks = kumpulkan_konteks_ringkasan(db, hari=hari)
    prompt = (
        "Buat ringkasan eksekutif keamanan jaringan untuk administrator server berdasarkan statistik berikut:\n"
        + json.dumps(konteks, ensure_ascii=False, indent=1)
        + "\n\nSusun 3–4 poin padat:\n"
        "1. Kondisi Umum Lalu Lintas & Tren Anomali\n"
        "2. Ancaman / IP Sumber Paling Menonjol\n"
        "3. Prioritas Tindakan Administrator Berikutnya."
    )
    return _jalankan_tercache(path_konfig, "ringkas:%d" % int(hari), konteks, prompt, profil_id=profil_id,
                              model_override=model_override, paksa_baru=paksa_baru, transport=transport)


def chat_keamanan(path_konfig, db, pesan_baru, riwayat_chat=None, profil_id=None, model_override=None,
                  hari=1, transport=_http_req):
    pesan = (pesan_baru or "").strip()[:1000]
    if not pesan:
        raise ValueError("Pesan tidak boleh kosong.")
    konteks = kumpulkan_konteks_ringkasan(db, hari=hari) if db is not None else {"catatan": "log deteksi belum terhubung"}
    sistem = PROMPT_SISTEM + "\n\nRingkasan kondisi server ASUNA NIDS saat ini:\n" + json.dumps(konteks, ensure_ascii=False)
    data = baca(path_konfig)
    profil = cari_profil(data, profil_id)
    if profil is None:
        raise ValueError("Belum ada koneksi AI. Tambahkan OpenAI atau provider lain di panel Koneksi API AI.")
    model_req = (model_override or "").strip() or profil["model"]
    teks, model_dipakai = panggil_ai(profil, pesan, prompt_sistem=sistem, model_override=model_req,
                                     riwayat_chat=riwayat_chat, transport=transport)
    return {
        "teks": teks,
        "profil_id": profil["id"],
        "profil_nama": profil["nama"],
        "provider": PROVIDER_PETA[profil["provider"]]["label"],
        "model": model_dipakai,
        "waktu_utc": sekarang_utc(),
        "dari_cache": False,
    }


def tanya_keamanan(path_konfig, db, pertanyaan, profil_id=None, model_override=None, hari=1, transport=_http_req):
    return chat_keamanan(path_konfig, db, pertanyaan, riwayat_chat=None, profil_id=profil_id,
                         model_override=model_override, hari=hari, transport=transport)
