package dev.portline.mobile

import android.content.Context
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URL
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.Executors
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import java.security.cert.X509Certificate

class LocalApiServer(
    private val context: Context,
    private val appVersion: String,
    private val onRequestConnectVpn: (String) -> Unit,
    private val onRequestDisconnectVpn: () -> Unit,
    private val onRequestQuit: () -> Unit
) {
    private val token: String = ByteArray(24).let {
        SecureRandom().nextBytes(it)
        it.joinToString("") { b -> "%02x".format(b) }
    }
    private val executor = Executors.newCachedThreadPool()
    private var serverSocket: ServerSocket? = null
    @Volatile private var running = false

    private val lock = Any()
    private var state = "idle"
    private var phase = "Ожидание"
    private var progress = 0
    private val logs = mutableListOf<String>()
    private var link = ""
    private var errorText = ""
    private var protocol = "portline"
    private var host = ""
    private var started = ""
    private var portConflict = false
    private var needsFreshProfile = false
    private var busy = false
    private var portBusy = false
    private var gatewayBusy = false
    private var portKey = ""

    private var savedNativeEncoded: String? = null
    private var savedNativeProfile: PortlineProfile? = null

    private var gatewayAction = ""
    private var gatewayError = ""
    private var gatewayInfo = JSONObject()

    private var portTask = JSONObject().apply {
        put("state", "")
        put("message", "")
        put("protocol", "")
        put("port", 0)
        put("service", "")
        put("process", "")
        put("pid", 0)
        put("canStop", false)
        put("suggestions", JSONArray())
    }

    init {
        restoreSavedNativeProfile()
    }

    private fun restoreSavedNativeProfile() {
        try {
            val raw = ProfileVault.load(context)
            if (raw != null) {
                val p = PortlineProfile.decode(raw)
                savedNativeEncoded = raw
                savedNativeProfile = p
                state = "success"
                phase = "Сохранённый профиль"
                progress = 100
                protocol = "portline"
                host = p.host
            }
        } catch (_: Exception) {
        }
    }

    fun start(): Int {
        val ss = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        serverSocket = ss
        running = true
        Thread({
            while (running) {
                try {
                    val client = ss.accept()
                    executor.execute { handleClient(client) }
                } catch (_: Exception) {
                    if (!running) break
                }
            }
        }, "PortlineLocalApi").apply { isDaemon = true; start() }
        return ss.localPort
    }

    fun stop() {
        running = false
        try { serverSocket?.close() } catch (_: Exception) {}
        executor.shutdownNow()
    }

    private fun handleClient(socket: Socket) {
        socket.use { sock ->
            sock.soTimeout = 15_000
            val inp = BufferedInputStream(sock.getInputStream())
            val out = BufferedOutputStream(sock.getOutputStream())
            val headerBytes = readHeaders(inp) ?: return
            val headerText = headerBytes.toString(StandardCharsets.ISO_8859_1)
            val lines = headerText.split("\r\n")
            if (lines.isEmpty()) return
            val reqParts = lines[0].split(" ")
            if (reqParts.size < 2) return
            val method = reqParts[0]
            val fullTarget = reqParts[1]
            val qIdx = fullTarget.indexOf('?')
            val path = if (qIdx >= 0) fullTarget.substring(0, qIdx) else fullTarget
            val query = if (qIdx >= 0) fullTarget.substring(qIdx + 1) else ""

            val headers = mutableMapOf<String, String>()
            for (i in 1 until lines.size) {
                val idx = lines[i].indexOf(':')
                if (idx > 0) {
                    headers[lines[i].substring(0, idx).trim().lowercase()] = lines[i].substring(idx + 1).trim()
                }
            }

            val hostHdr = headers["host"] ?: ""
            val hostOnly = hostHdr.substringBefore(':')
            if (hostOnly != "127.0.0.1" && hostOnly != "localhost") {
                sendResponse(out, 403, "text/plain; charset=utf-8", "Invalid host".toByteArray())
                return
            }

            val contentLen = headers["content-length"]?.toIntOrNull()?.coerceIn(0, 128 * 1024) ?: 0
            val bodyBytes = if (contentLen > 0) readExact(inp, contentLen) else ByteArray(0)

            when (path) {
                "/" -> {
                    val html = readAsset("ui/index.html")
                        .toString(StandardCharsets.UTF_8)
                        .replace("%%TOKEN%%", token)
                        .replace("%%VERSION%%", appVersion)
                    sendResponse(out, 200, "text/html; charset=utf-8", html.toByteArray(StandardCharsets.UTF_8))
                }
                "/style.css" -> sendResponse(out, 200, "text/css; charset=utf-8", readAsset("ui/style.css"))
                "/app.js" -> sendResponse(out, 200, "text/javascript; charset=utf-8", readAsset("ui/app.js"))
                else -> {
                    if (!path.startsWith("/api/")) {
                        sendResponse(out, 404, "text/plain; charset=utf-8", "Not found".toByteArray())
                        return
                    }
                    val auth = headers["authorization"] ?: ""
                    if (!auth.equals("Bearer $token", ignoreCase = true)) {
                        sendResponse(out, 401, "text/plain; charset=utf-8", "Unauthorized".toByteArray())
                        return
                    }
                    handleApi(out, method, path, query, bodyBytes)
                }
            }
        }
    }

    private fun handleApi(out: BufferedOutputStream, method: String, path: String, query: String, body: ByteArray) {
        val bodyStr = body.toString(StandardCharsets.UTF_8)
        when (path) {
            "/api/status" -> {
                if (method != "GET") return sendJson(out, 405, JSONObject().put("error", "Method not allowed"))
                sendJson(out, 200, buildStatusJson())
            }
            "/api/install" -> {
                if (method != "POST") return sendJson(out, 405, JSONObject().put("error", "Method not allowed"))
                val req = try { JSONObject(bodyStr) } catch (_: Exception) {
                    return sendJson(out, 400, JSONObject().put("error", "Некорректный запрос"))
                }
                val err = validateRequest(req)
                if (err != null) return sendJson(out, 400, JSONObject().put("error", err))
                synchronized(lock) {
                    if (busy || portBusy || gatewayBusy) {
                        return sendJson(out, 409, JSONObject().put("error", "Установка уже выполняется."))
                    }
                    busy = true
                    state = "running"
                    phase = "Соединение с сервером"
                    progress = 5
                    logs.clear()
                    link = ""
                    errorText = ""
                    portConflict = false
                    protocol = req.optString("protocol", "portline")
                    host = req.optString("host")
                }
                executor.execute { runInstall(req) }
                sendJson(out, 202, JSONObject().put("started", true))
            }
            "/api/ports/check", "/api/ports/stop" -> {
                if (method != "POST") return sendJson(out, 405, JSONObject().put("error", "Method not allowed"))
                val req = try { JSONObject(bodyStr) } catch (_: Exception) {
                    return sendJson(out, 400, JSONObject().put("error", "Некорректный запрос"))
                }
                val err = validateRequest(req)
                if (err != null) return sendJson(out, 400, JSONObject().put("error", err))
                val action = if (path == "/api/ports/stop") "stop" else "check"
                val svc = req.optString("service")
                val id = "${req.optString("host")}:${req.optInt("sshPort", 22)}/${req.optString("protocol")}:${req.optInt("port")}"
                synchronized(lock) {
                    if (busy || portBusy || gatewayBusy) {
                        return sendJson(out, 409, JSONObject().put("error", "Дождись завершения текущей операции на VPS."))
                    }
                    if (action == "stop" && (portKey != id || portTask.optString("state") != "busy" || !portTask.optBoolean("canStop") || portTask.optString("service") != svc || svc.isBlank())) {
                        return sendJson(out, 409, JSONObject().put("error", "Сначала проверь этот порт и убедись, что служба не изменилась."))
                    }
                    portBusy = true
                    portKey = id
                    portTask = JSONObject().apply {
                        put("state", "running")
                        put("protocol", if (req.optString("protocol") == "hy2") "udp" else "tcp")
                        put("port", req.optInt("port"))
                        put("message", if (action == "stop") "Останавливаем выбранную службу…" else "Подключаемся к VPS и проверяем порт…")
                        put("suggestions", JSONArray())
                    }
                }
                executor.execute { runPortTask(req, action, svc) }
                sendJson(out, 202, JSONObject().put("started", true))
            }
            "/api/gateway/inspect", "/api/gateway/use", "/api/gateway/update" -> {
                if (method != "POST") return sendJson(out, 405, JSONObject().put("error", "Method not allowed"))
                val req = try { JSONObject(bodyStr) } catch (_: Exception) {
                    return sendJson(out, 400, JSONObject().put("error", "Некорректный запрос"))
                }
                val action = path.removePrefix("/api/gateway/")
                if (action == "update" && !req.optBoolean("confirmUpdate")) {
                    return sendJson(out, 400, JSONObject().put("error", "Обновление требует отдельного подтверждения."))
                }
                val err = validateRequest(req)
                if (err != null) return sendJson(out, 400, JSONObject().put("error", err))
                synchronized(lock) {
                    if (busy || portBusy || gatewayBusy) {
                        return sendJson(out, 409, JSONObject().put("error", "Заверши текущую операцию с Gateway."))
                    }
                    gatewayBusy = true
                    gatewayAction = "running"
                    gatewayError = ""
                    if (action == "inspect") gatewayInfo = JSONObject()
                }
                executor.execute { runGatewayAction(req, action) }
                sendJson(out, 202, JSONObject().put("started", true))
            }
            "/api/tunnel/profile/export" -> {
                if (method != "POST") return sendJson(out, 405, JSONObject().put("error", "Method not allowed"))
                val encoded = synchronized(lock) { savedNativeEncoded } ?: ProfileVault.load(context)
                if (encoded.isNullOrBlank()) return sendJson(out, 409, JSONObject().put("error", "Missing tunnel profile"))
                sendJson(out, 200, JSONObject().put("profile", encoded))
            }
            "/api/tunnel/profile/import" -> {
                if (method != "POST") return sendJson(out, 405, JSONObject().put("error", "Method not allowed"))
                val raw = bodyStr.trim()
                val p = try { PortlineProfile.decode(raw) } catch (_: Exception) {
                    return sendJson(out, 400, JSONObject().put("error", "Некорректный файл профиля Portline."))
                }
                ProfileVault.save(context, raw)
                synchronized(lock) {
                    savedNativeEncoded = raw
                    savedNativeProfile = p
                    host = p.host
                    protocol = "portline"
                    state = "success"
                    phase = "Профиль импортирован"
                    progress = 100
                    needsFreshProfile = false
                }
                sendJson(out, 200, JSONObject().put("imported", true))
            }
            "/api/tunnel/connect" -> {
                if (method != "POST") return sendJson(out, 405, JSONObject().put("error", "Method not allowed"))
                val raw = synchronized(lock) { savedNativeEncoded } ?: ProfileVault.load(context)
                if (raw.isNullOrBlank()) {
                    return sendJson(out, 409, JSONObject().put("error", "Сначала установи Portline Tunnel на VPS или импортируй профиль."))
                }
                onRequestConnectVpn(raw)
                sendJson(out, 202, JSONObject().put("started", true))
            }
            "/api/tunnel/disconnect" -> {
                if (method != "POST") return sendJson(out, 405, JSONObject().put("error", "Method not allowed"))
                onRequestDisconnectVpn()
                sendJson(out, 202, JSONObject().put("started", true))
            }
            "/api/tunnel/diagnose" -> {
                if (method != "POST") return sendJson(out, 405, JSONObject().put("error", "Method not allowed"))
                val snap = PortlineVpnService.snapshot()
                if (snap.state == "connected") {
                    val res = JSONObject()
                        .put("state", if (snap.sentPackets > 0 && snap.receivedPackets > 0) "ok" else "pending")
                        .put("stage", "traffic")
                        .put("endpoint", snap.endpoint)
                        .put("message", "Пакеты IPv4 с начала подключения: отправлено ${snap.sentPackets}, получено ${snap.receivedPackets}.")
                        .put("advice", "Открой сайт и повтори проверку, чтобы увидеть изменение счётчиков.")
                    return sendJson(out, 200, res)
                }
                val p = synchronized(lock) { savedNativeProfile }
                    ?: return sendJson(out, 409, JSONObject().put("error", "Сначала импортируй или установи профиль."))
                sendJson(out, 200, probePortline(p))
            }
            "/api/profiles" -> handleProfiles(out, method, query, bodyStr)
            "/api/profiles/load" -> {
                val id = queryParam(query, "id")
                val found = loadSavedServers().firstOrNull { it.optString("id") == id }
                    ?: return sendJson(out, 404, JSONObject().put("error", "Профиль не найден"))
                val copy = JSONObject(found.toString())
                if (copy.optBoolean("hasPassword")) {
                    val pw = try { ProfileVault.loadSecret(context, "srv_pw_$id") } catch (_: Exception) { null }
                    if (!pw.isNullOrEmpty()) copy.put("password", pw)
                }
                sendJson(out, 200, JSONObject().put("profile", copy))
            }
            "/api/update" -> sendJson(out, 200, checkGitHubUpdate())
            "/api/quit" -> {
                sendJson(out, 200, JSONObject().put("ok", true))
                executor.execute {
                    Thread.sleep(150)
                    onRequestQuit()
                }
            }
            else -> sendJson(out, 404, JSONObject().put("error", "Not found"))
        }
    }

    private fun handleProfiles(out: BufferedOutputStream, method: String, query: String, bodyStr: String) {
        val storageDesc = "Пароли шифруются через Android Keystore (AES-256-GCM)."
        when (method) {
            "GET" -> sendJson(out, 200, JSONObject().put("profiles", JSONArray(loadSavedServers())).put("passwordStorage", storageDesc))
            "POST" -> {
                val input = try { JSONObject(bodyStr) } catch (_: Exception) {
                    return sendJson(out, 400, JSONObject().put("error", "Некорректный запрос"))
                }
                val list = loadSavedServers().toMutableList()
                val id = input.optString("id").ifBlank { UUID.randomUUID().toString() }
                val savePw = input.optBoolean("savePassword") && input.optString("auth") == "password" && input.optString("password").isNotEmpty()
                if (savePw) {
                    ProfileVault.saveSecret(context, "srv_pw_$id", input.optString("password"))
                }
                val entry = JSONObject().apply {
                    put("id", id)
                    put("name", input.optString("name").ifBlank { input.optString("host") })
                    put("host", input.optString("host"))
                    put("sshPort", input.optInt("sshPort", 22))
                    put("username", input.optString("username", "root"))
                    put("auth", input.optString("auth", "password"))
                    put("keyFile", input.optString("keyFile"))
                    put("protocol", input.optString("protocol", "portline"))
                    put("port", input.optInt("port", 8443))
                    put("sni", input.optString("sni", "www.cloudflare.com"))
                    put("hasPassword", savePw)
                }
                val idx = list.indexOfFirst { it.optString("id") == id }
                if (idx >= 0) list[idx] = entry else list.add(0, entry)
                saveSavedServers(list)
                sendJson(out, 200, JSONObject().put("profile", entry).put("profiles", JSONArray(list)).put("passwordStorage", storageDesc))
            }
            "DELETE" -> {
                val id = queryParam(query, "id")
                val list = loadSavedServers().filterNot { it.optString("id") == id }
                saveSavedServers(list)
                sendJson(out, 200, JSONObject().put("profiles", JSONArray(list)).put("passwordStorage", storageDesc))
            }
            else -> sendJson(out, 405, JSONObject().put("error", "Method not allowed"))
        }
    }

    private fun loadSavedServers(): List<JSONObject> {
        return try {
            val raw = ProfileVault.loadSecret(context, "saved_servers") ?: return emptyList()
            val arr = JSONArray(raw)
            List(arr.length()) { arr.getJSONObject(it) }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun saveSavedServers(list: List<JSONObject>) {
        val arr = JSONArray()
        list.forEach { arr.put(it) }
        ProfileVault.saveSecret(context, "saved_servers", arr.toString())
    }

    private fun runInstall(req: JSONObject) {
        try {
            val proto = req.optString("protocol", "portline")
            val hostStr = req.optString("host")
            val portNum = req.optInt("port", 8443)
            val sni = req.optString("sni", "www.cloudflare.com")
            var profileSeen = false

            val scriptPath = when (proto) {
                "hy2" -> "scripts/hy2.sh"
                "vless" -> "scripts/vless.sh"
                else -> "scripts/portline.sh"
            }
            var scriptBody = readAsset(scriptPath).toString(StandardCharsets.UTF_8)
            var env = "export NP_ADDR=${shellQuote(hostStr)} NP_PORT=${shellQuote(portNum.toString())} NP_SNI=${shellQuote(sni)}\n"
            if (proto == "portline") {
                val binBytes = readAsset("bin/portline-gateway-linux-amd64")
                val sha = MessageDigest.getInstance("SHA-256").digest(binBytes).joinToString("") { "%02x".format(it) }
                val b64 = Base64.encodeToString(binBytes, Base64.NO_WRAP).chunked(76).joinToString("\n")
                env = "export NP_ADDR=${shellQuote(hostStr)} NP_PORT=${shellQuote(portNum.toString())} NP_BIN_SHA=${shellQuote(sha)}\n"
                scriptBody = scriptBody.replace("__BINARY_BODY__", b64)
            }

            SshRunner.runScript(
                host = hostStr,
                port = req.optInt("sshPort", 22),
                username = req.optString("username", "root"),
                authType = req.optString("auth", "password"),
                password = req.optString("password"),
                keyContentOrPath = req.optString("keyFile"),
                script = env + scriptBody
            ) { line ->
                if (handleOutputLine(line)) profileSeen = true
            }

            synchronized(lock) {
                if (proto == "portline" && !profileSeen && savedNativeEncoded == null) {
                    state = "error"
                    errorText = "Portline gateway не вернул профиль подключения. Проверь журнал установки."
                } else {
                    state = "success"
                    phase = "Сервер готов"
                    progress = 100
                    needsFreshProfile = false
                    logs.add("Установка завершена.")
                }
            }
        } catch (e: Exception) {
            synchronized(lock) {
                state = "error"
                phase = "Ошибка установки"
                errorText = e.message ?: "Ошибка SSH"
            }
        } finally {
            synchronized(lock) { busy = false }
        }
    }

    private fun runPortTask(req: JSONObject, action: String, expectedService: String) {
        try {
            val proto = if (req.optString("protocol") == "hy2") "udp" else "tcp"
            val env = "export NP_PORT=${shellQuote(req.optInt("port").toString())} NP_CTL_PROTO=${shellQuote(proto)} NP_CTL_ACTION=${shellQuote(action)} NP_EXPECT_UNIT=${shellQuote(expectedService)} NP_SSH_PORT=${shellQuote(req.optInt("sshPort", 22).toString())}\n"
            val script = readAsset("scripts/portctl.sh").toString(StandardCharsets.UTF_8)
            SshRunner.runScript(
                host = req.optString("host"),
                port = req.optInt("sshPort", 22),
                username = req.optString("username", "root"),
                authType = req.optString("auth", "password"),
                password = req.optString("password"),
                keyContentOrPath = req.optString("keyFile"),
                script = env + script
            ) { line -> handleOutputLine(line) }
        } catch (e: Exception) {
            synchronized(lock) {
                portTask.put("state", "error")
                portTask.put("message", e.message ?: "Ошибка проверки порта")
            }
        } finally {
            synchronized(lock) { portBusy = false }
        }
    }

    private fun runGatewayAction(req: JSONObject, action: String) {
        try {
            val hostStr = req.optString("host")
            val portNum = req.optInt("port", 8443)
            var env = "export NP_GW_ACTION=${shellQuote(action)} NP_ADDR=${shellQuote(hostStr)} NP_PORT=${shellQuote(portNum.toString())}\n"
            var script = readAsset("scripts/gateway.sh").toString(StandardCharsets.UTF_8)
            if (action == "update") {
                val binBytes = readAsset("bin/portline-gateway-linux-amd64")
                val sha = MessageDigest.getInstance("SHA-256").digest(binBytes).joinToString("") { "%02x".format(it) }
                val b64 = Base64.encodeToString(binBytes, Base64.NO_WRAP).chunked(76).joinToString("\n")
                env += "export NP_BIN_SHA=${shellQuote(sha)}\n"
                script = script.replace("__BINARY_BODY__", b64)
            } else {
                script = script.replace("__BINARY_BODY__", "")
            }
            SshRunner.runScript(
                host = hostStr,
                port = req.optInt("sshPort", 22),
                username = req.optString("username", "root"),
                authType = req.optString("auth", "password"),
                password = req.optString("password"),
                keyContentOrPath = req.optString("keyFile"),
                script = env + script
            ) { line -> handleOutputLine(line) }
            synchronized(lock) { gatewayAction = "success" }
        } catch (e: Exception) {
            synchronized(lock) {
                gatewayAction = "error"
                gatewayError = e.message ?: "Ошибка Gateway"
            }
        } finally {
            synchronized(lock) { gatewayBusy = false }
        }
    }

    private fun handleOutputLine(line: String): Boolean {
        if (line.startsWith("PORTLINE_TUNNEL_PROFILE=")) {
            val raw = line.removePrefix("PORTLINE_TUNNEL_PROFILE=").trim()
            val p = PortlineProfile.decode(raw)
            ProfileVault.save(context, raw)
            synchronized(lock) {
                savedNativeEncoded = raw
                savedNativeProfile = p
                host = p.host
                protocol = "portline"
                needsFreshProfile = false
            }
            return true
        }
        if (line.startsWith("PORTLINE_GATEWAY|")) {
            val parts = line.split("|")
            synchronized(lock) {
                if (parts.size == 7) {
                    if (parts[1] == "missing") {
                        gatewayInfo = JSONObject().put("state", "missing").put("message", "Portline Gateway не найден.")
                    } else {
                        gatewayInfo = JSONObject()
                            .put("state", parts[1])
                            .put("activity", parts[2])
                            .put("port", parts[3])
                            .put("version", parts[4])
                            .put("configVersion", parts[5])
                            .put("host", parts[6])
                            .put("compatible", parts[5] == "1")
                            .put("needsUpdate", parts[5] == "1" && parts[4] != "1.4.0")
                            .put("message", if (parts[2] == "active") "Gateway установлен и активен." else "Gateway найден, но служба остановлена.")
                    }
                }
            }
            return false
        }
        if (line.startsWith("::phase|")) {
            val parts = line.removePrefix("::phase|").split("|", limit = 2)
            if (parts.size == 2) {
                synchronized(lock) {
                    progress = parts[0].toIntOrNull()?.coerceIn(0, 100) ?: progress
                    phase = parts[1]
                }
            }
            return false
        }
        if (line.startsWith("PORTLINE_PORT|")) {
            val parts = line.removePrefix("PORTLINE_PORT|").split("|")
            if (parts.size == 7) {
                synchronized(lock) {
                    val st = parts[0]
                    val pr = parts[1]
                    val pt = parts[2].toIntOrNull() ?: 0
                    val unit = if (parts[3] == "-") "" else parts[3]
                    val proc = if (parts[4] == "-") "" else parts[4]
                    val pid = parts[5].toIntOrNull() ?: 0
                    portTask.put("state", st)
                    portTask.put("protocol", pr)
                    portTask.put("port", pt)
                    portTask.put("service", unit)
                    portTask.put("process", proc)
                    portTask.put("pid", pid)
                    portTask.put("canStop", st == "busy" && parts[6] == "1" && unit.endsWith(".service"))
                    portTask.put("message", when (st) {
                        "free" -> "${pr.uppercase()} $pt свободен на сервере."
                        "busy" -> "${pr.uppercase()} $pt занят службой $proc."
                        else -> "Служба $unit остановлена. ${pr.uppercase()} $pt освобождён."
                    })
                }
            }
            return false
        }
        if (line.startsWith("PORTLINE_SUGGEST|")) {
            val arr = JSONArray()
            line.removePrefix("PORTLINE_SUGGEST|").split(",").mapNotNull { it.toIntOrNull() }.take(3).forEach { arr.put(it) }
            synchronized(lock) { portTask.put("suggestions", arr) }
            return false
        }
        if (line.startsWith("PORTLINE_LINK=")) {
            synchronized(lock) { link = line.removePrefix("PORTLINE_LINK=") }
            return false
        }
        synchronized(lock) {
            if (line.contains(" уже занят") && (line.startsWith("TCP ") || line.startsWith("UDP "))) {
                portConflict = true
            }
            logs.add(line.take(400))
            if (logs.size > 90) logs.removeAt(0)
        }
        return false
    }

    private fun probePortline(profile: PortlineProfile): JSONObject {
        val out = JSONObject().put("state", "error").put("stage", "tcp").put("endpoint", "${profile.host}:${profile.port}")
        return try {
            val sock = Socket()
            sock.connect(java.net.InetSocketAddress(profile.host, profile.port), 4000)
            sock.soTimeout = 5000
            out.put("stage", "tls")
            val trust = object : X509TrustManager {
                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
                override fun checkClientTrusted(c: Array<out X509Certificate>?, a: String?) = Unit
                override fun checkServerTrusted(c: Array<out X509Certificate>?, a: String?) = Unit
            }
            val ctx = SSLContext.getInstance("TLSv1.3").apply { init(null, arrayOf<TrustManager>(trust), SecureRandom()) }
            val ssl = ctx.socketFactory.createSocket(sock, profile.host, profile.port, true) as SSLSocket
            ssl.use { s ->
                val params = s.sslParameters
                params.protocols = arrayOf("TLSv1.3")
                if (android.os.Build.VERSION.SDK_INT >= 29) {
                    params.applicationProtocols = arrayOf("portline-ipv4-lease/1")
                }
                s.sslParameters = params
                s.startHandshake()
                val leaf = s.session.peerCertificates[0] as X509Certificate
                val actual = MessageDigest.getInstance("SHA-256").digest(leaf.publicKey.encoded)
                if (!MessageDigest.isEqual(actual, profile.pin)) {
                    return out.put("stage", "identity").put("message", "Ключ сервера не совпал с профилем.")
                }
                out.put("stage", "auth")
                s.outputStream.write(profile.token)
                s.outputStream.flush()
                if (s.inputStream.read() != 1) {
                    return out.put("message", "Gateway не подтвердил токен доступа.")
                }
            }
            out.put("state", "ok").put("stage", "ready").put("message", "TCP, TLS 1.3, ключ сервера и токен проверены.").put("advice", "Можно подключать VPN.")
        } catch (e: Exception) {
            out.put("message", e.message ?: "Ошибка соединения").put("advice", "Проверь порт и состояние portline-gateway на VPS.")
        }
    }

    private fun checkGitHubUpdate(): JSONObject {
        val res = JSONObject().put("currentVersion", appVersion)
        return try {
            val conn = (URL("https://api.github.com/repos/WeilBrainn/Portline/releases/latest").openConnection() as HttpURLConnection).apply {
                connectTimeout = 6000
                readTimeout = 6000
                setRequestProperty("Accept", "application/vnd.github+json")
                setRequestProperty("User-Agent", "Portline-Android/$appVersion")
            }
            if (conn.responseCode == 200) {
                val json = JSONObject(conn.inputStream.bufferedReader().use { it.readText() })
                val latest = json.optString("tag_name").removePrefix("v")
                val url = json.optString("html_url", "https://github.com/WeilBrainn/Portline/releases")
                res.put("latestVersion", latest).put("hasUpdate", isNewer(appVersion, latest)).put("releaseUrl", url)
            } else {
                res.put("latestVersion", appVersion).put("hasUpdate", false)
            }
        } catch (_: Exception) {
            res.put("error", "Не удалось связаться с GitHub.")
        }
    }

    private fun isNewer(current: String, latest: String): Boolean {
        if (latest.isBlank()) return false
        val c = current.substringBefore('-').split('.').map { it.toIntOrNull() ?: 0 }
        val l = latest.substringBefore('-').split('.').map { it.toIntOrNull() ?: 0 }
        for (i in 0 until 3) {
            val cv = c.getOrElse(i) { 0 }
            val lv = l.getOrElse(i) { 0 }
            if (lv != cv) return lv > cv
        }
        return current.contains('-') && !latest.contains('-')
    }

    private fun buildStatusJson(): JSONObject {
        val snap = PortlineVpnService.snapshot()
        val tunnelJson = JSONObject().apply {
            put("state", snap.state)
            put("phase", snap.phase)
            put("message", snap.message)
            put("sentPackets", snap.sentPackets)
            put("receivedPackets", snap.receivedPackets)
            put("latencyMs", snap.latencyMs)
            put("guardMode", "wfp")
            if (snap.connectedAtMs > 0L) {
                put("connectedAt", java.time.Instant.ofEpochMilli(snap.connectedAtMs).toString())
            }
        }
        return synchronized(lock) {
            JSONObject().apply {
                put("state", state)
                put("phase", phase)
                put("progress", progress)
                put("logs", JSONArray(logs))
                put("link", link)
                put("error", errorText)
                put("protocol", protocol)
                put("host", host)
                put("started", started)
                put("portConflict", portConflict)
                put("needsFreshProfile", needsFreshProfile)
                put("hasNativeProfile", savedNativeProfile != null)
                put("nativeProfileHost", savedNativeProfile?.host ?: "")
                put("nativeProfilePort", savedNativeProfile?.port ?: 0)
                put("gatewayAction", gatewayAction)
                put("gatewayError", gatewayError)
                put("gateway", gatewayInfo)
                put("portTask", portTask)
                put("tunnel", tunnelJson)
                put("happ", JSONObject().put("state", "idle"))
            }
        }
    }

    private fun validateRequest(req: JSONObject): String? {
        val h = req.optString("host").trim()
        if (h.isEmpty() || h.length > 253 || h.contains("..")) return "Укажи корректный IPv4 или домен VPS."
        val sshPort = req.optInt("sshPort", 22)
        val port = req.optInt("port", 8443)
        if (sshPort !in 1..65535 || port !in 1..65535) return "Порт должен быть от 1 до 65535."
        val user = req.optString("username", "root")
        if (!user.matches(Regex("[a-z_][a-z0-9_-]{0,31}"))) return "Некорректное SSH-имя пользователя."
        val auth = req.optString("auth", "password")
        if (auth == "password" && req.optString("password").isEmpty()) return "Введи SSH-пароль сервера."
        if (auth == "key" && req.optString("keyFile").isBlank()) return "Укажи SSH-ключ."
        return null
    }

    private fun shellQuote(s: String) = "'" + s.replace("'", "'\\''") + "'"

    private fun queryParam(query: String, key: String): String {
        for (pair in query.split("&")) {
            val idx = pair.indexOf('=')
            if (idx > 0 && pair.substring(0, idx) == key) {
                return java.net.URLDecoder.decode(pair.substring(idx + 1), "UTF-8")
            }
        }
        return ""
    }

    private fun readAsset(path: String): ByteArray = context.assets.open(path).use { it.readBytes() }

    private fun readHeaders(inp: InputStream): ByteArray? {
        val buf = ByteArrayOutputStream()
        var prev3 = 0; var prev2 = 0; var prev1 = 0
        while (buf.size() < 32768) {
            val b = inp.read()
            if (b < 0) return null
            buf.write(b)
            if (prev3 == '\r'.code && prev2 == '\n'.code && prev1 == '\r'.code && b == '\n'.code) {
                return buf.toByteArray()
            }
            prev3 = prev2; prev2 = prev1; prev1 = b
        }
        return null
    }

    private fun readExact(inp: InputStream, len: Int): ByteArray {
        val out = ByteArray(len)
        var off = 0
        while (off < len) {
            val n = inp.read(out, off, len - off)
            if (n < 0) break
            off += n
        }
        return out
    }

    private fun sendJson(out: BufferedOutputStream, status: Int, obj: JSONObject) {
        sendResponse(out, status, "application/json; charset=utf-8", obj.toString().toByteArray(StandardCharsets.UTF_8))
    }

    private fun sendResponse(out: BufferedOutputStream, status: Int, contentType: String, body: ByteArray) {
        val reason = when (status) {
            200 -> "OK"
            202 -> "Accepted"
            400 -> "Bad Request"
            401 -> "Unauthorized"
            403 -> "Forbidden"
            404 -> "Not Found"
            405 -> "Method Not Allowed"
            409 -> "Conflict"
            else -> "Error"
        }
        val hdr = "HTTP/1.1 $status $reason\r\nContent-Type: $contentType\r\nContent-Length: ${body.size}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
        out.write(hdr.toByteArray(StandardCharsets.ISO_8859_1))
        out.write(body)
        out.flush()
    }
}
