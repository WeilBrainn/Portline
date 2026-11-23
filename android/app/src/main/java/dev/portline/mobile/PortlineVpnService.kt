package dev.portline.mobile

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

data class TunnelSnapshot(
    val state: String = "idle",
    val phase: String = "Готов к подключению",
    val message: String = "Полный туннель IPv4 · DNS 1.1.1.1 / 9.9.9.9 · защита от IPv6",
    val endpoint: String = "",
    val clientIp: String = "",
    val sentPackets: Long = 0,
    val receivedPackets: Long = 0,
    val latencyMs: Long = -1,
    val connectedAtMs: Long = 0
)

class PortlineVpnService : VpnService() {
    companion object {
        const val CONNECT = "dev.portline.mobile.CONNECT"
        const val DISCONNECT = "dev.portline.mobile.DISCONNECT"
        const val PROFILE = "profile"
        private const val CHANNEL = "portline_tunnel"
        private const val NOTIFY_ID = 63
        private const val ECHO_ID = 0x504C

        @Volatile
        private var currentSnapshot = TunnelSnapshot()
        private val sentCounter = AtomicLong(0)
        private val recvCounter = AtomicLong(0)
        private val latencyValue = AtomicLong(-1)
        private val logLock = Any()
        private val tunnelLogs = ArrayDeque<String>(200)
        private val timeFmt = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US)

        fun log(msg: String) {
            val line = "[${synchronized(timeFmt) { timeFmt.format(java.util.Date()) }}] $msg"
            synchronized(logLock) {
                if (tunnelLogs.size >= 200) tunnelLogs.removeFirst()
                tunnelLogs.addLast(line)
            }
        }

        fun logs(): List<String> = synchronized(logLock) { tunnelLogs.toList() }

        fun clearLogs() = synchronized(logLock) { tunnelLogs.clear() }

        fun snapshot(): TunnelSnapshot = currentSnapshot.copy(
            sentPackets = sentCounter.get(),
            receivedPackets = recvCounter.get(),
            latencyMs = latencyValue.get()
        )
    }

    private val active = AtomicBoolean(false)
    private val userStopped = AtomicBoolean(false)
    @Volatile private var vpn: ParcelFileDescriptor? = null
    @Volatile private var tcp: Socket? = null
    @Volatile private var tls: SSLSocket? = null
    @Volatile private var runner: Thread? = null

    override fun onCreate() {
        super.onCreate()
        val channel = NotificationChannel(CHANNEL, "Portline VPN", NotificationManager.IMPORTANCE_LOW)
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            DISCONNECT -> {
                userStopped.set(true)
                currentSnapshot = currentSnapshot.copy(
                    state = "disconnecting",
                    phase = "Отключение…",
                    message = "Закрываем туннель и восстанавливаем сеть"
                )
                stopTunnel()
                currentSnapshot = TunnelSnapshot(
                    state = "disconnected",
                    phase = "Отключено",
                    message = "VPN отключён"
                )
                stopSelf()
                return START_NOT_STICKY
            }
            CONNECT -> {
                if (active.get()) return START_NOT_STICKY
                val encoded = intent.getStringExtra(PROFILE) ?: return START_NOT_STICKY
                val profile = try {
                    PortlineProfile.decode(encoded)
                } catch (e: Exception) {
                    currentSnapshot = TunnelSnapshot(
                        state = "error",
                        phase = "Ошибка профиля",
                        message = e.message ?: "Некорректный профиль"
                    )
                    return START_NOT_STICKY
                }
                userStopped.set(false)
                sentCounter.set(0)
                recvCounter.set(0)
                latencyValue.set(-1)
                currentSnapshot = TunnelSnapshot(
                    state = "connecting",
                    phase = "Подключение к ${profile.host}:${profile.port}…",
                    message = "Устанавливаем защищённый канал TLS 1.3",
                    endpoint = "${profile.host}:${profile.port}"
                )
                val notification = buildNotification("Подключение к ${profile.host}:${profile.port}…")
                if (Build.VERSION.SDK_INT >= 34) {
                    startForeground(NOTIFY_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
                } else {
                    startForeground(NOTIFY_ID, notification)
                }
                active.set(true)
                runner = Thread({ runWithReconnect(profile) }, "PortlineVpn").also { it.start() }
                return START_NOT_STICKY
            }
        }
        return START_NOT_STICKY
    }

    private fun buildNotification(text: String): Notification {
        val openPending = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val stopIntent = Intent(this, PortlineVpnService::class.java).apply { action = DISCONNECT }
        val stopPending = PendingIntent.getService(
            this, 1, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("Portline VPN")
            .setContentText(text)
            .setContentIntent(openPending)
            .addAction(Notification.Action.Builder(null, "Отключить", stopPending).build())
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        try {
            getSystemService(NotificationManager::class.java).notify(NOTIFY_ID, buildNotification(text))
        } catch (_: Exception) {
        }
    }

    private fun runWithReconnect(profile: PortlineProfile) {
        val backoffs = longArrayOf(1000L, 2000L, 4000L)
        var lastError: String? = null
        var wasEstablished = false
        try {
            log("Запуск подключения к ${profile.host}:${profile.port}")
            for (attempt in 0..backoffs.size) {
                if (userStopped.get()) break
                if (attempt > 0) {
                    if (!wasEstablished) break
                    log("Переподключение (попытка $attempt/${backoffs.size})…")
                    currentSnapshot = currentSnapshot.copy(
                        state = "connecting",
                        phase = "Переподключение ($attempt/${backoffs.size})…",
                        message = "Связь прервалась. Восстанавливаем туннель…"
                    )
                    updateNotification("Переподключение ($attempt/${backoffs.size})…")
                    try {
                        Thread.sleep(backoffs[attempt - 1])
                    } catch (_: InterruptedException) {
                        break
                    }
                    if (userStopped.get()) break
                    active.set(true)
                }
                try {
                    val established = runTunnel(profile)
                    if (established) wasEstablished = true
                    lastError = null
                    if (userStopped.get()) break
                } catch (e: Exception) {
                    lastError = e.message ?: e.javaClass.simpleName
                    log("Ошибка: $lastError")
                } finally {
                    stopTunnel()
                }
                if (userStopped.get() || !wasEstablished) break
            }
        } finally {
            stopTunnel()
            if (userStopped.get()) {
                log("Туннель остановлен пользователем.")
                currentSnapshot = TunnelSnapshot(
                    state = "disconnected",
                    phase = "Отключено",
                    message = "VPN отключён"
                )
            } else if (lastError != null) {
                currentSnapshot = TunnelSnapshot(
                    state = "error",
                    phase = "Ошибка подключения",
                    message = lastError,
                    endpoint = "${profile.host}:${profile.port}"
                )
            }
            stopSelf()
        }
    }

    /**
     * Opens TCP + TLS 1.3 to the gateway. compat=false uses the system
     * (Conscrypt/BoringSSL) engine; compat=true uses BouncyCastle JSSE, which
     * supports Ed25519 server certificates issued by older Portline Gateways.
     * Returns the socket and negotiated ALPN protocol (or "").
     */
    private fun openTls(profile: PortlineProfile, compat: Boolean): Pair<SSLSocket, String> {
        val upstream = Socket()
        tcp = upstream
        log("1/5 Привязка сокета и защита от петли (protect)…")
        upstream.bind(InetSocketAddress(0))
        check(protect(upstream)) { "Не удалось исключить служебный сокет VPN из туннеля" }
        log("2/5 TCP подключение к ${profile.host}:${profile.port}…")
        upstream.connect(InetSocketAddress(profile.host, profile.port), 15000)
        upstream.soTimeout = 20000
        upstream.tcpNoDelay = true

        val trust = object : X509TrustManager {
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
        }
        val lease = "portline-ipv4-lease/1"
        if (!compat) {
            val context = SSLContext.getInstance("TLSv1.3")
            context.init(null, arrayOf<TrustManager>(trust), SecureRandom())
            val secure = context.socketFactory.createSocket(upstream, profile.host, profile.port, true) as SSLSocket
            tls = secure
            val params = secure.sslParameters
            params.protocols = arrayOf("TLSv1.3")
            if (Build.VERSION.SDK_INT >= 29) params.applicationProtocols = arrayOf(lease)
            secure.sslParameters = params
            log("3/5 TLS 1.3 рукопожатие…")
            secure.startHandshake()
            val alpn = if (Build.VERSION.SDK_INT >= 29) (secure.applicationProtocol ?: "") else ""
            return secure to alpn
        }
        val crypto = org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider()
            .setProvider(org.bouncycastle.jce.provider.BouncyCastleProvider())
        val jsse = org.bouncycastle.jsse.provider.BouncyCastleJsseProvider(false, crypto)
        val context = SSLContext.getInstance("TLS", jsse)
        context.init(null, arrayOf<TrustManager>(trust), SecureRandom())
        val secure = context.socketFactory.createSocket(upstream, profile.host, profile.port, true) as SSLSocket
        tls = secure
        val bc = secure as org.bouncycastle.jsse.BCSSLSocket
        val bp = bc.parameters
        bp.protocols = arrayOf("TLSv1.3")
        bp.applicationProtocols = arrayOf(lease)
        bc.parameters = bp
        log("3/5 TLS 1.3 рукопожатие (совместимый режим)…")
        secure.startHandshake()
        log("Совместимый режим TLS активен. Рекомендуем обновить Gateway на VPS до ECDSA-сертификата.")
        return secure to (bc.applicationProtocol ?: "")
    }

    /** SHA-256 pin input: DER SubjectPublicKeyInfo of the leaf, provider-independent. */
    private fun spkiOf(secure: SSLSocket): ByteArray {
        val der = secure.session.peerCertificates[0].encoded
        return org.bouncycastle.asn1.x509.Certificate.getInstance(der).subjectPublicKeyInfo.encoded
    }

    private fun runTunnel(profile: PortlineProfile): Boolean {
        var established = false
        check(prepare(this) == null) { "Нет разрешения Android на VPN — нажми «Подключить VPN»" }
        val (secure, alpn) = try {
            openTls(profile, compat = false)
        } catch (e: javax.net.ssl.SSLException) {
            if (userStopped.get()) throw e
            log("Системный TLS отклонён (${e.javaClass.simpleName}). Пробуем совместимый TLS-движок (Ed25519)…")
            try { tls?.close() } catch (_: Exception) {}
            try { tcp?.close() } catch (_: Exception) {}
            try {
                openTls(profile, compat = true)
            } catch (e2: Exception) {
                throw IllegalStateException(
                    "Сервер ${profile.host}:${profile.port} отклонил TLS 1.3-рукопожатие. Проверь, что на этом порту работает Portline Gateway. (${e2.message ?: e.message})",
                    e2
                )
            }
        }

        val actual = MessageDigest.getInstance("SHA-256").digest(spkiOf(secure))
        check(MessageDigest.isEqual(actual, profile.pin)) { "TLS-ключ сервера не совпал с профилем" }
        log("4/5 Авторизация токена…")

        val netIn = DataInputStream(secure.inputStream)
        val netOut = DataOutputStream(secure.outputStream)
        netOut.write(profile.token)
        netOut.flush()
        check(netIn.readUnsignedByte() == 1) { "Gateway не подтвердил токен доступа" }

        val clientIP = if (alpn == "portline-ipv4-lease/1") {
            val ip = ByteArray(4)
            netIn.readFully(ip)
            require(ip[0].toInt() == 10 && ip[1].toInt() == 76 && ip[2].toInt() == 24 && (ip[3].toInt() and 255) in 3..254) {
                "Gateway вернул некорректный адрес клиента"
            }
            InetAddress.getByAddress(ip).hostAddress!!
        } else {
            "10.76.24.2"
        }
        secure.soTimeout = 45000
        log("5/5 Создание TUN-интерфейса (IP: $clientIP)…")

        val builder = Builder().setSession("Portline")
            .setMtu(1280)
            .setBlocking(true)
            .addAddress(clientIP, 24)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")
            .addDnsServer("9.9.9.9")
            .addAddress("fd76:24::2", 64)
            .addRoute("::", 0)
        if (Build.VERSION.SDK_INT >= 29) {
            builder.setMetered(false)
        }
        val tunnel = builder.establish() ?: error("Android отказался создавать VPN-интерфейс")
        vpn = tunnel
        established = true
        log("Туннель активен · $clientIP → ${profile.host}:${profile.port}")

        val tunIn = FileInputStream(tunnel.fileDescriptor)
        val tunOut = FileOutputStream(tunnel.fileDescriptor)
        val writeLock = Any()
        val tunOutLock = Any()

        fun writeFrame(data: ByteArray, len: Int) {
            val frame = ByteArray(2 + len)
            frame[0] = ((len ushr 8) and 0xFF).toByte()
            frame[1] = (len and 0xFF).toByte()
            System.arraycopy(data, 0, frame, 2, len)
            synchronized(writeLock) {
                netOut.write(frame)
                netOut.flush()
            }
        }

        val connectedAt = System.currentTimeMillis()
        currentSnapshot = TunnelSnapshot(
            state = "connected",
            phase = "Полный туннель активен",
            message = "Весь IPv4 и DNS идут через сервер; IPv6 заблокирован",
            endpoint = "${profile.host}:${profile.port}",
            clientIp = clientIP,
            connectedAtMs = connectedAt
        )
        updateNotification("Подключён · ${profile.host}:${profile.port}")

        val pingLock = Any()
        var lastPingSeq = 0
        var lastPingSentNs = 0L

        val transmitter = Thread({
            val buf = ByteArray(1280)
            try {
                while (active.get()) {
                    val n = tunIn.read(buf)
                    if (n <= 0) break
                    val version = buf[0].toInt() ushr 4
                    if (version == 6 && n >= 40) {
                        val reply = buildIcmpv6AdminProhibited(buf, n)
                        if (reply != null) {
                            synchronized(tunOutLock) {
                                tunOut.write(reply)
                            }
                        }
                        continue
                    }
                    if (n < 20 || version != 4) continue
                    writeFrame(buf, n)
                    sentCounter.incrementAndGet()
                }
            } catch (_: Exception) {
            } finally {
                closeSockets()
            }
        }, "PortlineToGateway").apply { isDaemon = true; start() }

        val heartbeat = Thread({
            var seq = 0
            try {
                while (active.get()) {
                    Thread.sleep(12000)
                    if (!active.get()) break
                    seq = (seq + 1) and 0xFFFF
                    val ping = buildIcmpEchoRequest(clientIP, "10.76.24.1", seq)
                    synchronized(pingLock) {
                        lastPingSeq = seq
                        lastPingSentNs = System.nanoTime()
                    }
                    writeFrame(ping, ping.size)
                }
            } catch (_: Exception) {
            }
        }, "PortlineHeartbeat").apply { isDaemon = true; start() }

        val buffer = ByteArray(1280)
        try {
            while (active.get()) {
                val n = netIn.readUnsignedShort()
                check(n in 20..1280) { "Gateway прислал некорректную длину пакета" }
                netIn.readFully(buffer, 0, n)
                check((buffer[0].toInt() ushr 4) == 4) { "Gateway прислал неподдерживаемую версию IP" }
                val echoSeq = parsePortlineEchoReply(buffer, n)
                if (echoSeq >= 0) {
                    synchronized(pingLock) {
                        if (echoSeq == lastPingSeq && lastPingSentNs > 0L) {
                            val ms = ((System.nanoTime() - lastPingSentNs) / 1_000_000L).coerceAtLeast(1L)
                            latencyValue.set(ms)
                        }
                    }
                    continue
                }
                synchronized(tunOutLock) {
                    tunOut.write(buffer, 0, n)
                }
                recvCounter.incrementAndGet()
            }
        } finally {
            heartbeat.interrupt()
            closeSockets()
            try { transmitter.join(500) } catch (_: Exception) {}
        }
        return established
    }

    private fun closeSockets() {
        try { tls?.close() } catch (_: Exception) {}
        try { tcp?.close() } catch (_: Exception) {}
        try { vpn?.close() } catch (_: Exception) {}
    }

    private fun stopTunnel() {
        active.set(false)
        closeSockets()
        tls = null
        tcp = null
        vpn = null
    }

    override fun onRevoke() {
        userStopped.set(true)
        stopTunnel()
        currentSnapshot = TunnelSnapshot(
            state = "disconnected",
            phase = "Отключено",
            message = "Системное разрешение VPN отозвано"
        )
        stopSelf()
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }

    private fun checksum16(initialSum: Int, data: ByteArray, offset: Int, length: Int): Int {
        var sum = initialSum
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            val word = ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        if (i < end) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }
        while (sum ushr 16 != 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return sum.inv() and 0xFFFF
    }

    private fun buildIcmpv6AdminProhibited(orig: ByteArray, len: Int): ByteArray? {
        if (len < 40 || (orig[0].toInt() ushr 4) != 6) return null
        if ((orig[6].toInt() and 0xFF) == 58 && len >= 48) {
            val icmpType = orig[40].toInt() and 0xFF
            if (icmpType < 128 || icmpType in 133..136) return null
        }
        if ((orig[24].toInt() and 0xFF) == 0xFF) return null
        val quotedLen = len.coerceAtMost(1280 - 48)
        val pkt = ByteArray(48 + quotedLen)
        pkt[0] = 0x60
        val payloadLen = 8 + quotedLen
        pkt[4] = ((payloadLen ushr 8) and 0xFF).toByte()
        pkt[5] = (payloadLen and 0xFF).toByte()
        pkt[6] = 58
        pkt[7] = 64
        System.arraycopy(orig, 24, pkt, 8, 16)
        System.arraycopy(orig, 8, pkt, 24, 16)
        pkt[40] = 1
        pkt[41] = 1
        System.arraycopy(orig, 0, pkt, 48, quotedLen)

        var pseudo = 0
        for (i in 8 until 40 step 2) {
            pseudo += ((pkt[i].toInt() and 0xFF) shl 8) or (pkt[i + 1].toInt() and 0xFF)
        }
        pseudo += payloadLen + 58
        val csum = checksum16(pseudo, pkt, 40, payloadLen)
        pkt[42] = ((csum ushr 8) and 0xFF).toByte()
        pkt[43] = (csum and 0xFF).toByte()
        return pkt
    }

    private fun buildIcmpEchoRequest(srcIp: String, dstIp: String, seq: Int): ByteArray {
        val src = InetAddress.getByName(srcIp).address
        val dst = InetAddress.getByName(dstIp).address
        val pkt = ByteArray(28)
        pkt[0] = 0x45
        pkt[3] = 28
        pkt[8] = 64
        pkt[9] = 1
        System.arraycopy(src, 0, pkt, 12, 4)
        System.arraycopy(dst, 0, pkt, 16, 4)
        val ipCsum = checksum16(0, pkt, 0, 20)
        pkt[10] = ((ipCsum ushr 8) and 0xFF).toByte()
        pkt[11] = (ipCsum and 0xFF).toByte()
        pkt[20] = 8
        pkt[24] = ((ECHO_ID ushr 8) and 0xFF).toByte()
        pkt[25] = (ECHO_ID and 0xFF).toByte()
        pkt[26] = ((seq ushr 8) and 0xFF).toByte()
        pkt[27] = (seq and 0xFF).toByte()
        val icmpCsum = checksum16(0, pkt, 20, 8)
        pkt[22] = ((icmpCsum ushr 8) and 0xFF).toByte()
        pkt[23] = (icmpCsum and 0xFF).toByte()
        return pkt
    }

    private fun parsePortlineEchoReply(pkt: ByteArray, len: Int): Int {
        if (len < 28 || (pkt[0].toInt() ushr 4) != 4 || (pkt[9].toInt() and 0xFF) != 1) return -1
        val ihl = (pkt[0].toInt() and 0x0F) * 4
        if (ihl < 20 || len < ihl + 8) return -1
        if (pkt[ihl].toInt() != 0 || pkt[ihl + 1].toInt() != 0) return -1
        val id = ((pkt[ihl + 4].toInt() and 0xFF) shl 8) or (pkt[ihl + 5].toInt() and 0xFF)
        if (id != ECHO_ID) return -1
        return ((pkt[ihl + 6].toInt() and 0xFF) shl 8) or (pkt[ihl + 7].toInt() and 0xFF)
    }
}
