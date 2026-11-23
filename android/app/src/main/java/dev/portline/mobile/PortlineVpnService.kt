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
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

// Experimental native Android transport for Portline profile version 1.
// It is NOT security-audited and must be run with Always-on VPN and
// 'Block connections without VPN' enabled by the user in Android Settings.
class PortlineVpnService : VpnService() {
    companion object {
        const val CONNECT = "dev.portline.mobile.CONNECT"
        const val DISCONNECT = "dev.portline.mobile.DISCONNECT"
        const val PROFILE = "profile"
        private const val CHANNEL = "portline_tunnel"
        private const val NOTIFY_ID = 63
    }
    private val active = AtomicBoolean(false)
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
            DISCONNECT -> { stopTunnel(); stopSelf(); return START_NOT_STICKY }
            CONNECT -> {
                if (active.get()) return START_NOT_STICKY
                val encoded = intent.getStringExtra(PROFILE) ?: return START_NOT_STICKY
                val profile = try { PortlineProfile.decode(encoded) } catch (_: Exception) { return START_NOT_STICKY }
                val pending = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
                val notification = Notification.Builder(this, CHANNEL)
                    .setSmallIcon(android.R.drawable.stat_sys_warning)
                    .setContentTitle("Portline VPN")
                    .setContentText("Защищённый туннель запускается — экспериментальная версия")
                    .setContentIntent(pending).setOngoing(true).build()
                if (Build.VERSION.SDK_INT >= 34) startForeground(NOTIFY_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
                else startForeground(NOTIFY_ID, notification)
                active.set(true)
                runner = Thread({ runTunnel(profile) }, "PortlineVpn").also { it.start() }
                return START_NOT_STICKY
            }
        }
        return START_NOT_STICKY
    }

    private fun runTunnel(profile: PortlineProfile) {
        try {
            // Protect socket before connect: the VPN's own TLS connection
            // MUST use the real underlying network or it would loop forever.
            val upstream = Socket()
            tcp = upstream
            check(protect(upstream)) { "Не удалось исключить служебный сокет VPN из туннеля" }
            upstream.connect(InetSocketAddress(profile.host, profile.port), 15000)
            upstream.soTimeout = 20000
            val trust = object : X509TrustManager {
                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
                override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
                override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
            }
            // Self-signed certs are accepted ONLY if their pinned SHA-256 SPKI
            // matches the profile. Verify before sending the authentication token.
            val context = SSLContext.getInstance("TLSv1.3")
            context.init(null, arrayOf<TrustManager>(trust), SecureRandom())
            val secure = context.socketFactory.createSocket(upstream, profile.host, profile.port, true) as SSLSocket
            tls = secure
            secure.enabledProtocols = arrayOf("TLSv1.3")
            if (Build.VERSION.SDK_INT >= 29) {
                secure.sslParameters = secure.sslParameters.apply { applicationProtocols = arrayOf("portline-ipv4-lease/1") }
            }
            secure.startHandshake()
            val leaf = secure.session.peerCertificates[0] as X509Certificate
            val actual = MessageDigest.getInstance("SHA-256").digest(leaf.publicKey.encoded)
            check(MessageDigest.isEqual(actual, profile.pin)) { "TLS-подпись сервера не совпала с профилем" }
            val netIn = DataInputStream(secure.inputStream)
            val netOut = DataOutputStream(secure.outputStream)
            netOut.write(profile.token)
            netOut.flush()
            check(netIn.readUnsignedByte() == 1) { "Gateway не подтвердил доступ" }
            val clientIP = if (Build.VERSION.SDK_INT >= 29 && secure.applicationProtocol == "portline-ipv4-lease/1") {
                val ip = ByteArray(4)
                netIn.readFully(ip)
                require(ip[0].toInt() == 10 && ip[1].toInt() == 76 && ip[2].toInt() == 24 && (ip[3].toInt() and 255) in 3..254)
                java.net.InetAddress.getByAddress(ip).hostAddress!!
            } else "10.76.24.2"
            secure.soTimeout = 0

            val tunnel = Builder().setSession("Portline")
                .setMtu(1280)
                .setBlocking(true)
                .addAddress(clientIP, 24)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("1.1.1.1")
                // The current protocol supports IPv4 only. IPv6 is intentionally
                // routed to TUN and dropped, NOT sent outside the VPN.
                .addAddress("fd76:24::2", 64)
                .addRoute("::", 0)
                .establish() ?: error("Android отказался создавать VPN-интерфейс")
            vpn = tunnel
            val tunIn = FileInputStream(tunnel.fileDescriptor)
            val tunOut = FileOutputStream(tunnel.fileDescriptor)
            val transmitter = Thread({
                val buf = ByteArray(1280)
                try {
                    while (active.get()) {
                        val n = tunIn.read(buf)
                        if (n <= 0) break
                        if (n < 20 || (buf[0].toInt() ushr 4) != 4) continue
                        netOut.writeShort(n)
                        netOut.write(buf, 0, n)
                        netOut.flush()
                    }
                } catch (_: Exception) { /* closing the VPN also interrupts IO */ }
                finally { stopTunnel() }
            }, "PortlineToGateway")
            transmitter.isDaemon = true
            transmitter.start()
            val buffer = ByteArray(1280)
            while (active.get()) {
                val n = netIn.readUnsignedShort()
                check(n in 20..1280) { "Gateway прислал некорректную длину пакета" }
                netIn.readFully(buffer, 0, n)
                check((buffer[0].toInt() ushr 4) == 4) { "Gateway прислал неподдерживаемую версию IP" }
                tunOut.write(buffer, 0, n)
            }
        } catch (_: Exception) {
            // No 'connected' state is advertised after a failed handshake.
            // TODO: persist a redacted diagnostic for the foreground UI.
        } finally {
            stopTunnel()
            stopSelf()
        }
    }

    private fun stopTunnel() {
        active.set(false)
        try { tls?.close() } catch (_: Exception) { }
        try { tcp?.close() } catch (_: Exception) { }
        try { vpn?.close() } catch (_: Exception) { }
        tls = null; tcp = null; vpn = null
    }

    override fun onRevoke() { stopTunnel(); stopSelf() }
    override fun onDestroy() { stopTunnel(); super.onDestroy() }
}
