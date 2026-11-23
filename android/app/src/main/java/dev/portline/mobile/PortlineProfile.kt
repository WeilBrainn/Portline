package dev.portline.mobile

import android.util.Base64
import org.json.JSONObject
import java.net.InetAddress

data class PortlineProfile(val host: String, val port: Int, val pin: ByteArray, val token: ByteArray) {
    companion object {
        fun decode(encoded: String): PortlineProfile {
            require(encoded.length in 4..8192) { "Неверный размер профиля" }
            val raw = Base64.decode(encoded.trim(), Base64.DEFAULT)
            require(raw.size < 4096) { "Слишком большой профиль" }
            val json = JSONObject(raw.toString(Charsets.UTF_8))
            require(json.getInt("version") == 1) { "Несовместимая версия профиля" }
            val host = json.getString("host")
            require(host.length in 1..253 && host.matches(Regex("[a-zA-Z0-9][a-zA-Z0-9.-]*")) && !host.contains("..")) { "Неверный адрес сервера" }
            val port = json.getInt("port")
            require(port in 1..65535) { "Неверный порт сервера" }
            val pin = Base64.decode(json.getString("serverKeyPin"), Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
            val token = Base64.decode(json.getString("token"), Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
            require(pin.size == 32 && token.size == 32) { "Неверный ключ или токен" }
            return PortlineProfile(host, port, pin, token)
        }
    }
}
