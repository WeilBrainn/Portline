package dev.portline.mobile

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

class MainActivity : Activity() {
    private lateinit var input: EditText
    private lateinit var info: TextView
    private var pendingProfile = ""

    private fun dp(n: Int): Int = (resources.displayMetrics.density * n).toInt()
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val bg = 0xff111916.toInt()
        val text = 0xffedf5ef.toInt()
        val muted = 0xffa3b9a9.toInt()
        val green = 0xff759e7e.toInt()
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(28),dp(32),dp(28),dp(24)); setBackgroundColor(bg) }
        fun label(message: String, size: Float, color: Int): TextView {
            return TextView(this).apply { this.text = message; textSize = size; setTextColor(color); setPadding(0,0,0,dp(16)) }
        }
        root.addView(label("PORTLINE", 13f, green))
        root.addView(label("Прямой туннель к своему серверу", 25f, text))
        root.addView(label("Экспериментальная версия. IPv4 направляется через Gateway, IPv6 блокируется внутри VPN. В Android Settings включи Always-on VPN и Block connections without VPN — иначе трафик может уйти напрямую при сбое.", 13f, muted))
        input = EditText(this).apply {
            hint = "Вставь Portline-профиль (Base64)"
            setHintTextColor(muted); setTextColor(text); textSize=12f; minLines=4; maxLines=6
            setBackgroundColor(0xff1d2a22.toInt()); setPadding(dp(14),dp(14),dp(14),dp(14))
        }
        root.addView(input, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(140)))
        info = label("Профиль хранится зашифрованно в Android Keystore.", 13f, muted)
        root.addView(info)
        fun button(title: String, action: () -> Unit): Button = Button(this).apply { this.text=title; isAllCaps=false; setOnClickListener { action() } }
        root.addView(button("Импортировать файл профиля") {
            startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "*/*"
            }, 2)
        })
        root.addView(button("Сохранить профиль") {
            try { ProfileVault.save(this, input.text.toString().trim());info.text="Профиль сохранён в Android Keystore" }
            catch(e:Exception){info.text="Ошибка: ${e.message}"}
        })
        root.addView(button("Подключить") {
            try {
                val raw = input.text.toString().trim().ifBlank { ProfileVault.load(this) ?: error("Сначала добавь профиль") }
                PortlineProfile.decode(raw)
                pendingProfile = raw
                val prepare = VpnService.prepare(this)
                if (prepare != null) startActivityForResult(prepare, 1) else connect()
            } catch(e:Exception){info.text="Ошибка: ${e.message}"}
        })
        root.addView(button("Отключить") {
            val intent=Intent(this, PortlineVpnService::class.java).apply { action=PortlineVpnService.DISCONNECT }
            startService(intent)
            info.text="Отключение запрошено"
        })
        val scroll = ScrollView(this).apply { addView(root) }
        setContentView(scroll)
        try { if (ProfileVault.load(this) != null) info.text = "Сохранённый VPN-профиль готов к подключению" } catch (_: Exception) { info.text = "Сохранённый профиль недоступен" }
    }

    private fun connect() {
        val intent = Intent(this, PortlineVpnService::class.java).apply { action = PortlineVpnService.CONNECT; putExtra(PortlineVpnService.PROFILE,pendingProfile) }
        if (Build.VERSION.SDK_INT>=26) startForegroundService(intent) else startService(intent)
        info.text = "Запуск VPN запрошен. Проверь системное уведомление Portline."
    }
    @Deprecated("Deprecated in Android API")
    override fun onActivityResult(requestCode:Int,resultCode:Int,data:Intent?) {
        super.onActivityResult(requestCode,resultCode,data)
        if (requestCode == 2 && resultCode == RESULT_OK) {
            val uri = data?.data ?: return
            try {
                val raw = contentResolver.openInputStream(uri)?.use { stream ->
                    val buf = ByteArray(8193)
                    var count = 0
                    while (count < buf.size) {
                        val n = stream.read(buf, count, buf.size - count)
                        if (n < 0) break
                        count += n
                    }
                    require(count in 1..8192) { "Неверный размер профиля" }
                    String(buf, 0, count, Charsets.UTF_8).trim()
                } ?: error("Файл недоступен")
                ProfileVault.save(this, raw)
                input.setText("")
                info.text = "VPN-профиль импортирован"
            } catch (e: Exception) { info.text = "Ошибка импорта профиля" }
        }
        if (requestCode==1) {
            if(resultCode==RESULT_OK) connect() else info.text="Разрешение Android на VPN не предоставлено"
        }
    }
}
