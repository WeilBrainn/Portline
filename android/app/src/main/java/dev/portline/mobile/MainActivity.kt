package dev.portline.mobile

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.ViewGroup
import android.view.WindowInsets
import android.webkit.JavascriptInterface
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.FrameLayout

class MainActivity : Activity() {
    companion object {
        private const val APP_VERSION = "1.4.8"
        private const val REQ_VPN = 1
        private const val REQ_FILE = 2
        private const val REQ_NOTIFY = 3
        private const val REQ_SAVE_FILE = 4
    }

    private lateinit var webView: WebView
    private lateinit var apiServer: LocalApiServer
    private var pendingProfile = ""
    private var filePathCallback: ValueCallback<Array<Uri>>? = null
    private var pendingExportContent: String? = null

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val bg = 0xff080d18.toInt()
        window.statusBarColor = bg
        window.navigationBarColor = bg

        apiServer = LocalApiServer(
            context = applicationContext,
            appVersion = APP_VERSION,
            onRequestConnectVpn = { raw ->
                runOnUiThread {
                    pendingProfile = raw
                    val prepare = VpnService.prepare(this)
                    if (prepare != null) {
                        startActivityForResult(prepare, REQ_VPN)
                    } else {
                        startVpnService()
                    }
                }
            },
            onRequestDisconnectVpn = {
                runOnUiThread {
                    startService(Intent(this, PortlineVpnService::class.java).apply {
                        action = PortlineVpnService.DISCONNECT
                    })
                }
            },
            onRequestInstallApk = {
                runOnUiThread {
                    try {
                        val intent = Intent(Intent.ACTION_VIEW).apply {
                            setDataAndType(ApkUpdateProvider.UPDATE_URI, "application/vnd.android.package-archive")
                            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
                        }
                        startActivity(intent)
                    } catch (_: Exception) {
                    }
                }
            },
            onRequestQuit = {
                runOnUiThread {
                    startService(Intent(this, PortlineVpnService::class.java).apply {
                        action = PortlineVpnService.DISCONNECT
                    })
                    finishAndRemoveTask()
                }
            }
        )
        val port = apiServer.start()

        val container = FrameLayout(this).apply {
            setBackgroundColor(bg)
            setOnApplyWindowInsetsListener { v, insets ->
                val topInset: Int
                val bottomInset: Int
                if (Build.VERSION.SDK_INT >= 30) {
                    val sys = insets.getInsets(WindowInsets.Type.systemBars())
                    topInset = sys.top
                    bottomInset = sys.bottom
                } else {
                    @Suppress("DEPRECATION")
                    topInset = insets.systemWindowInsetTop
                    @Suppress("DEPRECATION")
                    bottomInset = insets.systemWindowInsetBottom
                }
                v.setPadding(0, topInset, 0, bottomInset)
                insets
            }
        }

        webView = WebView(this).apply {
            setBackgroundColor(bg)
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.allowFileAccess = false
            settings.mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
            addJavascriptInterface(AndroidBridge(), "PortlineAndroid")

            webViewClient = object : WebViewClient() {
                override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
                    val uri = request?.url ?: return false
                    if (uri.host == "127.0.0.1" || uri.host == "localhost") return false
                    try {
                        startActivity(Intent(Intent.ACTION_VIEW, uri))
                    } catch (_: Exception) {}
                    return true
                }

                override fun onPageFinished(view: WebView?, url: String?) {
                    super.onPageFinished(view, url)
                    // Intercept blob: file exports so saving .portline/.txt works natively on Android.
                    view?.evaluateJavascript(
                        """
                        (function(){
                          if (window.__portlineAndroidHooked) return;
                          window.__portlineAndroidHooked = true;
                          const origClick = HTMLAnchorElement.prototype.click;
                          HTMLAnchorElement.prototype.click = function() {
                            if (this.href && this.href.startsWith('blob:') && this.download) {
                              const fname = this.download;
                              fetch(this.href).then(r => r.text()).then(txt => {
                                if (window.PortlineAndroid) window.PortlineAndroid.saveTextFile(fname, txt);
                              });
                              return;
                            }
                            return origClick.apply(this, arguments);
                          };
                        })();
                        """.trimIndent(),
                        null
                    )
                }
            }

            webChromeClient = object : WebChromeClient() {
                override fun onShowFileChooser(
                    webView: WebView?,
                    filePathCallback: ValueCallback<Array<Uri>>?,
                    fileChooserParams: FileChooserParams?
                ): Boolean {
                    this@MainActivity.filePathCallback?.onReceiveValue(null)
                    this@MainActivity.filePathCallback = filePathCallback
                    val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                        addCategory(Intent.CATEGORY_OPENABLE)
                        type = "*/*"
                    }
                    startActivityForResult(intent, REQ_FILE)
                    return true
                }
            }
        }

        container.addView(webView, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.MATCH_PARENT
        ))
        setContentView(container)

        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIFY)
        }

        webView.loadUrl("http://127.0.0.1:$port/")
    }

    inner class AndroidBridge {
        @JavascriptInterface
        fun saveTextFile(filename: String, content: String) {
            runOnUiThread {
                pendingExportContent = content
                val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                    addCategory(Intent.CATEGORY_OPENABLE)
                    type = "application/octet-stream"
                    putExtra(Intent.EXTRA_TITLE, filename)
                }
                startActivityForResult(intent, REQ_SAVE_FILE)
            }
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, PortlineVpnService::class.java).apply {
            action = PortlineVpnService.CONNECT
            putExtra(PortlineVpnService.PROFILE, pendingProfile)
        }
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(intent) else startService(intent)
    }

    @Deprecated("Deprecated in Android API")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        when (requestCode) {
            REQ_VPN -> {
                if (resultCode == RESULT_OK) startVpnService()
            }
            REQ_FILE -> {
                val cb = filePathCallback
                filePathCallback = null
                val uri = if (resultCode == RESULT_OK) data?.data else null
                cb?.onReceiveValue(if (uri != null) arrayOf(uri) else null)
            }
            REQ_SAVE_FILE -> {
                val content = pendingExportContent
                pendingExportContent = null
                val uri = if (resultCode == RESULT_OK) data?.data else null
                if (uri != null && content != null) {
                    try {
                        contentResolver.openOutputStream(uri)?.use { out ->
                            out.write(content.toByteArray(Charsets.UTF_8))
                        }
                    } catch (_: Exception) {}
                }
            }
        }
    }

    override fun onDestroy() {
        apiServer.stop()
        super.onDestroy()
    }
}
