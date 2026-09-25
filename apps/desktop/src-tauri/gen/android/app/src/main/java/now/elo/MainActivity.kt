package now.elo

import android.content.Intent
import android.os.Bundle
import android.os.Environment
import android.graphics.Color
import android.view.View
import android.view.WindowManager
import java.io.File
import android.webkit.JavascriptInterface
import android.webkit.WebView
import androidx.activity.enableEdgeToEdge
import androidx.activity.OnBackPressedCallback
import androidx.core.graphics.Insets
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowCompat

class MainActivity : TauriActivity() {
  private external fun initializeTls()
  override val handleBackNavigation: Boolean = false

  // Tauri's generated camera picker calls this API. Redirect only its Pictures
  // directory into internal storage, including on Android 7–9 where other apps
  // with storage permission can read external app directories.
  override fun getExternalFilesDir(type: String?): File? =
    if (type == Environment.DIRECTORY_PICTURES) File(cacheDir, "elo-captures").apply {
      check(isDirectory || mkdirs()) { "Camera storage is unavailable" }
    } else super.getExternalFilesDir(type)

  override fun onPause() {
    window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    super.onPause()
  }

  override fun onResume() {
    super.onResume()
    // Screenshots remain a deliberate user action while the app is visible;
    // the system's background task preview must not expose conversations.
    window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
  }

  override fun onNewIntent(intent: Intent) {
    // A restored task can receive a notification before the plugins load.
    // Keep that intent available for their initialization as well.
    setIntent(intent)
    super.onNewIntent(intent)
  }

  override fun onWebViewCreate(webView: WebView) {
    super.onWebViewCreate(webView)
    // SPA screens have no WebView history entries. Give dialogs and the visible
    // Back header their existing action before using Android's root navigation.
    onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
      private var pending = false
      override fun handleOnBackPressed() {
        if (pending) return
        pending = true
        webView.evaluateJavascript("window.eloHandleBack?.() === true") { handled ->
          pending = false
          if (handled != "true" && !isDestroyed) {
            isEnabled = false
            try { onBackPressedDispatcher.onBackPressed() }
            finally { isEnabled = true }
          }
        }
      }
    })
    // The single boolean controls system-bar appearance only; no data API.
    webView.addJavascriptInterface(object {
      @JavascriptInterface
      fun setDarkMode(dark: Boolean) {
        runOnUiThread {
          val background = Color.parseColor(if (dark) "#15231D" else "#F7F9F6")
          findViewById<View>(android.R.id.content).setBackgroundColor(background)
          WindowCompat.getInsetsController(window, webView).apply {
            isAppearanceLightStatusBars = !dark
            isAppearanceLightNavigationBars = !dark
          }
        }
      }

      @JavascriptInterface
      fun getTextScale(): Double = resources.configuration.fontScale.toDouble()

    }, "eloAppearance")
    // The WebView camera picker creates temporary JPEGs in this app's Pictures
    // directory. Drop only those captures once JS has read them, or on restart.
    webView.addJavascriptInterface(object {
      @JavascriptInterface
      fun clearCapture() { clearPhotoCaptures() }
    }, "eloPhotos")
  }

  private fun clearPhotoCaptures() {
    listOf(getExternalFilesDir(Environment.DIRECTORY_PICTURES),
      super.getExternalFilesDir(Environment.DIRECTORY_PICTURES)).filterNotNull().forEach { directory ->
      directory.listFiles()?.forEach { file ->
      if (file.isFile && file.name.matches(Regex("JPEG_\\d{8}_\\d{6}_.*\\.jpg"))) {
        file.delete()
      }
      }
    }
  }

  private fun clearOldShareFiles() {
    // The native share plugin copies encrypted recovery QR images here so
    // FileProvider can grant a receiver access. Earlier builds tried the
    // cache root and left a copy before FileProvider rejected it.
    for (directory in listOf(File(cacheDir, "elo-captures"), cacheDir)) {
      directory.listFiles()?.forEach { file ->
        if (file.isFile && file.name.matches(Regex("elo-[0-9a-f]{32}\\.png"))) {
          file.delete()
        }
      }
    }
  }

  override fun onCreate(savedInstanceState: Bundle?) {
    // Reqwest uses Android's trust manager through rustls-platform-verifier.
    // Initialize it before Tauri can start any HTTPS work.
    System.loadLibrary("elo_app_lib")
    initializeTls()
    enableEdgeToEdge()
    clearPhotoCaptures()
    clearOldShareFiles()
    super.onCreate(savedInstanceState)

    // Older Android WebViews do not expose system bars or the keyboard to CSS.
    // Size the native container and zero the handled insets for its WebView.
    val content = findViewById<View>(android.R.id.content)
    ViewCompat.setOnApplyWindowInsetsListener(content) { view, windowInsets ->
      val handled = WindowInsetsCompat.Type.systemBars() or
        WindowInsetsCompat.Type.displayCutout() or WindowInsetsCompat.Type.ime()
      val safe = windowInsets.getInsets(handled)
      view.setPadding(safe.left, safe.top, safe.right, safe.bottom)
      WindowInsetsCompat.Builder(windowInsets)
        .setInsets(handled, Insets.NONE)
        .build()
    }
    ViewCompat.requestApplyInsets(content)
  }
}
