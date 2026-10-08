package now.elo

import android.content.Intent
import android.os.Bundle
import android.os.Environment
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.FrameLayout
import java.io.File
import android.webkit.JavascriptInterface
import android.webkit.WebView
import androidx.activity.enableEdgeToEdge
import androidx.activity.OnBackPressedCallback
import androidx.core.graphics.Insets
import androidx.core.graphics.toColorInt
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowCompat

class MainActivity : TauriActivity() {
  private external fun initializeTls()
  override val handleBackNavigation: Boolean = false
  private var webBackCallback: OnBackPressedCallback? = null
  private var launchCover: View? = null
  private var launchWebView: WebView? = null

  override fun setContentView(view: View?) {
    if (view !is WebView) {
      super.setContentView(view)
      return
    }
    // Keep the same mark across the Android starting window and WebView startup.
    // The WebView stays visible underneath so it can prepare its first frame.
    val container = FrameLayout(this)
    val appContent = FrameLayout(this)
    appContent.addView(view, FrameLayout.LayoutParams(
      ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
    container.addView(appContent, FrameLayout.LayoutParams(
      ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
    val cover = View(this).apply {
      setBackgroundResource(R.drawable.elo_launch_background)
      isClickable = true
      importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
    }
    container.addView(cover, FrameLayout.LayoutParams(
      ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
    launchWebView = view
    launchCover = cover
    // Keep the cover in the same full-window coordinates as windowBackground.
    // Insetting their shared parent moves the star when the WebView appears.
    // Only app content avoids system bars, cutouts and the keyboard; the cover
    // stays centered until the first usable WebView frame replaces it.
    ViewCompat.setOnApplyWindowInsetsListener(container) { _, windowInsets ->
      val handled = WindowInsetsCompat.Type.systemBars() or
        WindowInsetsCompat.Type.displayCutout() or WindowInsetsCompat.Type.ime()
      val safe = windowInsets.getInsets(handled)
      appContent.setPadding(safe.left, safe.top, safe.right, safe.bottom)
      WindowInsetsCompat.Builder(windowInsets)
        .setInsets(handled, Insets.NONE)
        .build()
    }
    super.setContentView(container)
    ViewCompat.requestApplyInsets(container)
  }

  override fun onWebViewDestroyed(webView: WebView) {
    if (launchWebView === webView) {
      launchWebView = null
      launchCover = null
    }
    webBackCallback?.remove()
    webBackCallback = null
    app.tauri.plugin.PluginManager.onWebViewDestroyed()
    super.onWebViewDestroyed(webView)
  }

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
    webBackCallback?.remove()
    webBackCallback = object : OnBackPressedCallback(true) {
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
    }.also { onBackPressedDispatcher.addCallback(this, it) }
    // These methods control presentation only; they do not expose profile data.
    webView.addJavascriptInterface(object {
      @JavascriptInterface
      fun setDarkMode(dark: Boolean) {
        runOnUiThread {
          val background = (if (dark) "#15231D" else "#F7F9F6").toColorInt()
          findViewById<View>(android.R.id.content).setBackgroundColor(background)
          WindowCompat.getInsetsController(window, webView).apply {
            isAppearanceLightStatusBars = !dark
            isAppearanceLightNavigationBars = !dark
          }
        }
      }

      @JavascriptInterface
      fun getTextScale(): Double = resources.configuration.fontScale.toDouble()

      @JavascriptInterface
      fun revealApp() {
        runOnUiThread {
          if (launchWebView !== webView || launchCover == null || isDestroyed) return@runOnUiThread
          // JS calls this after the local profile check has committed its UI.
          // Wait for that WebView frame, not a timer or any network operation.
          webView.postVisualStateCallback(0, object : WebView.VisualStateCallback() {
            override fun onComplete(requestId: Long) {
              if (launchWebView !== webView || isDestroyed) return
              launchCover?.let { (it.parent as? ViewGroup)?.removeView(it) }
              launchCover = null
            }
          })
        }
      }

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
  }
}
