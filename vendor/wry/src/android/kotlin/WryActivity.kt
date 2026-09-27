// Copyright 2020-2023 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

package {{package}}

import android.annotation.SuppressLint
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.view.ViewGroup
import androidx.lifecycle.Lifecycle
import android.webkit.WebView
import android.view.KeyEvent
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner

private val ACTIVITY_ID_KEY = "__wryActivityId"

object WryLifecycleObserver : DefaultLifecycleObserver {
    override fun onCreate(owner: LifecycleOwner) {
        super.onCreate(owner)
        Rust.create()
        Rust.wryCreate()
    }

    override fun onStart(owner: LifecycleOwner) {
        super.onStart(owner)
        Rust.start()
    }

    override fun onResume(owner: LifecycleOwner) {
        super.onResume(owner)
        Rust.resume()
    }

    override fun onPause(owner: LifecycleOwner) {
        super.onPause(owner)
        Rust.pause()
    }

    override fun onStop(owner: LifecycleOwner) {
        super.onStop(owner)
        Rust.stop()
    }
}

abstract class WryActivity : AppCompatActivity() {
    private var mWebView: RustWebView? = null
    private var webviewId = ""
    private var backCallback: OnBackPressedCallback? = null
    private val rendererRecovery = RendererRecovery()
    var id: Int = 0
    open val handleBackNavigation: Boolean = true

    open fun onWebViewCreate(webView: WebView) { }
    open fun onWebViewDestroyed(webView: WebView) { }

    fun onRendererTerminated(webView: RustWebView) {
        if (mWebView !== webView) return
        mWebView = null
        backCallback?.remove()
        backCallback = null
        onWebViewDestroyed(webView)
        (webView.webChromeClient as? RustWebChromeClient)?.onRendererTerminated()
        Rust.releaseTerminatedWebview(this, webView)
        (webView.parent as? ViewGroup)?.removeView(webView)
        webView.destroy()
        rendererRecovery.terminated()
        // Finish the platform callback before creating a new renderer.
        Handler(Looper.getMainLooper()).post { recoverRendererIfVisible() }
    }

    private fun recoverRendererIfVisible() {
        if (isFinishing || isDestroyed) return
        when (rendererRecovery.nextAction(
            lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED), SystemClock.elapsedRealtime()
        )) {
            RendererRecovery.Action.RECREATE -> Rust.recreateWebview(this)
            // A repeatedly crashing startup must not cause an automatic loop.
            RendererRecovery.Action.CLOSE -> finish()
            RendererRecovery.Action.NONE -> Unit
        }
    }

    fun setWebView(webView: RustWebView) {
        mWebView = webView
        webviewId = webView.id

        if (handleBackNavigation) {
            val callback = object : OnBackPressedCallback(true) {
                override fun handleOnBackPressed() {
                    this@WryActivity.mWebView?.let { current ->
                        if (current.canGoBack()) {
                            current.goBack()
                        } else {
                            this.isEnabled = false
                            try {
                                this@WryActivity.onBackPressedDispatcher.onBackPressed()
                            } finally {
                                this.isEnabled = true
                            }
                        }
                    }
                }
            }
            backCallback?.remove()
            backCallback = callback
            onBackPressedDispatcher.addCallback(this, callback)
        }

        onWebViewCreate(webView)
    }

    val version: String
        get() = WebView.getCurrentWebViewPackage()?.versionName ?: ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        id = savedInstanceState?.getInt(ACTIVITY_ID_KEY) ?: intent.extras?.getInt(ACTIVITY_ID_KEY) ?: hashCode()
        ProcessLifecycleOwner.get().lifecycle.addObserver(WryLifecycleObserver)
        Rust.onActivityCreate(this)
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        Rust.onWindowFocusChanged(this, hasFocus)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putInt(ACTIVITY_ID_KEY, id)
        Rust.onActivitySaveInstanceState()
    }

    override fun onPause() {
        super.onPause()
        mWebView?.onPause()
    }

    override fun onResume() {
        super.onResume()
        mWebView?.onResume()
        // Lifecycle reaches RESUMED after the platform finishes this callback.
        Handler(Looper.getMainLooper()).post { recoverRendererIfVisible() }
    }

    override fun onDestroy() {
        super.onDestroy()
        Rust.onActivityDestroy(this)
        Rust.onWebviewDestroy(this, webviewId)
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        Rust.onActivityLowMemory()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        Rust.onNewIntent(intent)
    }

    fun getAppClass(name: String): Class<*> {
        return Class.forName(name)
    }

    fun startActivity(cls: Class<*>): Int {
        val intent = Intent(this, cls)
        val id = kotlin.random.Random.nextInt()
        intent.putExtra(ACTIVITY_ID_KEY, id)
        startActivity(intent)
        return id
    }

    {{class-extension}}
}
