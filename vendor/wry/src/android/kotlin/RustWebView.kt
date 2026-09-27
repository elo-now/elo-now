// Copyright 2020-2023 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

@file:Suppress("unused", "SetJavaScriptEnabled")

package {{package}}

import android.annotation.SuppressLint
import android.webkit.*
import android.content.Context
import android.util.AttributeSet
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import kotlin.collections.Map

@SuppressLint("RestrictedApi")
class RustWebView(context: Context, val initScripts: Array<String>, val id: String): WebView(context) {
    val isDocumentStartScriptEnabled: Boolean
    @Volatile private var terminated = false
    private val pendingEvals = mutableSetOf<Int>()

    // Layout tools can instantiate the view without loading the native bridge.
    // Runtime construction still requires Wry's explicit scripts and identity.
    constructor(context: Context, attrs: AttributeSet?) : this(context, emptyArray(), "preview") {
        check(isInEditMode) { "RustWebView must be created by Wry at runtime" }
    }

    override fun destroy() {
        terminated = true
        val abandoned = pendingEvals.toList()
        pendingEvals.clear()
        for (evalId in abandoned) Rust.onEval(id, evalId, "null")
        super.destroy()
    }

    init {
        settings.javaScriptEnabled = true
        settings.domStorageEnabled = true
        settings.setGeolocationEnabled(true)
        settings.mediaPlaybackRequiresUserGesture = false
        settings.javaScriptCanOpenWindowsAutomatically = true

        if (WebViewFeature.isFeatureSupported(WebViewFeature.DOCUMENT_START_SCRIPT)) {
            isDocumentStartScriptEnabled = true
            for (script in initScripts) {
                WebViewCompat.addDocumentStartJavaScript(this, script, setOf("*"));
            }
        } else {
          isDocumentStartScriptEnabled = false
        }

        {{class-init}}
    }

    fun loadUrlMainThread(url: String) {
        post {
          loadUrl(url)
        }
    }

    fun loadUrlMainThread(url: String, additionalHttpHeaders: Map<String, String>) {
        post {
          loadUrl(url, additionalHttpHeaders)
        }
    }

    override fun loadUrl(url: String) {
        if (!terminated && (isInEditMode || !Rust.shouldOverride(id, url))) {
            super.loadUrl(url);
        }
    }

    override fun loadUrl(url: String, additionalHttpHeaders: Map<String, String>) {
        if (!terminated && (isInEditMode || !Rust.shouldOverride(id, url))) {
            super.loadUrl(url, additionalHttpHeaders);
        }
    }

    fun loadHTMLMainThread(html: String) {
        post {
          if (!terminated) super.loadData(html, "text/html", null)
        }
    }

    fun evalScript(id: Int, script: String) {
        post {
            if (terminated) {
                Rust.onEval(this.id, id, "null")
                return@post
            }
            pendingEvals.add(id)
            super.evaluateJavascript(script) { result ->
                if (pendingEvals.remove(id)) Rust.onEval(this.id, id, result)
            }
        }
    }

    fun clearAllBrowsingData() {
        if (terminated) return
        try {
            super.getContext().deleteDatabase("webviewCache.db")
            super.getContext().deleteDatabase("webview.db")
            super.clearCache(true)
            super.clearHistory()
            super.clearFormData()
        } catch (ex: Exception) {
            Logger.error("Unable to create temporary media capture file: " + ex.message)
        }
    }

    fun getCookies(url: String): String {
        if (terminated) return ""
        val cookieManager = CookieManager.getInstance()
        return cookieManager.getCookie(url)
    }

    {{class-extension}}
}
