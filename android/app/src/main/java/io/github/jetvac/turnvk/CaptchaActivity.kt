package io.github.jetvac.turnvk

import android.annotation.SuppressLint
import android.app.Activity
import android.graphics.Bitmap
import android.os.Bundle
import android.view.ViewGroup
import android.webkit.JavascriptInterface
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature

/**
 * Shows VK's captcha page so the user can solve it. A script on the page
 * passes on the success_token VK returns after the user passes the check;
 * the engine then repeats its request with it. Nothing is solved
 * automatically.
 */
class CaptchaActivity : Activity() {

    companion object {
        const val EXTRA_URL = "url"

        // Watches the page's own check request and reports VK's answer.
        private const val HOOK = """(function () {
  if (window.__turnvk) return; window.__turnvk = true;
  function report(d) { try { if (d && d.response && d.response.success_token) TurnVK.token(d.response.success_token); } catch (e) {} }
  var f = window.fetch;
  window.fetch = function (input) {
    var url = typeof input === 'string' ? input : (input && input.url) || '';
    return f.apply(this, arguments).then(function (r) {
      if (url.indexOf('captchaNotRobot.check') >= 0) r.clone().json().then(report).catch(function () {});
      return r;
    });
  };
  var open = XMLHttpRequest.prototype.open, send = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (m, url) { this.__u = url; return open.apply(this, arguments); };
  XMLHttpRequest.prototype.send = function () {
    var x = this;
    if (String(x.__u || '').indexOf('captchaNotRobot.check') >= 0)
      x.addEventListener('load', function () { try { report(JSON.parse(x.responseText)); } catch (e) {} });
    return send.apply(this, arguments);
  };
})();"""
    }

    private var answered = false
    private lateinit var web: WebView

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val url = intent.getStringExtra(EXTRA_URL) ?: TunnelState.captcha.value
        if (url == null) {
            finish()
            return
        }
        web = WebView(this)
        web.settings.javaScriptEnabled = true
        web.settings.domStorageEnabled = true
        web.addJavascriptInterface(Bridge(), "TurnVK")
        val documentStart = WebViewFeature.isFeatureSupported(WebViewFeature.DOCUMENT_START_SCRIPT)
        if (documentStart) {
            WebViewCompat.addDocumentStartJavaScript(web, HOOK, setOf("*"))
        }
        web.webViewClient = object : WebViewClient() {
            override fun onPageStarted(view: WebView, url: String?, favicon: Bitmap?) {
                if (!documentStart) view.evaluateJavascript(HOOK, null)
            }

            override fun onPageFinished(view: WebView, url: String?) {
                if (!documentStart) view.evaluateJavascript(HOOK, null)
            }
        }

        val title = TextView(this).apply {
            text = "Подтвердите в VK, что вы не робот. После проверки подключение продолжится само."
            setPadding(32, 48, 32, 16)
            textSize = 15f
        }
        val cancel = Button(this).apply {
            text = "Отмена"
            setOnClickListener { answer(null) }
        }
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(title)
            addView(web, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
            addView(cancel)
        }
        setContentView(root)
        web.loadUrl(url)
    }

    private fun answer(token: String?) {
        if (answered) return
        answered = true
        TunnelState.setCaptcha(null)
        if (token != null) {
            TunnelState.log("проверка VK пройдена")
            mobile.Mobile.submitCaptcha(token)
        } else {
            TunnelState.log("проверка VK отменена")
            mobile.Mobile.cancelCaptcha()
        }
        finish()
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        answer(null)
    }

    override fun onDestroy() {
        if (!answered && isFinishing) answer(null)
        if (::web.isInitialized) web.destroy()
        super.onDestroy()
    }

    private inner class Bridge {
        @JavascriptInterface
        fun token(t: String) {
            runOnUiThread { answer(t) }
        }
    }
}
