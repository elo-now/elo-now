package now.elo.push

import android.app.Activity
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.ImageButton
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView

/** The locked screen deliberately shows no decrypted profile or conversation data. */
internal fun Activity.incomingCallScreen(answer: () -> Unit, decline: () -> Unit): View {
    fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()
    val background = Color.rgb(16, 21, 18)
    val foreground = Color.rgb(245, 248, 246)
    val muted = Color.rgb(171, 188, 179)
    fun circle(color: Int) = GradientDrawable().apply {
        shape = GradientDrawable.OVAL
        setColor(color)
    }
    fun text(value: String, size: Float, color: Int) = TextView(this).apply {
        text = value
        textSize = size
        setTextColor(color)
        gravity = Gravity.CENTER
        typeface = Typeface.create("sans-serif", Typeface.NORMAL)
    }
    window.statusBarColor = background
    window.navigationBarColor = background
    window.decorView.systemUiVisibility = 0
    val root = FrameLayout(this).apply {
        setBackgroundColor(background)
        fitsSystemWindows = true
    }
    val content = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        gravity = Gravity.CENTER_HORIZONTAL
        setPadding(dp(24), dp(24), dp(24), dp(32))
    }
    val width = minOf(resources.displayMetrics.widthPixels, dp(480))
    root.addView(content, FrameLayout.LayoutParams(width, -1, Gravity.CENTER))
    content.addView(text("elo.now", 24f, muted))

    val identity = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        gravity = Gravity.CENTER
    }
    content.addView(identity, LinearLayout.LayoutParams(-1, 0, 1f))
    identity.addView(ImageView(this).apply {
        setImageResource(R.drawable.ic_elo_notification)
        imageTintList = ColorStateList.valueOf(Color.rgb(163, 202, 181))
        setPadding(dp(28), dp(28), dp(28), dp(28))
        this.background = circle(Color.rgb(36, 51, 43))
        importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
    }, LinearLayout.LayoutParams(dp(104), dp(104)).apply { bottomMargin = dp(24) })
    identity.addView(text(IncomingCalls.label(this, "incoming"), 28f, foreground))

    val actions = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER
        setBaselineAligned(false)
    }
    content.addView(actions, LinearLayout.LayoutParams(-1, -2))
    fun action(labelKey: String, icon: Int, color: Int, onClick: () -> Unit) {
        val label = IncomingCalls.label(this, labelKey)
        val group = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
        }
        actions.addView(group, LinearLayout.LayoutParams(0, -2, 1f))
        group.addView(ImageButton(this).apply {
            setImageResource(icon)
            imageTintList = ColorStateList.valueOf(Color.WHITE)
            setPadding(dp(22), dp(22), dp(22), dp(22))
            this.background = RippleDrawable(ColorStateList.valueOf(0x30ffffff), circle(color), circle(Color.WHITE))
            contentDescription = label
            setOnClickListener { onClick() }
        }, LinearLayout.LayoutParams(dp(76), dp(76)))
        group.addView(text(label, 16f, foreground).apply {
            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
        }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(12) })
    }
    action("decline", R.drawable.ic_call_decline, Color.rgb(187, 66, 66), decline)
    action("answer", R.drawable.ic_call_answer, Color.rgb(53, 126, 83), answer)
    return root
}
