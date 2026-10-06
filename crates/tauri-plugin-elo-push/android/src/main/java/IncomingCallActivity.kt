package now.elo.push

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.view.Gravity
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

/** A private call-only surface over the lock screen, never the conversation WebView. */
class IncomingCallActivity : Activity() {
    private var callId: String? = null
    private var invitationId: String? = null
    private lateinit var status: TextView
    private lateinit var answer: Button
    private lateinit var end: Button
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setShowWhenLocked(true)
        setTurnScreenOn(true)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE or WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(32, 64, 32, 64)
            setBackgroundColor(Color.rgb(17, 24, 39))
        }
        content.addView(TextView(this).apply { text = applicationInfo.loadLabel(packageManager); textSize = 28f; setTextColor(Color.WHITE); gravity = Gravity.CENTER })
        status = TextView(this).apply { textSize = 20f; setTextColor(Color.WHITE); gravity = Gravity.CENTER; setPadding(0, 32, 0, 64) }
        content.addView(status)
        answer = Button(this).apply { setText(R.string.notification_answer_call); setOnClickListener {
            val id = callId ?: return@setOnClickListener
            val invitation = invitationId ?: return@setOnClickListener
            IncomingCalls.answer(id, invitation)
        } }
        end = Button(this).apply { setOnClickListener {
            val id = callId ?: return@setOnClickListener
            val invitation = invitationId ?: return@setOnClickListener
            if (IncomingCalls.matching(id, invitation)?.phase == IncomingCallState.Phase.RINGING) IncomingCalls.rejectFromSystem(id, invitation)
            else IncomingCalls.end(id, invitation)
        } }
        content.addView(answer)
        content.addView(end)
        setContentView(content)
        IncomingCalls.initialize(this)
        IncomingCalls.attach(this)
        acceptIntent(intent)
    }
    override fun onNewIntent(intent: Intent) { super.onNewIntent(intent); setIntent(intent); acceptIntent(intent) }
    private fun acceptIntent(value: Intent) {
        callId = value.getStringExtra(IncomingCalls.CALL_ID)
        invitationId = value.getStringExtra(IncomingCalls.INVITATION_ID)
        if (value.action == IncomingCalls.ANSWER && callId != null && invitationId != null) IncomingCalls.answer(callId!!, invitationId!!)
        refresh()
    }
    internal fun refresh() {
        if (!::status.isInitialized) return
        val call = IncomingCalls.matching(callId, invitationId)
        if (call == null) { finish(); return }
        status.setText(when (call.phase) {
            IncomingCallState.Phase.RINGING -> R.string.notification_incoming_call
            IncomingCallState.Phase.ANSWERING -> R.string.notification_connecting_call
            IncomingCallState.Phase.CONNECTED -> R.string.notification_chat_session
        })
        answer.setText(if (OutgoingCalls.active() || IncomingCalls.hasOtherOngoing(call.offer.callId, call.offer.invitationId)) R.string.notification_end_and_answer_call else R.string.notification_answer_call)
        answer.visibility = if (call.phase == IncomingCallState.Phase.RINGING) android.view.View.VISIBLE else android.view.View.GONE
        end.setText(if (call.phase == IncomingCallState.Phase.RINGING) R.string.notification_decline_call else R.string.notification_end_call)
    }
    override fun onDestroy() { IncomingCalls.detach(this); super.onDestroy() }
}
