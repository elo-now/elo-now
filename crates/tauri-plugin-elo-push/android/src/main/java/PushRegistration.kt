package now.elo.push

import com.google.android.gms.tasks.Task
import com.google.android.gms.tasks.Tasks
import com.google.firebase.installations.FirebaseInstallations
import com.google.firebase.messaging.FirebaseMessaging

/** Serialize provider changes even when the activity is recreated during logout. */
internal object PushRegistration {
    private var pending: Task<*> = Tasks.forResult(null)

    @Synchronized
    fun register(): Task<String> {
        val result = pending.continueWithTask {
            FirebaseMessaging.getInstance().register()
        }.onSuccessTask {
            // An FID alone is not deliverable until Messaging has registered it.
            FirebaseInstallations.getInstance().id
        }
        pending = result
        return result
    }

    @Synchronized
    fun unregister() {
        pending = pending.continueWithTask { FirebaseMessaging.getInstance().unregister() }
    }
}
