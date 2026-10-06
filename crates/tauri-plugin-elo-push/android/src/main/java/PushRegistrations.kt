package now.elo.push

import android.content.SharedPreferences

/** Native-only route IDs, independently generated for every approved hosting service. */
internal object PushRegistrations {
    fun all(prefs: SharedPreferences): Set<String> = prefs.getStringSet("registrations", null)?.toSet()
        ?: prefs.getString("registration", null)?.let { setOf(it) } ?: emptySet()
    fun contains(prefs: SharedPreferences, registration: String?): Boolean = registration != null && registration in all(prefs)
    fun add(prefs: SharedPreferences, registration: String): Boolean {
        val values = all(prefs)
        if (registration !in values && values.size >= 32) return false
        val edit = prefs.edit().putStringSet("registrations", values + registration).remove("registration")
        prefs.getString("registration", null)?.let { legacy ->
            prefs.getString("challenge", null)?.let { edit.putString("challenge:$legacy", it).remove("challenge") }
            for (key in listOf("wake", "opened")) if (prefs.getString(key, null) != null) edit.putString("$key-registration", legacy)
        }
        edit.commit()
        return true
    }
    fun targetRegistration(prefs: SharedPreferences, key: String): String? = prefs.getString("$key-registration", null) ?: prefs.getString("registration", null)
    fun remove(prefs: SharedPreferences, registration: String) {
        val edit = prefs.edit().putStringSet("registrations", all(prefs) - registration).remove("registration").remove("challenge:$registration")
        if (prefs.getString("registration", null) == registration) edit.remove("challenge")
        for (key in listOf("wake", "opened")) if (targetRegistration(prefs, key) == registration) {
            edit.remove(key).remove("$key-registration")
        }
        edit.commit()
    }
}
