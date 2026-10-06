package now.elo.push

import android.content.SharedPreferences
import java.lang.reflect.Proxy
import org.junit.Assert.*
import org.junit.Test

class PushRegistrationsTest {
    private val publicRoute = "11".repeat(16)
    private val privateRoute = "22".repeat(16)

    private fun preferences(values: MutableMap<String, Any?>): SharedPreferences {
        return Proxy.newProxyInstance(javaClass.classLoader, arrayOf(SharedPreferences::class.java)) { _, method, args ->
            when (method.name) {
                "getString", "getStringSet" -> values[args[0]] ?: args[1]
                "edit" -> {
                    val changes = mutableMapOf<String, Any?>()
                    Proxy.newProxyInstance(javaClass.classLoader, arrayOf(SharedPreferences.Editor::class.java)) { editor, edit, parameters ->
                        when (edit.name) {
                            "putString", "putStringSet" -> { changes[parameters[0] as String] = parameters[1]; editor }
                            "remove" -> { changes[parameters[0] as String] = null; editor }
                            "commit" -> { changes.forEach { (key, value) -> if (value == null) values.remove(key) else values[key] = value }; true }
                            else -> error("Unexpected preferences operation: ${edit.name}")
                        }
                    }
                }
                else -> error("Unexpected preferences operation: ${method.name}")
            }
        } as SharedPreferences
    }

    @Test fun addingPrivateHostingPreservesLegacyChallengeAndNotificationOwnership() {
        val values = mutableMapOf<String, Any?>("registration" to publicRoute, "opened" to "public-target", "challenge" to "public-challenge")
        val prefs = preferences(values)
        assertTrue(PushRegistrations.add(prefs, privateRoute))
        assertEquals(setOf(publicRoute, privateRoute), PushRegistrations.all(prefs))
        assertEquals(publicRoute, PushRegistrations.targetRegistration(prefs, "opened"))
        assertEquals("public-challenge", values["challenge:$publicRoute"])
        values["challenge:$privateRoute"] = "private-challenge"
        PushRegistrations.remove(prefs, privateRoute)
        assertEquals(setOf(publicRoute), PushRegistrations.all(prefs))
        assertEquals("public-target", values["opened"])
        assertEquals("public-challenge", values["challenge:$publicRoute"])
        assertNull(values["challenge:$privateRoute"])
        PushRegistrations.remove(prefs, publicRoute)
        assertTrue(PushRegistrations.all(prefs).isEmpty())
        assertNull(values["opened"])
    }

    @Test fun removingUnmigratedLegacyRouteClearsItsChallengeAndTap() {
        val values = mutableMapOf<String, Any?>("registration" to publicRoute, "opened" to "public-target", "challenge" to "public-challenge")
        val prefs = preferences(values)
        PushRegistrations.remove(prefs, publicRoute)
        assertTrue(PushRegistrations.all(prefs).isEmpty())
        assertNull(values["opened"])
        assertNull(values["challenge"])
        assertFalse(PushRegistrations.contains(prefs, publicRoute))
    }
}
