package now.elo.push

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import app.tauri.plugin.JSObject
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/** Device-only call delegations, never a profile password or general signing key. */
internal object CallBindings {
    private const val ALIAS = "elo.call-delegations.v1"
    @Synchronized fun command(context: Context, op: String, payload: String?): JSObject {
        val file = AtomicFile(File(context.noBackupFilesDir, "call-bindings.v1"))
        val aad = (context.packageName + ":call-bindings:v1").toByteArray(Charsets.UTF_8)
        return when (op) {
            "load" -> {
                if (!file.baseFile.exists()) JSObject().put("payload", JSONObject.NULL)
                else {
                    check(file.baseFile.length() in (CallBindingEnvelope.OVERHEAD + 1L)..(CallBindingEnvelope.MAX_BYTES + CallBindingEnvelope.OVERHEAD.toLong()))
                    val encoded = file.readFully()
                    val clear = CallBindingEnvelope.open(encoded, key(false), aad)
                    try { JSObject().put("payload", clear.toString(Charsets.UTF_8)) } finally { clear.fill(0) }
                }
            }
            "store" -> {
                val clear = requireNotNull(payload).toByteArray(Charsets.UTF_8)
                try {
                    val encrypted = CallBindingEnvelope.seal(clear, key(true), aad)
                    val output = file.startWrite()
                    try { output.write(encrypted); file.finishWrite(output) }
                    catch (error: Exception) { file.failWrite(output); throw error }
                } finally { clear.fill(0) }
                JSObject()
            }
            "clear" -> { file.delete(); check(!file.baseFile.exists()); JSObject() }
            else -> error("invalid")
        }
    }
    private fun key(create: Boolean): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        check(create) { "unavailable" }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256).setUserAuthenticationRequired(false).build())
        }.generateKey()
    }
}
