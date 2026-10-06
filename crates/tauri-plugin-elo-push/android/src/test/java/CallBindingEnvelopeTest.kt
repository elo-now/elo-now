package now.elo.push

import org.junit.Assert.*
import org.junit.Test
import javax.crypto.AEADBadTagException
import javax.crypto.KeyGenerator

class CallBindingEnvelopeTest {
    private fun key() = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    private val aad = "now.elo:call-bindings:v1".toByteArray()

    @Test fun ciphertextRoundTripsButEachWriteUsesANewNonce() {
        val key = key()
        val clear = "synthetic-call-delegation".toByteArray()
        val first = CallBindingEnvelope.seal(clear, key, aad)
        val second = CallBindingEnvelope.seal(clear, key, aad)
        assertFalse(first.contentEquals(second))
        assertFalse(first.toString(Charsets.UTF_8).contains("synthetic-call-delegation"))
        assertArrayEquals(clear, CallBindingEnvelope.open(first, key, aad))
        assertArrayEquals(clear, CallBindingEnvelope.open(second, key, aad))
    }
    @Test fun anotherDeviceOrApplicationCannotOpenTheDelegation() {
        val key = key()
        val cipher = CallBindingEnvelope.seal("synthetic-call-delegation".toByteArray(), key, aad)
        assertThrows(AEADBadTagException::class.java) { CallBindingEnvelope.open(cipher, key(), aad) }
        assertThrows(AEADBadTagException::class.java) { CallBindingEnvelope.open(cipher, key, "other-app".toByteArray()) }
    }
    @Test fun corruptOrUnsupportedEnvelopesFailClosed() {
        val key = key()
        val cipher = CallBindingEnvelope.seal("synthetic-call-delegation".toByteArray(), key, aad)
        cipher[cipher.lastIndex] = (cipher.last().toInt() xor 1).toByte()
        assertThrows(AEADBadTagException::class.java) { CallBindingEnvelope.open(cipher, key, aad) }
        cipher[0] = 2
        assertThrows(IllegalArgumentException::class.java) { CallBindingEnvelope.open(cipher, key, aad) }
        assertThrows(IllegalArgumentException::class.java) { CallBindingEnvelope.open(ByteArray(20), key, aad) }
        assertThrows(IllegalArgumentException::class.java) { CallBindingEnvelope.seal(ByteArray(CallBindingEnvelope.MAX_BYTES + 1), key, aad) }
    }
}
