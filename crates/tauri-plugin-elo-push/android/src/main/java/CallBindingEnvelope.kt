package now.elo.push

import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal object CallBindingEnvelope {
    const val MAX_BYTES = 2 * 1024 * 1024
    const val OVERHEAD = 29
    fun seal(clear: ByteArray, key: SecretKey, aad: ByteArray): ByteArray {
        require(clear.size in 1..MAX_BYTES)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD(aad)
        check(cipher.iv.size == 12)
        return byteArrayOf(1) + cipher.iv + cipher.doFinal(clear)
    }
    fun open(encoded: ByteArray, key: SecretKey, aad: ByteArray): ByteArray {
        require(encoded.size in (OVERHEAD + 1)..(MAX_BYTES + OVERHEAD) && encoded[0] == 1.toByte())
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, encoded.copyOfRange(1, 13)))
        cipher.updateAAD(aad)
        return cipher.doFinal(encoded, 13, encoded.size - 13)
    }
}
