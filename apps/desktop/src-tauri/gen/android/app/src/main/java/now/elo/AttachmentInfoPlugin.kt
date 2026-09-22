package now.elo

import android.app.Activity
import android.net.Uri
import android.provider.OpenableColumns
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin

@InvokeArg
class DocumentInfoArgs { var uri: String = "" }

@TauriPlugin
class AttachmentInfoPlugin(private val activity: Activity) : Plugin(activity) {
    @Command
    fun displayName(invoke: Invoke) {
        val args = invoke.parseArgs(DocumentInfoArgs::class.java)
        val uri = Uri.parse(args.uri)
        if (uri.scheme != "content") {
            invoke.reject("Invalid document URI.")
            return
        }
        // The picker has granted access to this document. Its URI suffix is an
        // opaque identifier (for example, 75), never the user-visible filename.
        val name = try {
            activity.contentResolver.query(
                uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null
            )?.use { cursor ->
                val column = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (column >= 0 && cursor.moveToFirst() && !cursor.isNull(column)) {
                    cursor.getString(column)?.take(255)
                } else null
            }
        } catch (_: Exception) {
            // Missing optional metadata must not prevent opening a granted file.
            null
        }
        invoke.resolve(JSObject().put("name", name))
    }
}
