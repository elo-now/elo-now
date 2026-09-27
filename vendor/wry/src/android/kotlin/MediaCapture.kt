// Copyright 2026 elo.now contributors
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

package {{package}}

internal enum class MediaCaptureKind { PHOTO, VIDEO }

internal fun mediaCaptureKinds(acceptTypes: Array<String>, captureEnabled: Boolean): List<MediaCaptureKind> {
  if (!captureEnabled) return emptyList()
  val types = acceptTypes.flatMap { it.split(',') }.map { it.trim().lowercase(java.util.Locale.ROOT) }
  return buildList {
    if (types.any { it.startsWith("image/") }) add(MediaCaptureKind.PHOTO)
    if (types.any { it.startsWith("video/") }) add(MediaCaptureKind.VIDEO)
  }
}

internal fun <T> mediaCaptureResult(completed: Boolean, photoWritten: Boolean, photoUri: T?, returnedUri: T?): T? {
  if (!completed) return null
  return if (photoWritten && photoUri != null) photoUri else returnedUri
}
