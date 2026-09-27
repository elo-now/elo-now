package now.elo

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class MediaCaptureTest {
    @Test fun chatCameraOffersBothPhotoAndVideo() {
        val expected = listOf(MediaCaptureKind.PHOTO, MediaCaptureKind.VIDEO)
        assertEquals(expected, mediaCaptureKinds(arrayOf("image/*", "video/*"), true))
        assertEquals(expected, mediaCaptureKinds(arrayOf("image/*, video/*"), true))
    }

    @Test fun avatarCameraAndVideoOnlyInputsKeepTheirRequestedMode() {
        assertEquals(listOf(MediaCaptureKind.PHOTO), mediaCaptureKinds(arrayOf("image/jpeg"), true))
        assertEquals(listOf(MediaCaptureKind.VIDEO), mediaCaptureKinds(arrayOf("video/*"), true))
    }

    @Test fun galleryInputDoesNotForceCapture() {
        assertEquals(emptyList<MediaCaptureKind>(), mediaCaptureKinds(arrayOf("image/*", "video/*"), false))
    }

    @Test fun photoUsesFullResolutionOutputEvenIfCameraReturnsNoIntent() {
        assertEquals("photo", mediaCaptureResult(true, true, "photo", null))
        assertEquals("photo", mediaCaptureResult(true, true, "photo", "thumbnail"))
    }

    @Test fun videoDoesNotReturnTheUnusedEmptyPhotoFile() {
        assertEquals("video", mediaCaptureResult(true, false, "photo", "video"))
        assertNull(mediaCaptureResult(true, false, "photo", null))
    }

    @Test fun cancellationNeverStagesAnAttachment() {
        assertNull(mediaCaptureResult(false, true, "photo", "video"))
    }
}
