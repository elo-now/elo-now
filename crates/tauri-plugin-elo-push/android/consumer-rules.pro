-keep class now.elo.push.** { *; }
# WebRTC Java methods and class names are invoked by libjingle's JNI bindings.
-keep class org.webrtc.** { *; }
-keep class livekit.org.webrtc.** { *; }
# JNI Zero is loaded by name from JNI_OnLoad before Java references its helpers.
# Keep only native entry points: WebRTC's JniZero.setJniClassLoader is unused and
# references a Chromium-generated bridge that is not included in its AAR.
-keep class org.jni_zero.JniZero {
    private static java.lang.Object[] init();
    private static void crashIfMultiplexingMisaligned(long, long);
}
-keep class org.jni_zero.CommonApis {
    private static java.lang.Object[] mapToArray(java.util.Map);
    private static java.util.Map arrayToMap(java.lang.Object[]);
}
-keep class livekit.org.jni_zero.JniInit {
    private static java.lang.Object[] init();
    private static void crashIfMultiplexingMisaligned(long, long);
}
-keep class livekit.org.jni_zero.JniUtil {
    private static java.lang.Object[] mapToArray(java.util.Map);
    private static java.util.Map arrayToMap(java.lang.Object[]);
}
