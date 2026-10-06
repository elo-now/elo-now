-keep class now.elo.push.** { *; }
# WebRTC Java methods and class names are invoked by libjingle's JNI bindings.
-keep class org.webrtc.** { *; }
-keep class livekit.org.webrtc.** { *; }
