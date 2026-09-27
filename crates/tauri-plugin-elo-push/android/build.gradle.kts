import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import groovy.json.JsonSlurper

plugins {
    id("com.android.library")
}
android {
    namespace = "now.elo.push"
    compileSdk { version = release(37) }
    defaultConfig { minSdk = 27; consumerProguardFiles("consumer-rules.pro") }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_11; targetCompatibility = JavaVersion.VERSION_11 }
}
abstract class GenerateNotificationResources : DefaultTask() {
    @get:InputFile
    abstract val catalog: RegularFileProperty
    @get:OutputDirectory
    abstract val outputDirectory: DirectoryProperty
    @TaskAction
    fun generate() {
        val copy = JsonSlurper().parse(catalog.get().asFile) as Map<*, *>
        val names = mapOf("notification_message" to "notifications.nativeMessage", "notification_invitation" to "notifications.nativeInvitation", "notification_activity" to "notifications.nativeActivity", "notification_channel_messages" to "notifications.channelMessages", "notification_channel_invitations" to "notifications.channelInvitations")
        val file = outputDirectory.get().file("values/notification_strings.xml").asFile
        file.parentFile.mkdirs()
        file.writeText("<resources>\n" + names.entries.joinToString("\n") { (name, key) ->
            val text = copy[key].toString().replace("&", "&amp;").replace("<", "&lt;").replace("'", "\\'")
            "<string name=\"$name\">$text</string>"
        } + "\n</resources>\n")
    }
}
androidComponents.onVariants { variant ->
    val generate = tasks.register<GenerateNotificationResources>("generate${variant.name.replaceFirstChar { it.uppercase() }}NotificationResources") {
        catalog.set(file("../../../apps/desktop/src/locales/native.en.json"))
        outputDirectory.set(layout.buildDirectory.dir("generated/notification-resources/${variant.name}"))
    }
    variant.sources.res?.addGeneratedSourceDirectory(generate, GenerateNotificationResources::outputDirectory)
}

dependencies {
    implementation(project(":tauri-android"))
    compileOnly("androidx.appcompat:appcompat:1.8.0")
    implementation(platform("com.google.firebase:firebase-bom:34.19.0"))
    implementation("com.google.firebase:firebase-messaging")
    implementation("com.google.firebase:firebase-installations")
    implementation("androidx.core:core-telecom:1.0.1")
    implementation("androidx.core:core-ktx:1.19.1")
    implementation("androidx.lifecycle:lifecycle-process:2.11.0")
    testImplementation("junit:junit:4.13.2")
}

kotlin { compilerOptions { jvmTarget = JvmTarget.JVM_11 } }
