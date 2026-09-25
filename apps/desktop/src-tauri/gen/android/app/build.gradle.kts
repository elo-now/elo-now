import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.util.Properties
import java.io.File
import groovy.json.JsonSlurper
import java.nio.file.Files
import java.nio.file.LinkOption

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("rust")
}

val tauriProperties = Properties().apply {
    val propFile = file("tauri.properties")
    if (propFile.exists()) {
        propFile.inputStream().use { load(it) }
    }
}

// Signing credentials remain outside the checkout and are never APK resources.
val signingPath = providers.environmentVariable("TAURI_ELO_ANDROID_SIGNING").orNull
val releaseCredentials = signingPath?.let {
    val source = file(it)
    require(File(it).isAbsolute && Files.isRegularFile(source.toPath(), LinkOption.NOFOLLOW_LINKS)) {
        "Android signing requires a private absolute configuration path"
    }
    require(source.length() <= 8192) { "Invalid Android signing configuration" }
    val permissions = Files.getPosixFilePermissions(source.toPath())
    require(permissions.none { permission -> permission.name.startsWith("GROUP_") || permission.name.startsWith("OTHERS_") }) {
        "Android signing configuration must be private"
    }
    JsonSlurper().parse(source) as Map<*, *>
}

// Resolve the matching Kotlin verifier from Cargo.lock's Android dependency.
// The Android 0.2 shim moved from the crate to upstream's Maven archive.
// Keep the version Cargo-synchronized and the archive pinned to reviewed bytes.
val verifierMetadata = providers.exec {
    commandLine("cargo", "metadata", "--locked", "--offline", "--format-version", "1",
        "--filter-platform", "aarch64-linux-android", "--manifest-path",
        file("../../../Cargo.toml").absolutePath)
}.standardOutput.asText.get()
val verifierPackages = (JsonSlurper().parseText(verifierMetadata) as Map<*, *>)["packages"] as List<*>
val verifierPackage = verifierPackages.map { it as Map<*, *> }
    .single { it["name"] == "rustls-platform-verifier-android" }

repositories {
    exclusiveContent {
        forRepository {
            maven {
                url = uri("https://raw.githubusercontent.com/rustls/rustls-platform-verifier/1aa691352a5e0c215210dfc9a3c2f2078639dc91/android-release-support/maven/")
                metadataSources { mavenPom(); artifact() }
            }
        }
        filter { includeModule("org.rustls", "rustls-platform-verifier") }
    }
}

android {
    compileSdk { version = release(37) }
    namespace = "now.elo"
    defaultConfig {
        manifestPlaceholders["usesCleartextTraffic"] = "false"
        applicationId = "now.elo"
        minSdk = 24
        targetSdk = 36
        versionCode = tauriProperties.getProperty("tauri.android.versionCode", "1").toInt()
        versionName = tauriProperties.getProperty("tauri.android.versionName", "1.0")
        // Only the public client configuration is used here. Never accept a service account.
        val firebasePath = providers.environmentVariable("TAURI_ELO_FIREBASE_ANDROID").orNull
        if (firebasePath != null) {
            val config = JsonSlurper().parse(file(firebasePath)) as Map<*, *>
            require(!config.containsKey("private_key") && config["type"] != "service_account") { "A Firebase client configuration is required" }
            val project = config["project_info"] as Map<*, *>
            val client = (config["client"] as List<*>).map { it as Map<*, *> }.single {
                val info = it["client_info"] as Map<*, *>
                (info["android_client_info"] as Map<*, *>)["package_name"] == applicationId
            }
            val info = client["client_info"] as Map<*, *>
            val key = (client["api_key"] as List<*>).map { it as Map<*, *> }.first()["current_key"] as String
            resValue("string", "google_app_id", info["mobilesdk_app_id"] as String)
            resValue("string", "gcm_defaultSenderId", project["project_number"] as String)
            resValue("string", "google_api_key", key)
            resValue("string", "project_id", project["project_id"] as String)
        }
    }
    signingConfigs {
        if (releaseCredentials != null) {
            create("teamRelease") {
                storeFile = file(releaseCredentials["storeFile"] as String)
                storeType = "PKCS12"
                storePassword = releaseCredentials["storePassword"] as String
                keyAlias = releaseCredentials["keyAlias"] as String
                keyPassword = releaseCredentials["keyPassword"] as String
            }
        }
    }
    buildTypes {
        getByName("debug") {
            manifestPlaceholders["usesCleartextTraffic"] = "true"
            isDebuggable = true
            isJniDebuggable = true
            isMinifyEnabled = false
            packaging {                jniLibs.keepDebugSymbols.add("*/arm64-v8a/*.so")
                jniLibs.keepDebugSymbols.add("*/armeabi-v7a/*.so")
                jniLibs.keepDebugSymbols.add("*/x86/*.so")
                jniLibs.keepDebugSymbols.add("*/x86_64/*.so")
            }
        }
        getByName("release") {
            signingConfig = signingConfigs.findByName("teamRelease")
            isMinifyEnabled = true
            proguardFiles(
                *fileTree(".") { include("**/*.pro") }
                    .plus(getDefaultProguardFile("proguard-android-optimize.txt"))
                    .toList().toTypedArray()
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlin {
        compilerOptions { jvmTarget = JvmTarget.JVM_11 }
    }
    buildFeatures {
        buildConfig = true
        // Firebase client configuration is supplied through generated resources.
        resValues = true
    }
}

rust {
    rootDirRel = "../../../"
}

dependencies {
    implementation("org.rustls:rustls-platform-verifier:${verifierPackage["version"]}")
    implementation("androidx.webkit:webkit:1.17.1")
    implementation("androidx.appcompat:appcompat:1.8.0")
    implementation("androidx.activity:activity-ktx:1.13.0")
    implementation("com.google.android.material:material:1.14.0")
    implementation("androidx.lifecycle:lifecycle-process:2.11.0")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.7.0")
}

apply(from = file("tauri.build.gradle.kts"))
