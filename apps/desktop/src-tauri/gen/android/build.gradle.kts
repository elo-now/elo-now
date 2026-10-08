buildscript {
    repositories {
        google()
        mavenCentral()
    }
    dependencies {
        classpath("com.android.tools.build:gradle:9.4.1")
        classpath("com.google.firebase:firebase-crashlytics-gradle:3.0.8")
        classpath("com.google.gms:google-services:4.5.0")
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:2.4.20")
    }
}

allprojects {
    repositories {
        google()
        mavenCentral()
        maven("https://jitpack.io") {
            content { includeModule("com.github.davidliu", "audioswitch") }
        }
    }
}

tasks.register("clean").configure {
    delete("build")
}
