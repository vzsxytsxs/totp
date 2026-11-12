// The core module is a plain Kotlin/JVM library (no Android dependencies), so it
// can be built and unit-tested on any machine: `gradle -p android/core test`.
// The Android app consumes it through `includeBuild("core")`.
pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}

rootProject.name = "core"
