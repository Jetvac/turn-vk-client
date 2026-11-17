plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "io.github.jetvac.turnvk"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.github.jetvac.turnvk"
        minSdk = 24
        targetSdk = 35
        versionCode = 7
        versionName = "0.5.0"
    }

    // The release key comes from the environment (CI: repository secrets).
    // Every release must be signed with the same key, or Android refuses
    // to install it over the previous version. Without it (local builds)
    // the debug key is used.
    val releaseKey = System.getenv("TURNVK_KEYSTORE")?.takeIf { file(it).exists() }
    signingConfigs {
        if (releaseKey != null) {
            create("release") {
                storeFile = file(releaseKey)
                storePassword = System.getenv("TURNVK_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("TURNVK_KEY_ALIAS") ?: "turnvk"
                keyPassword = System.getenv("TURNVK_KEY_PASSWORD") ?: System.getenv("TURNVK_KEYSTORE_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    packaging {
        jniLibs.useLegacyPackaging = true
    }
}

dependencies {
    // The Go engine, built by `gomobile bind` into libs/turnvk.aar.
    implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.aar"))))

    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material:material-icons-core")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.webkit:webkit:1.12.1")
}
