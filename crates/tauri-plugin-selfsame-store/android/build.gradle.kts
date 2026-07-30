plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "io.anuna.selfsame.store"

    // Matches ANDROID_PLATFORM in .forgejo/workflows/android.yml. Pinning it to
    // the platform that workflow installs means Gradle never has to auto-download
    // an SDK mid-build to compile this module.
    compileSdk = 34

    defaultConfig {
        // KeyGenParameterSpec is API 23; Context.getNoBackupFilesDir is API 21.
        // 24 is the floor the rest of the Tauri Android project uses.
        minSdk = 24
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
}

// Nothing but the Tauri plugin API. The Keystore, Cipher and file APIs this
// module uses are all in the platform itself, so there is no androidx here and
// therefore nothing that can widen what the merged manifest asks the OS for —
// which is what SPEC-003 REQ-203's allowlist check would otherwise catch late.
dependencies {
    implementation(project(":tauri-android"))
}
