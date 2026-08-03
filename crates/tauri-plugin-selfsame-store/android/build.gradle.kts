plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    // Must match PLUGIN_IDENTIFIER in ../src/lib.rs.
    namespace = "io.anuna.selfsame.store"
    compileSdk = 36

    defaultConfig {
        // API 24 is the floor `setUserAuthenticationValidityDurationSeconds`
        // and AES/GCM in AndroidKeyStore both need, and it matches the other
        // Tauri mobile plugins this app already ships.
        minSdk = 24

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
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

dependencies {
    // Nothing beyond the platform: the Keystore and SharedPreferences are both
    // framework APIs. `androidx.security:security-crypto` would be the obvious
    // dependency here and is deliberately not used — it is deprecated, and it
    // wraps the same two framework calls this plugin makes directly.
    implementation("androidx.core:core-ktx:1.9.0")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")
    implementation(project(":tauri-android"))
}
