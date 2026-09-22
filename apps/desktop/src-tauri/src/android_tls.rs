//! Initialize Android's certificate verifier before Tauri starts networking.
use jni::{Env, objects::JObject};

const _: jni::NativeMethod = jni::native_method! {
    java_type = "now.elo.MainActivity",
    extern fn initialize_tls(),
};

fn initialize_tls<'local>(
    env: &mut Env<'local>,
    activity: JObject<'local>,
) -> Result<(), jni::errors::Error> {
    // Retain the application context, not an Activity that can be recreated.
    let context = env
        .call_method(
            &activity,
            jni::jni_str!("getApplicationContext"),
            jni::jni_sig!(() -> android.content.Context),
            &[],
        )?
        .l()?;
    rustls_platform_verifier::android::init_with_env(env, context)
}
