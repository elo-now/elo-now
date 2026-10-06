//! Explicit Decline from the system notification, without an Activity or vault.
use super::*;
use jni::{
    Env,
    objects::{JByteArray, JClass, JObject, JString},
};
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroizing;

// One worker per process. Repeated callbacks remain pending for a later app
// reconciliation instead of allocating unbounded runtimes or network requests.
static RUNNING: AtomicBool = AtomicBool::new(false);
struct Worker;
impl Drop for Worker {
    fn drop(&mut self) {
        RUNNING.store(false, Ordering::Release);
    }
}
struct QuietFailure;
impl<T: Default, E> jni::errors::ErrorPolicy<T, E> for QuietFailure {
    type Captures<'env: 'call, 'call> = ();
    fn on_error<'env: 'call, 'call>(_: &mut Env<'env>, _: &mut (), _: E) -> jni::errors::Result<T> {
        Ok(T::default())
    }
    fn on_panic<'env: 'call, 'call>(
        _: &mut Env<'env>,
        _: &mut (),
        _: Box<dyn std::any::Any + Send>,
    ) -> jni::errors::Result<T> {
        Ok(T::default())
    }
}
const _: jni::NativeMethod = jni::native_method! {
    java_type = "now.elo.push.ColdCallActions",
    error_policy = QuietFailure,
    static extern fn native_decline(context: android.content.Context, enrollment: byte[], event: JString) -> bool,
};
fn native_decline<'local>(
    env: &mut Env<'local>,
    _: JClass<'local>,
    context: JObject<'local>,
    enrollment: JByteArray<'local>,
    event: JString<'local>,
) -> jni::errors::Result<bool> {
    if enrollment.len(env)? > 2 * 1024 * 1024 {
        return Ok(false);
    }
    let event_length = env
        .call_method(
            &event,
            jni::jni_str!("length"),
            jni::jni_sig!(() -> int),
            &[],
        )?
        .i()?;
    if !(1..=8192).contains(&event_length) {
        return Ok(false);
    }
    if RUNNING
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Ok(false);
    }
    let _worker = Worker;
    let context = env
        .call_method(
            &context,
            jni::jni_str!("getApplicationContext"),
            jni::jni_sig!(() -> android.content.Context),
            &[],
        )?
        .l()?;
    rustls_platform_verifier::android::init_with_env(env, context)?;
    let clear = Zeroizing::new(env.convert_byte_array(&enrollment)?);
    let event = event.mutf8_chars(env)?;
    let Ok(event) = serde_json::from_str::<Value>(&event.to_str()) else {
        return Ok(false);
    };
    let Ok(enrollment) = serde_json::from_slice::<Enrollment>(&clear) else {
        return Ok(false);
    };
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return Ok(false);
    };
    let acknowledged = runtime.block_on(super::transport::decline(enrollment, event));
    // DNS resolution can use a blocking task. Dropping a runtime normally waits
    // for it, which would exceed the BroadcastReceiver's bounded lifetime.
    runtime.shutdown_background();
    Ok(acknowledged)
}
