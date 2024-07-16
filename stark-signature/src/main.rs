use std::time::Instant;

use rand::thread_rng;
use rand_utils::rand_array;
use stark_signature::{SecretKey, Signature};
#[cfg(feature = "std")]
use tracing::info_span;
#[cfg(feature = "tracing-forest")]
use tracing_forest::ForestLayer;
#[cfg(not(feature = "tracing-forest"))]
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use utils::{Deserializable, Serializable};

// EXAMPLE RUNNER
// ================================================================================================

fn main() {
    // configure logging
    if std::env::var("WINTER_LOG").is_err() {
        std::env::set_var("WINTER_LOG", "info");
    }
    let registry =
        tracing_subscriber::registry::Registry::default().with(EnvFilter::from_env("WINTER_LOG"));

    #[cfg(feature = "tracing-forest")]
    registry.with(ForestLayer::default()).init();

    #[cfg(not(feature = "tracing-forest"))]
    {
        let format = tracing_subscriber::fmt::layer()
            .with_level(false)
            .with_target(false)
            .with_thread_names(false)
            .with_span_events(FmtSpan::CLOSE)
            .with_ansi(false)
            .with_timer(tracing_subscriber::fmt::time::SystemTime)
            .compact();

        registry.with(format).init();
    }

    let mut rng = thread_rng();
    let sk = SecretKey::generate_secret_key(&mut rng);

    let message = rand_array();

    let pk = sk.compute_public_key();

    // generate signature
    let now = Instant::now();
    let signature = info_span!("signing").in_scope(|| sk.sign(message));
    println!("---------------------\nSignature generated in {} ms", now.elapsed().as_millis());

    let signature_bytes = signature.to_bytes();

    // verify the signature
    println!("---------------------");
    println!("Signature size: {:.1} KB", signature_bytes.len() as f64 / 1024f64);
    let parsed_signature = Signature::read_from_bytes(&signature_bytes).unwrap();
    println!("---------------------\n Security level {}", signature.security_level());
    assert_eq!(signature, parsed_signature);
    let now = Instant::now();
    if pk.verify(message, &signature) {
        println!("Signature verified in {:.1} ms", now.elapsed().as_micros() as f64 / 1000f64)
    } else {
        println!("Failed to verify signature")
    }
}
