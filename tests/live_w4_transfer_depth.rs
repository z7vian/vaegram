use sha2::{Digest, Sha256};
use vaegram::Client;
use vaegram::types::Upload;

#[tokio::test]
#[ignore = "uses a logged-in user session; uploads and downloads 50 MiB in Saved Messages"]
async fn round_trip_50mib_sha256() {
    let Ok(session) = std::env::var("VAEGRAM_USER_SESSION") else {
        eprintln!("skipped: set VAEGRAM_USER_SESSION (a logged-in session name)");
        return;
    };
    let env = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("set {k}"));
    let user = Client::builder(session, env("VAEGRAM_API_ID").parse().unwrap(), env("VAEGRAM_API_HASH"))
        .connect()
        .await
        .unwrap();

    let data: Vec<u8> = (0..50u32 << 20).map(|i| (i * 7 + i / 251) as u8).collect();
    let sent = user.send_document("me", Upload::bytes("vaegram-50mib.bin", &data)).await.unwrap();
    let downloaded = sent.download().await;
    sent.delete().await.unwrap();
    assert_eq!(Sha256::digest(downloaded.unwrap()), Sha256::digest(&data));
}
