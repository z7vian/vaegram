// Run with `cargo test --test live_w4_privacy -- --ignored`; see tests/support/mod.rs for the env.
// Live behaviour is unverified: these tests have not been run.

#[allow(dead_code)] // this binary drives only the user half of the kit
mod support;

use vaegram::Client;
use vaegram::enums::BlockList;

async fn user() -> Option<Client> {
    Some(support::Kit::from_env().await?.user.client)
}

fn env_id(name: &str) -> Option<i64> {
    let id = std::env::var(name).ok().and_then(|v| v.parse().ok());
    if id.is_none() {
        eprintln!("skipped: set {name}");
    }
    id
}

#[tokio::test]
#[ignore]
async fn mute_until_reads_back() {
    let (Some(user), Some(chat)) = (user().await, env_id("VAEGRAM_CHAT_ID")) else { return };
    let until = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600) as i32;
    user.mute_chat(chat).mute_until(until).await.unwrap();
    let muted = user.get_chat_notifications(chat).await.unwrap();
    user.unmute_chat(chat).await.unwrap();
    assert_eq!(muted.mute_until, Some(until));
}

#[tokio::test]
#[ignore]
async fn stories_block_list_round_trip() {
    let (Some(user), Some(target)) = (user().await, env_id("VAEGRAM_BLOCK_TEST_USER")) else { return };
    user.block_user(target).list(BlockList::Stories).await.unwrap();
    let blocked = user.get_blocked_message_senders(0, 100).list(BlockList::Stories).await.unwrap();
    user.unblock_user(target).list(BlockList::Stories).await.unwrap();
    assert!(blocked.iter().any(|chat| chat.id == target));
}

#[tokio::test]
#[ignore]
async fn owned_bot_photo_can_be_removed() {
    let (Some(user), Some(bot)) = (user().await, env_id("VAEGRAM_OWNED_BOT")) else { return };
    user.remove_bot_profile_photo(bot).await.unwrap();
}
