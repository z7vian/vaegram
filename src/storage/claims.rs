//! Who owns a username or phone number that several peers name: the one updated last, the larger id on a tie.
//! Engines that index names by key use this, so the owner doesn't depend on the order records were written in.

use std::collections::HashMap;
use std::hash::Hash;

use super::PeerRecord;

/// The newest claim, as `(updated, id)`, a batch of peers makes on each key `keys` names for a peer.
pub(crate) fn claims<'a, K, I>(
    batch: impl IntoIterator<Item = &'a PeerRecord>,
    keys: impl Fn(&'a PeerRecord) -> I,
) -> HashMap<K, (i64, i64)>
where
    K: Eq + Hash,
    I: IntoIterator<Item = K>,
{
    let mut claims = HashMap::new();
    for p in batch {
        for key in keys(p) {
            let claim = claims.entry(key).or_insert((p.updated, p.id));
            *claim = (*claim).max((p.updated, p.id));
        }
    }
    claims
}

/// Who ends up with a key: the batch's claim or the holder outside the batch, `(updated, id)` each, whichever is
/// newer. `None` means nobody keeps it.
pub(crate) fn owner(claim: Option<(i64, i64)>, holder: Option<(i64, i64)>) -> Option<i64> {
    claim.max(holder).map(|(_, id)| id)
}

#[cfg(test)]
mod tests {
    use super::{claims, owner};
    use crate::storage::PeerRecord;

    fn peer(id: i64, updated: i64, names: &[&str]) -> PeerRecord {
        let mut p = PeerRecord::new(id, 0);
        (p.updated, p.usernames) = (updated, names.iter().map(|n| n.to_string()).collect());
        p
    }

    #[test]
    fn the_newest_claim_wins_and_ties_go_to_the_larger_id() {
        let batch = [peer(1, 10, &["a", "b"]), peer(2, 20, &["a"]), peer(3, 10, &["b"])];
        let claims = claims(&batch, |p| p.usernames.iter().map(String::as_str));
        assert_eq!((claims["a"], claims["b"]), ((20, 2), (10, 3)));
        assert_eq!(claims.len(), 2);
        let reversed = super::claims(batch.iter().rev(), |p| p.usernames.iter().map(String::as_str));
        assert_eq!(reversed, claims, "the order the peers came in doesn't matter");
    }

    #[test]
    fn a_newer_holder_outside_the_batch_keeps_the_key() {
        assert_eq!(owner(Some((10, 1)), Some((20, 9))), Some(9));
        assert_eq!(owner(Some((20, 1)), Some((10, 9))), Some(1));
        assert_eq!(owner(Some((10, 1)), Some((10, 9))), Some(9), "a tie goes to the larger id");
        assert_eq!(owner(None, Some((5, 9))), Some(9));
        assert_eq!(owner(None, None), None, "a key nobody claims goes");
    }
}
