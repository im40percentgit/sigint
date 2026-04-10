//! Deterministic 80/20 train/test split for training examples.
//!
//! Splitting is based on a hash of each example's session_id so that all
//! examples from the same session end up in the same partition. This prevents
//! data leakage where a model sees context from a session during training and
//! is then evaluated on a different tool call from the same session.
//!
//! @decision DEC-TRAIN-004
//! @title Session-based 80/20 split using session_id hash, not example index
//! @status accepted
//! @rationale Index-based splits would put early tool calls in train and later
//! ones in test, which is misleading (the model would see early context from
//! the same scan during training). Session-based splitting ensures the model
//! is genuinely evaluated on unseen scans. The hash is deterministic so the
//! same dataset always produces the same split.

use crate::TrainingExample;

/// Split examples into (train, test) partitions using an 80/20 ratio.
///
/// Partitioning is deterministic: given the same input slice, the output is
/// always identical. Examples from the same session_id always land in the
/// same partition to prevent cross-contamination.
pub fn train_test_split(
    examples: &[TrainingExample],
) -> (Vec<TrainingExample>, Vec<TrainingExample>) {
    let mut train = Vec::new();
    let mut test = Vec::new();

    for example in examples {
        if session_in_train(&example.session_id) {
            train.push(example.clone());
        } else {
            test.push(example.clone());
        }
    }

    (train, test)
}

/// Return true if this session_id should go into the training set (80%).
///
/// Uses the first 8 bytes of the UUID as a u64, then checks modulo 10.
/// Sessions where hash % 10 < 8 → train (80%); otherwise → test (20%).
fn session_in_train(session_id: &uuid::Uuid) -> bool {
    let bytes = session_id.as_bytes();
    let hash = u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    hash % 10 < 8
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TrainingMessage};
    use uuid::Uuid;

    fn make_example(session_id: Uuid) -> TrainingExample {
        TrainingExample {
            session_id,
            messages: vec![TrainingMessage {
                role: "system".to_string(),
                content: Some("test".to_string()),
                tool_calls: None,
                tool_call_id: None,
            }],
        }
    }

    #[test]
    fn split_is_deterministic() {
        let examples: Vec<TrainingExample> = (0..20).map(|_| make_example(Uuid::new_v4())).collect();

        let (train1, test1) = train_test_split(&examples);
        let (train2, test2) = train_test_split(&examples);

        assert_eq!(train1.len(), train2.len());
        assert_eq!(test1.len(), test2.len());

        for (a, b) in train1.iter().zip(train2.iter()) {
            assert_eq!(a.session_id, b.session_id);
        }
    }

    #[test]
    fn split_partitions_all_examples() {
        let examples: Vec<TrainingExample> = (0..100).map(|_| make_example(Uuid::new_v4())).collect();
        let (train, test) = train_test_split(&examples);
        assert_eq!(train.len() + test.len(), 100);
    }

    #[test]
    fn split_roughly_80_20() {
        // With 1000 random UUIDs the split should be within ±5% of 80/20.
        let examples: Vec<TrainingExample> = (0..1000).map(|_| make_example(Uuid::new_v4())).collect();
        let (train, test) = train_test_split(&examples);

        let train_pct = train.len() as f64 / 1000.0;
        assert!(
            (0.75..=0.85).contains(&train_pct),
            "train% should be ~80%, got {:.1}%",
            train_pct * 100.0
        );
        let _ = test; // test gets the remainder
    }

    #[test]
    fn same_session_always_in_same_partition() {
        let session_id = Uuid::new_v4();
        // Three examples from the same session — all must land in the same partition.
        let examples: Vec<TrainingExample> = vec![
            make_example(session_id),
            make_example(session_id),
            make_example(session_id),
        ];
        let (train, test) = train_test_split(&examples);
        // Either all in train or all in test — never split across.
        assert!(
            train.len() == 3 || test.len() == 3,
            "all examples from same session must be in same partition"
        );
    }

    #[test]
    fn empty_input_produces_empty_output() {
        let (train, test) = train_test_split(&[]);
        assert!(train.is_empty());
        assert!(test.is_empty());
    }
}
