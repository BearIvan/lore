use std::future::Future;
use std::pin::pin;

use tokio::sync::mpsc;

/// Drain a streaming producer into a `Vec` alongside a summary value for
/// callers that do not benefit from streaming.
///
/// The producer takes an `mpsc::Sender` and emits `Ok(T)` items as it goes,
/// returning `Ok(S)` on success (where `S` is some summary or metadata
/// value — use `()` when there is none) or `Err(E)` on failure. Runs the
/// producer concurrently with a receive loop in the same task via
/// `tokio::select!`, so there is no `tokio::spawn` and no `JoinError`.
/// When the producer completes first, the loop drains any remaining
/// buffered items before returning.
///
/// Returns `Ok((S, Vec<T>))` — the summary first, then every item the
/// producer emitted. First error wins: a producer error or an `Err(E)`
/// item short-circuits the drain and propagates up.
///
/// A producer that outlives the channel is awaited outside the `select!`, and
/// the items left once the producer finishes are drained after the loop, so the
/// loop holds no received item and only the drain holds the summary.
pub async fn collect_stream_with_summary<T, S, E, Fut>(
    f: impl FnOnce(mpsc::Sender<Result<T, E>>) -> Fut,
) -> Result<(S, Vec<T>), E>
where
    Fut: Future<Output = Result<S, E>>,
{
    let (tx, mut rx) = mpsc::channel(256);
    let mut driver = pin!(f(tx));
    let mut out = Vec::new();
    let summary = loop {
        let closed = tokio::select! {
            biased;
            item = rx.recv() => match item {
                Some(item) => {
                    out.push(item?);
                    false
                }
                None => true,
            },
            result = &mut driver => break result?,
        };
        if closed {
            break (&mut driver).await?;
        }
    };
    while let Some(item) = rx.recv().await {
        out.push(item?);
    }
    Ok((summary, out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn happy_path_emits_in_order() {
        let result: Result<((), Vec<u32>), ()> = collect_stream_with_summary(|tx| async move {
            for n in 0..10 {
                tx.send(Ok(n)).await.unwrap();
            }
            Ok(())
        })
        .await;
        assert_eq!(result.unwrap().1, (0..10).collect::<Vec<u32>>());
    }

    #[tokio::test]
    async fn empty_producer_yields_empty_vec() {
        let result: Result<((), Vec<u32>), ()> =
            collect_stream_with_summary(|_tx| async move { Ok(()) }).await;
        assert_eq!(result.unwrap().1, Vec::<u32>::new());
    }

    #[tokio::test]
    async fn item_error_short_circuits() {
        let result: Result<((), Vec<u32>), &'static str> =
            collect_stream_with_summary(|tx| async move {
                tx.send(Ok(1)).await.unwrap();
                tx.send(Err("nope")).await.unwrap();
                tx.send(Ok(2)).await.unwrap();
                Ok(())
            })
            .await;
        assert_eq!(result, Err("nope"));
    }

    #[tokio::test]
    async fn producer_error_propagates() {
        let result: Result<((), Vec<u32>), &'static str> =
            collect_stream_with_summary(|tx| async move {
                tx.send(Ok(1)).await.unwrap();
                Err("boom")
            })
            .await;
        assert_eq!(result, Err("boom"));
    }

    #[tokio::test]
    async fn drains_after_producer_finishes() {
        // Producer fills the channel and returns; the drain must collect
        // the remaining buffered items rather than dropping them.
        let result: Result<((), Vec<u32>), ()> = collect_stream_with_summary(|tx| async move {
            for n in 0..50 {
                tx.send(Ok(n)).await.unwrap();
            }
            Ok(())
        })
        .await;
        assert_eq!(result.unwrap().1, (0..50).collect::<Vec<u32>>());
    }

    #[tokio::test]
    async fn large_burst_exercises_channel_backpressure() {
        // Producer emits more items than the channel's capacity (256), so
        // `tx.send` must await the receiver between batches. The driver and
        // receiver share a task, so this proves the `tokio::select!` shape
        // makes progress on both branches without deadlock.
        let result: Result<((), Vec<u32>), ()> = collect_stream_with_summary(|tx| async move {
            for n in 0..1000 {
                tx.send(Ok(n)).await.unwrap();
            }
            Ok(())
        })
        .await;
        assert_eq!(result.unwrap().1, (0..1000).collect::<Vec<u32>>());
    }

    #[tokio::test]
    async fn producer_error_after_dropping_tx_still_yields_error() {
        // Producer drops the sender, yields once so the receive loop observes
        // the channel close, then returns an error. The driver's error must
        // win even though `rx.recv()` returned `None` first.
        let result: Result<((), Vec<u32>), &'static str> =
            collect_stream_with_summary(|tx| async move {
                drop(tx);
                tokio::task::yield_now().await;
                Err("boom")
            })
            .await;
        assert_eq!(result, Err("boom"));
    }

    #[tokio::test]
    async fn producer_error_after_items_still_yields_error() {
        // Producer emits a few items, then errors. The returned `Err`
        // takes priority over partial item accumulation; the caller does
        // not see a partial `Vec`.
        let result: Result<((), Vec<u32>), &'static str> =
            collect_stream_with_summary(|tx| async move {
                tx.send(Ok(1)).await.unwrap();
                tx.send(Ok(2)).await.unwrap();
                Err("boom")
            })
            .await;
        assert_eq!(result, Err("boom"));
    }

    #[tokio::test]
    async fn with_summary_returns_summary_and_items() {
        let result: Result<(&'static str, Vec<u32>), ()> =
            collect_stream_with_summary(|tx| async move {
                for n in 0..5 {
                    tx.send(Ok(n)).await.unwrap();
                }
                Ok("done")
            })
            .await;
        let (summary, items) = result.unwrap();
        assert_eq!(summary, "done");
        assert_eq!(items, vec![0, 1, 2, 3, 4]);
    }

    /// The drain holds no received item beside its producer, while it receives or while it awaits
    /// a producer that outlives the channel.
    #[test]
    fn the_drain_holds_no_item_beside_its_producer() {
        async fn produce(tx: mpsc::Sender<Result<[u8; 1024], ()>>) -> Result<(), ()> {
            tx.send(Ok([0; 1024])).await.map_err(|_closed| ())
        }

        let (tx, _rx) = mpsc::channel(1);
        let producer = size_of_val(&produce(tx));
        let drain = size_of_val(&collect_stream_with_summary(produce));

        assert!(
            drain < producer + size_of::<[u8; 1024]>(),
            "the drain holds {drain} bytes over a producer of {producer}"
        );
    }

    #[tokio::test]
    async fn with_summary_producer_error_propagates() {
        let result: Result<(&'static str, Vec<u32>), &'static str> =
            collect_stream_with_summary(|tx| async move {
                tx.send(Ok(1)).await.unwrap();
                Err("boom")
            })
            .await;
        assert_eq!(result, Err("boom"));
    }
}
