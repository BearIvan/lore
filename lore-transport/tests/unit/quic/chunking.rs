// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT

use bytes::Bytes;
use lore_transport::quic::QuicServiceError;
use lore_transport::quic::RESERVED_ERROR_CODE_START;
use lore_transport::quic::chunking::ChunkingMetric;
use lore_transport::quic::chunking::QuicMessage;
use lore_transport::quic::chunking::SerialChunking;
use lore_transport::quic::command_header::COMMAND_HEADER_SIZE;
use lore_transport::quic::command_header::COMMAND_HEADER_SIZE_V4;
use lore_transport::quic::command_header::CommandHeader;
use quinn::Chunk;

const MAX_CHUNK: usize = 64 * 1024;

fn header_size(v4: bool) -> usize {
    if v4 {
        COMMAND_HEADER_SIZE_V4
    } else {
        COMMAND_HEADER_SIZE
    }
}

/// One message as it is written onto the wire, paired with the payload the chunker owes back.
#[derive(Clone, Debug)]
struct WireMessage {
    header: CommandHeader,
    payload: Vec<u8>,
}

impl WireMessage {
    fn success(cmd: u8, command_id: u32, session_id: u32, v4: bool, payload: Vec<u8>) -> Self {
        WireMessage {
            header: CommandHeader {
                cmd,
                error: false,
                size_or_status: payload.len() as u32,
                command_id,
                session_id,
                v4,
            },
            payload,
        }
    }

    fn failure(cmd: u8, command_id: u32, session_id: u32, v4: bool, status: u32) -> Self {
        WireMessage {
            header: CommandHeader {
                cmd,
                error: true,
                size_or_status: status,
                command_id,
                session_id,
                v4,
            },
            payload: vec![],
        }
    }

    fn encode(&self, into: &mut Vec<u8>) {
        if self.header.v4 {
            into.extend_from_slice(&self.header.to_bytes_v4());
        } else {
            into.extend_from_slice(&self.header.to_bytes());
        }
        // On an error header the size field is a status code, so no payload follows it.
        if !self.header.error {
            into.extend_from_slice(&self.payload);
        }
    }
}

/// Message flattened for comparison. Derives `Ord` so a set of messages can be compared
/// without depending on the order the chunker emitted them in.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Flat {
    command_id: u32,
    cmd: u8,
    error: bool,
    size_or_status: u32,
    session_id: u32,
    v4: bool,
    payload: Option<Vec<u8>>,
}

fn flatten_expected(message: &WireMessage) -> Flat {
    let carries_payload = !message.header.error && message.header.size_or_status > 0;
    Flat {
        command_id: message.header.command_id,
        cmd: message.header.cmd,
        error: message.header.error,
        size_or_status: message.header.size_or_status,
        session_id: message.header.session_id,
        v4: message.header.v4,
        payload: carries_payload.then(|| message.payload.clone()),
    }
}

fn flatten_actual(message: &QuicMessage) -> Flat {
    Flat {
        command_id: message.header.command_id,
        cmd: message.header.cmd,
        error: message.header.error,
        size_or_status: message.header.size_or_status,
        session_id: message.header.session_id,
        v4: message.header.v4,
        payload: message.payload.as_ref().map(|payload| payload.to_vec()),
    }
}

fn into_chunks(stream: &[u8], chunk_size: usize) -> Vec<Chunk> {
    stream
        .chunks(chunk_size)
        .enumerate()
        .map(|(index, bytes)| Chunk {
            offset: (index * chunk_size) as u64,
            bytes: Bytes::copy_from_slice(bytes),
        })
        .collect()
}

#[derive(Clone, Copy, Debug)]
enum Arrival {
    InOrder,
    Reversed,
    OddsThenEvens,
    Shuffled,
}

const ARRIVALS: [Arrival; 4] = [
    Arrival::InOrder,
    Arrival::Reversed,
    Arrival::OddsThenEvens,
    Arrival::Shuffled,
];

/// Seed for the one permutation `Arrival::Shuffled` samples. Fixed, so the exhaustive sweep
/// stays reproducible.
const SHUFFLE_SEED: u64 = 0x2545_f491_4f6c_dd1d;

fn reorder(chunks: &mut Vec<Chunk>, arrival: Arrival) {
    match arrival {
        Arrival::InOrder => {}
        Arrival::Reversed => chunks.reverse(),
        Arrival::OddsThenEvens => {
            let mut slots: Vec<Option<Chunk>> = chunks.drain(..).map(Some).collect();
            for start in [1, 0] {
                let mut index = start;
                while index < slots.len() {
                    if let Some(chunk) = slots[index].take() {
                        chunks.push(chunk);
                    }
                    index += 2;
                }
            }
        }
        Arrival::Shuffled => {
            shuffle(&mut Chaos::new(SHUFFLE_SEED), chunks);
        }
    }
}

/// One chunk's worth of output, for the tests that step chunk by chunk.
fn resolve_one(
    chunker: &mut SerialChunking,
    chunk: Chunk,
) -> Result<Vec<QuicMessage>, CommandHeader> {
    let mut messages = Vec::new();
    chunker.resolve_into(chunk, &mut messages)?;
    Ok(messages)
}

fn feed(chunker: &mut SerialChunking, chunks: Vec<Chunk>) -> Vec<QuicMessage> {
    let mut messages = vec![];
    for chunk in chunks {
        chunker
            .resolve_into(chunk, &mut messages)
            .expect("chunk accepted");
    }
    messages
}

/// Payload shapes that between them cover every branch the chunker takes: absent, a single
/// byte, exactly one header wide, wider than any single chunk under test, and repeated
/// payload-free messages back to back.
fn mixed_stream(v4: bool) -> Vec<WireMessage> {
    let session = |id: u32| if v4 { id } else { 0 };
    vec![
        WireMessage::success(1, 1, session(7), v4, vec![]),
        WireMessage::success(2, 2, session(7), v4, vec![0xaa]),
        WireMessage::failure(3, 3, session(7), v4, QuicServiceError::NotFound as u32),
        WireMessage::success(4, 4, session(9), v4, (0..=255u8).collect()),
        WireMessage::failure(5, 5, session(9), v4, QuicServiceError::SlowDown as u32),
        WireMessage::failure(6, 6, session(9), v4, RESERVED_ERROR_CODE_START),
        WireMessage::success(7, 7, session(0), v4, vec![0x5a; COMMAND_HEADER_SIZE_V4]),
        WireMessage::success(8, 8, session(1), v4, vec![]),
        WireMessage::success(9, 9, session(2), v4, vec![]),
        WireMessage::success(10, 10, session(3), v4, vec![0xff; 700]),
        WireMessage::success(11, 11, session(4), v4, vec![0x01, 0x02, 0x03]),
    ]
}

/// Compares two sets of messages already sorted by command id, reporting the first field that
/// differs rather than dumping whole payloads.
fn assert_same_messages(actual: &[Flat], expected: &[Flat], case: &str) {
    assert_eq!(actual.len(), expected.len(), "{case}: message count");

    for (got, want) in actual.iter().zip(expected) {
        assert_eq!(got.command_id, want.command_id, "{case}: command id");

        let command_id = want.command_id;
        assert_eq!(got.cmd, want.cmd, "{case}: command {command_id} opcode");
        assert_eq!(got.error, want.error, "{case}: command {command_id} error");
        assert_eq!(
            got.size_or_status, want.size_or_status,
            "{case}: command {command_id} size or status"
        );
        assert_eq!(
            got.session_id, want.session_id,
            "{case}: command {command_id} session id"
        );
        assert_eq!(got.v4, want.v4, "{case}: command {command_id} header width");
        assert_eq!(
            got.payload.is_some(),
            want.payload.is_some(),
            "{case}: command {command_id} payload presence"
        );

        if let (Some(got_payload), Some(want_payload)) = (&got.payload, &want.payload) {
            assert_eq!(
                got_payload.len(),
                want_payload.len(),
                "{case}: command {command_id} payload length"
            );

            let first_difference = got_payload
                .iter()
                .zip(want_payload)
                .position(|(got_byte, want_byte)| got_byte != want_byte);
            assert!(
                first_difference.is_none(),
                "{case}: command {command_id} payload differs at byte {first_difference:?}"
            );
        }
    }
}

/// xorshift64*, so a chaos case reproduces exactly from the seed the failure reports.
struct Chaos(u64);

impl Chaos {
    fn new(seed: u64) -> Self {
        // A zero state is a fixed point for xorshift and would emit nothing but zeroes.
        Chaos(if seed == 0 { 1 } else { seed })
    }

    fn next(&mut self) -> u64 {
        let mut state = self.0;
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        self.0 = state;
        state.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() >> 33) as usize % bound
    }
}

/// Fisher-Yates. Shared so a fix reaches both the fixed-seed arrival and the chaos one.
fn shuffle(chaos: &mut Chaos, chunks: &mut [Chunk]) {
    for index in (1..chunks.len()).rev() {
        chunks.swap(index, chaos.below(index + 1));
    }
}

/// Randomized message mixture. Command ids are sequential and unique so the sorted comparison
/// pairs each emitted message with the one it was built from.
fn chaos_messages(
    chaos: &mut Chaos,
    count: usize,
    v4: bool,
    max_payload: usize,
) -> Vec<WireMessage> {
    (0..count)
        .map(|index| {
            let command_id = index as u32 + 1;
            let cmd = chaos.below(256) as u8;
            let session_id = if v4 { chaos.next() as u32 } else { 0 };

            if chaos.below(4) == 0 {
                let status = chaos.below(300) as u32;
                return WireMessage::failure(cmd, command_id, session_id, v4, status);
            }

            // Weighted towards the small sizes, where the header and payload boundaries
            // interleave most densely, while still reaching payloads spanning many chunks.
            let size = match chaos.below(8) {
                0 => 0,
                1 => 1,
                2 => chaos.below(16),
                _ => chaos.below(max_payload),
            };
            let payload = (0..size).map(|_| chaos.next() as u8).collect();
            WireMessage::success(cmd, command_id, session_id, v4, payload)
        })
        .collect()
}

/// Cuts the stream at random boundaries, each chunk between one byte and `read_cap` - the
/// bound production reads under.
fn into_random_chunks(chaos: &mut Chaos, stream: &[u8], read_cap: usize) -> Vec<Chunk> {
    let mut chunks = vec![];
    let mut offset = 0;

    while offset < stream.len() {
        let size = 1 + chaos.below(read_cap.min(stream.len() - offset));
        let end = offset + size;
        chunks.push(Chunk {
            offset: offset as u64,
            bytes: Bytes::copy_from_slice(&stream[offset..end]),
        });
        offset = end;
    }

    chunks
}

#[derive(Clone, Copy, Debug)]
enum ChaosArrival {
    InOrder,
    /// Swaps only within a short window, the reordering a real network produces.
    NearbySwaps,
    FullShuffle,
}

fn deliver(chaos: &mut Chaos, chunks: &mut [Chunk], arrival: ChaosArrival) {
    match arrival {
        ChaosArrival::InOrder => {}
        ChaosArrival::NearbySwaps => {
            for index in 0..chunks.len() {
                let reach = (chunks.len() - index).min(4);
                let target = index + chaos.below(reach);
                chunks.swap(index, target);
            }
        }
        ChaosArrival::FullShuffle => shuffle(chaos, chunks),
    }
}

mod serial_chunking_new {
    use super::*;

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "header_size <= COMMAND_HEADER_SIZE_V4")]
    fn header_wider_than_the_staging_buffer_is_rejected() {
        SerialChunking::new(COMMAND_HEADER_SIZE_V4 + 1, MAX_CHUNK, None);
    }

    #[test]
    fn widest_supported_header_is_accepted() {
        let mut chunker = SerialChunking::new(COMMAND_HEADER_SIZE_V4, MAX_CHUNK, None);
        let message = WireMessage::success(1, 1, 5, true, vec![0x01]);
        let mut stream = vec![];
        message.encode(&mut stream);

        let messages = feed(&mut chunker, into_chunks(&stream, stream.len()));

        assert_eq!(
            messages.iter().map(flatten_actual).collect::<Vec<_>>(),
            vec![flatten_expected(&message)]
        );
    }
}

mod resolve {
    use super::*;

    /// The headline property: the chunker reproduces exactly the set of messages written onto
    /// the wire, for every chunk size from one byte upwards and every arrival order. Emission
    /// order is deliberately not asserted, so both sides are sorted before comparison.
    #[test]
    fn mixed_stream_round_trips_under_every_split_and_arrival_order() {
        for v4 in [false, true] {
            let messages = mixed_stream(v4);
            let mut stream = vec![];
            for message in &messages {
                message.encode(&mut stream);
            }

            let mut expected: Vec<Flat> = messages.iter().map(flatten_expected).collect();
            expected.sort();

            for chunk_size in 1..=stream.len() {
                for arrival in ARRIVALS {
                    let mut chunker = SerialChunking::new(header_size(v4), MAX_CHUNK, None);
                    let mut chunks = into_chunks(&stream, chunk_size);
                    reorder(&mut chunks, arrival);

                    let mut actual: Vec<Flat> = feed(&mut chunker, chunks)
                        .iter()
                        .map(flatten_actual)
                        .collect();
                    actual.sort();

                    assert_eq!(
                        actual, expected,
                        "v4 {v4}, chunk size {chunk_size}, {arrival:?}"
                    );
                }
            }
        }
    }

    const CHAOS_SEEDS: [u64; 8] = [
        0x0000_0000_0000_0001,
        0xdead_beef_cafe_f00d,
        0x1234_5678_9abc_def0,
        0xffff_ffff_ffff_ffff,
        0x5555_aaaa_5555_aaaa,
        0x0f1e_2d3c_4b5a_6978,
        0x8000_0000_0000_0000,
        0x0123_4567_89ab_cdef,
    ];

    /// Chaos at volume: a few thousand messages of randomized shape per case, cut at random
    /// chunk boundaries and delivered with the local reordering a real network produces. Every
    /// input message must come back out. The seed is reported on failure so a case reproduces.
    #[test]
    fn chaos_large_mixture_reconstructs_every_message() {
        const MESSAGE_COUNT: usize = 3000;
        const MAX_PAYLOAD: usize = 8192;
        const READ_CAP: usize = 1400;
        const CHUNK_CAP: usize = 16384;

        for seed in CHAOS_SEEDS {
            for v4 in [false, true] {
                let mut chaos = Chaos::new(seed);
                let messages = chaos_messages(&mut chaos, MESSAGE_COUNT, v4, MAX_PAYLOAD);

                let mut stream = vec![];
                for message in &messages {
                    message.encode(&mut stream);
                }

                let mut expected: Vec<Flat> = messages.iter().map(flatten_expected).collect();
                expected.sort();

                for arrival in [ChaosArrival::InOrder, ChaosArrival::NearbySwaps] {
                    let mut chunks = into_random_chunks(&mut chaos, &stream, READ_CAP);
                    deliver(&mut chaos, &mut chunks, arrival);

                    let mut chunker = SerialChunking::new(header_size(v4), CHUNK_CAP, None);
                    let mut actual: Vec<Flat> = feed(&mut chunker, chunks)
                        .iter()
                        .map(flatten_actual)
                        .collect();
                    actual.sort();

                    assert_same_messages(
                        &actual,
                        &expected,
                        &format!(
                            "seed {seed:#018x}, v4 {v4}, {arrival:?}, {} bytes",
                            stream.len()
                        ),
                    );
                }
            }
        }
    }

    /// The same property under total reordering, where every chunk but the first has to be
    /// queued before anything can be assembled. Smaller than the volume case above because
    /// the chunker rescans its whole pending queue per arriving chunk.
    #[test]
    fn chaos_full_shuffle_reconstructs_every_message() {
        const MESSAGE_COUNT: usize = 1200;
        const MAX_PAYLOAD: usize = 2048;
        const READ_CAP: usize = 256;
        const CHUNK_CAP: usize = 4096;

        for seed in CHAOS_SEEDS {
            for v4 in [false, true] {
                let mut chaos = Chaos::new(seed);
                let messages = chaos_messages(&mut chaos, MESSAGE_COUNT, v4, MAX_PAYLOAD);

                let mut stream = vec![];
                for message in &messages {
                    message.encode(&mut stream);
                }

                let mut chunks = into_random_chunks(&mut chaos, &stream, READ_CAP);
                deliver(&mut chaos, &mut chunks, ChaosArrival::FullShuffle);

                let mut chunker = SerialChunking::new(header_size(v4), CHUNK_CAP, None);
                let mut actual: Vec<Flat> = feed(&mut chunker, chunks)
                    .iter()
                    .map(flatten_actual)
                    .collect();
                actual.sort();

                let mut expected: Vec<Flat> = messages.iter().map(flatten_expected).collect();
                expected.sort();

                assert_same_messages(
                    &actual,
                    &expected,
                    &format!("seed {seed:#018x}, v4 {v4}, {} bytes", stream.len()),
                );
            }
        }
    }

    #[test]
    fn message_and_payload_arriving_in_one_chunk() {
        let mut chunker = SerialChunking::new(COMMAND_HEADER_SIZE, MAX_CHUNK, None);
        let message = WireMessage::success(9, 4, 0, false, vec![0xde, 0xad, 0xbe, 0xef]);
        let mut stream = vec![];
        message.encode(&mut stream);

        let messages = feed(&mut chunker, into_chunks(&stream, stream.len()));

        assert_eq!(
            messages.iter().map(flatten_actual).collect::<Vec<_>>(),
            vec![flatten_expected(&message)]
        );
    }

    #[test]
    fn zero_length_payload_yields_no_payload() {
        let mut chunker = SerialChunking::new(COMMAND_HEADER_SIZE, MAX_CHUNK, None);
        let message = WireMessage::success(3, 1, 0, false, vec![]);
        let mut stream = vec![];
        message.encode(&mut stream);

        let messages = feed(&mut chunker, into_chunks(&stream, stream.len()));

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].header.size_or_status, 0);
        assert!(messages[0].payload.is_none());
    }

    /// An error header's size field is a status code, so the chunker must not read payload
    /// bytes for it - the next bytes on the wire belong to the following message.
    #[test]
    fn error_header_yields_its_status_and_consumes_no_payload() {
        let mut chunker = SerialChunking::new(COMMAND_HEADER_SIZE, MAX_CHUNK, None);
        let failed = WireMessage::failure(2, 1, 0, false, QuicServiceError::NotFound as u32);
        let followed = WireMessage::success(3, 2, 0, false, vec![0x77; 5]);
        let mut stream = vec![];
        failed.encode(&mut stream);
        followed.encode(&mut stream);

        let messages = feed(&mut chunker, into_chunks(&stream, stream.len()));

        assert_eq!(
            messages.iter().map(flatten_actual).collect::<Vec<_>>(),
            vec![flatten_expected(&failed), flatten_expected(&followed)]
        );
    }

    #[test]
    fn header_split_one_byte_per_chunk() {
        let mut chunker = SerialChunking::new(COMMAND_HEADER_SIZE, MAX_CHUNK, None);
        let message = WireMessage::success(5, 3, 0, false, vec![]);
        let mut stream = vec![];
        message.encode(&mut stream);

        let chunks = into_chunks(&stream, 1);
        let (last, leading) = chunks.split_last().expect("header splits into chunks");
        for chunk in leading {
            let partial = resolve_one(
                &mut chunker,
                Chunk {
                    offset: chunk.offset,
                    bytes: chunk.bytes.clone(),
                },
            )
            .expect("partial header accepted");
            assert!(partial.is_empty(), "no message before the header completes");
        }

        let messages = resolve_one(
            &mut chunker,
            Chunk {
                offset: last.offset,
                bytes: last.bytes.clone(),
            },
        )
        .expect("final header byte accepted");

        assert_eq!(
            messages.iter().map(flatten_actual).collect::<Vec<_>>(),
            vec![flatten_expected(&message)]
        );
    }

    /// Payload bytes are concatenated in stream order even though message emission order is
    /// not part of the contract.
    #[test]
    fn payload_split_across_chunks_keeps_its_byte_order() {
        let mut chunker = SerialChunking::new(COMMAND_HEADER_SIZE, MAX_CHUNK, None);
        let payload: Vec<u8> = (0..=255u8).collect();
        let message = WireMessage::success(6, 1, 0, false, payload.clone());
        let mut stream = vec![];
        message.encode(&mut stream);

        let messages = feed(&mut chunker, into_chunks(&stream, 7));

        assert_eq!(messages.len(), 1);
        let got = messages[0].payload.as_ref().expect("payload present");
        assert_eq!(got.as_ref(), payload.as_slice());
    }

    #[test]
    fn several_messages_in_one_chunk_are_all_emitted() {
        let mut chunker = SerialChunking::new(COMMAND_HEADER_SIZE, MAX_CHUNK, None);
        let messages = vec![
            WireMessage::success(1, 1, 0, false, vec![0x01]),
            WireMessage::success(2, 2, 0, false, vec![]),
            WireMessage::failure(3, 3, 0, false, QuicServiceError::Failed as u32),
            WireMessage::success(4, 4, 0, false, vec![0x02, 0x03]),
        ];
        let mut stream = vec![];
        for message in &messages {
            message.encode(&mut stream);
        }

        let resolved = feed(&mut chunker, into_chunks(&stream, stream.len()));

        assert_eq!(
            resolved.iter().map(flatten_actual).collect::<Vec<_>>(),
            messages.iter().map(flatten_expected).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_chunk_past_the_gap_is_held_until_the_gap_is_filled() {
        let mut chunker = SerialChunking::new(COMMAND_HEADER_SIZE, MAX_CHUNK, None);
        let message = WireMessage::success(1, 1, 0, false, vec![0x42; 24]);
        let mut stream = vec![];
        message.encode(&mut stream);

        let chunks = into_chunks(&stream, 8);
        let (first, rest) = chunks.split_first().expect("stream splits into chunks");

        for chunk in rest {
            let held = resolve_one(
                &mut chunker,
                Chunk {
                    offset: chunk.offset,
                    bytes: chunk.bytes.clone(),
                },
            )
            .expect("out of order chunk accepted");
            assert!(held.is_empty(), "nothing emitted while offset 0 is missing");
        }

        let messages = resolve_one(
            &mut chunker,
            Chunk {
                offset: first.offset,
                bytes: first.bytes.clone(),
            },
        )
        .expect("gap-filling chunk accepted");

        assert_eq!(
            messages.iter().map(flatten_actual).collect::<Vec<_>>(),
            vec![flatten_expected(&message)]
        );
    }

    #[test]
    fn payload_larger_than_the_chunk_cap_is_rejected() {
        const CAP: usize = 64;
        let mut chunker = SerialChunking::new(COMMAND_HEADER_SIZE, CAP, None);
        let message = WireMessage::success(7, 12, 0, false, vec![0x00; CAP + 1]);
        let mut stream = vec![];
        message.encode(&mut stream);

        let rejected = resolve_one(
            &mut chunker,
            Chunk {
                offset: 0,
                bytes: Bytes::copy_from_slice(&stream),
            },
        )
        .expect_err("payload over the cap is rejected");

        assert_eq!(rejected.command_id, 12);
        assert_eq!(rejected.cmd, 7);
        assert_eq!(rejected.size_or_status, CAP as u32 + 1);
    }

    #[test]
    fn payload_exactly_at_the_chunk_cap_is_accepted() {
        const CAP: usize = 64;
        let mut chunker = SerialChunking::new(COMMAND_HEADER_SIZE, CAP, None);
        let message = WireMessage::success(7, 12, 0, false, vec![0x31; CAP]);
        let mut stream = vec![];
        message.encode(&mut stream);

        let messages = feed(&mut chunker, into_chunks(&stream, 16));

        assert_eq!(
            messages.iter().map(flatten_actual).collect::<Vec<_>>(),
            vec![flatten_expected(&message)]
        );
    }

    #[test]
    fn wide_header_carries_the_session_id() {
        let mut chunker = SerialChunking::new(COMMAND_HEADER_SIZE_V4, MAX_CHUNK, None);
        let message = WireMessage::success(1, 1, 0xabcd, true, vec![0x09]);
        let mut stream = vec![];
        message.encode(&mut stream);

        let messages = feed(&mut chunker, into_chunks(&stream, stream.len()));

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].header.session_id, 0xabcd);
        assert!(messages[0].header.v4);
    }

    #[test]
    fn narrow_header_reports_no_session_id() {
        let mut chunker = SerialChunking::new(COMMAND_HEADER_SIZE, MAX_CHUNK, None);
        let message = WireMessage::success(1, 1, 0, false, vec![0x09]);
        let mut stream = vec![];
        message.encode(&mut stream);

        let messages = feed(&mut chunker, into_chunks(&stream, stream.len()));

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].header.session_id, 0);
        assert!(!messages[0].header.v4);
    }

    #[test]
    fn out_of_order_arrival_reports_the_queue_depth_and_one_stall() {
        let (sender, receiver) = std::sync::mpsc::channel();
        let mut chunker = SerialChunking::new(COMMAND_HEADER_SIZE, MAX_CHUNK, Some(sender));
        let message = WireMessage::success(1, 1, 0, false, vec![0x11; 24]);
        let mut stream = vec![];
        message.encode(&mut stream);

        let chunks = into_chunks(&stream, 8);
        let (first, rest) = chunks.split_first().expect("stream splits into chunks");
        for chunk in rest {
            resolve_one(
                &mut chunker,
                Chunk {
                    offset: chunk.offset,
                    bytes: chunk.bytes.clone(),
                },
            )
            .expect("out of order chunk accepted");
        }
        resolve_one(
            &mut chunker,
            Chunk {
                offset: first.offset,
                bytes: first.bytes.clone(),
            },
        )
        .expect("gap-filling chunk accepted");

        let mut depths = vec![];
        let mut stalls = 0;
        while let Ok(metric) = receiver.try_recv() {
            match metric {
                ChunkingMetric::PendingChunks(depth) => depths.push(depth),
                ChunkingMetric::Stall(_) => stalls += 1,
            }
        }

        assert_eq!(depths, vec![1, 2, 3, 0]);
        assert_eq!(stalls, 1, "one stall spanning the whole queued period");
    }

    #[test]
    fn in_order_arrival_reports_no_metrics() {
        let (sender, receiver) = std::sync::mpsc::channel();
        let mut chunker = SerialChunking::new(COMMAND_HEADER_SIZE, MAX_CHUNK, Some(sender));
        let message = WireMessage::success(1, 1, 0, false, vec![0x11; 24]);
        let mut stream = vec![];
        message.encode(&mut stream);

        feed(&mut chunker, into_chunks(&stream, 8));

        assert!(receiver.try_recv().is_err(), "no stall or queue to report");
    }
}
