// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::mpsc::Sender;
use std::time::Duration;
use std::time::Instant;

use bytes::Bytes;
use lore_base::lore_trace;
use quinn::Chunk;
use zerocopy::IntoBytes;

use crate::quic::command_header::COMMAND_HEADER_SIZE_V4;
use crate::quic::command_header::CommandHeader;

#[derive(Debug)]
pub struct QuicMessage {
    pub header: CommandHeader,
    pub payload: Option<Bytes>,
}

pub enum ChunkingMetric {
    Stall(Duration),
    PendingChunks(usize),
}

pub struct SerialChunking {
    header_size: usize,
    max_chunk_size: u32,

    request: CommandHeader,
    payload: Option<bytes::BytesMut>,
    request_bytes: [u8; COMMAND_HEADER_SIZE_V4],
    request_bytes_read: usize,
    current_offset: u64,
    pending_chunks: Vec<Chunk>,

    metrics: Option<Sender<ChunkingMetric>>,
    stall_start: Instant,
}

impl SerialChunking {
    pub fn new(
        header_size: usize,
        max_chunk_size: usize,
        metrics: Option<Sender<ChunkingMetric>>,
    ) -> Self {
        debug_assert!(header_size <= COMMAND_HEADER_SIZE_V4);

        SerialChunking {
            header_size,
            max_chunk_size: max_chunk_size as u32,
            request: CommandHeader::default(),
            payload: None,
            request_bytes: [0u8; COMMAND_HEADER_SIZE_V4],
            request_bytes_read: 0,
            current_offset: 0,
            pending_chunks: vec![],
            metrics,
            stall_start: Instant::now(),
        }
    }

    /// Frames whatever messages the chunk completes, appending them to `messages`.
    ///
    /// The buffer belongs to the caller so a stream can keep one across its read loop: a chunk
    /// carrying several messages then costs no allocation in steady state.
    ///
    /// Returns the offending header if one declares a payload larger than the chunk size cap,
    /// which is fatal to the stream.
    pub fn resolve_into(
        &mut self,
        new_chunk: Chunk,
        messages: &mut Vec<QuicMessage>,
    ) -> Result<(), CommandHeader> {
        let mut pending_chunk_change = None;

        let mut next_chunk = Some(new_chunk);
        while let Some(mut chunk) = next_chunk.take() {
            if chunk.offset == self.current_offset {
                while !chunk.bytes.is_empty() {
                    if self.request_bytes_read < self.header_size {
                        // Read the request header
                        if chunk.bytes.len() + self.request_bytes_read < self.header_size {
                            let got_count = chunk.bytes.len();
                            self.request_bytes
                                [self.request_bytes_read..(self.request_bytes_read + got_count)]
                                .copy_from_slice(chunk.bytes.as_ref());

                            self.request_bytes_read += got_count;
                            self.current_offset += got_count as u64;
                            chunk.bytes.clear();
                        } else {
                            let remain_count = self.header_size - self.request_bytes_read;
                            let remain_bytes = chunk.bytes.split_to(remain_count);

                            self.request_bytes[self.request_bytes_read..self.header_size]
                                .copy_from_slice(remain_bytes.as_ref());

                            self.request = if self.header_size == COMMAND_HEADER_SIZE_V4 {
                                CommandHeader::from_bytes_v4(self.request_bytes.as_bytes())
                            } else {
                                CommandHeader::from_bytes(self.request_bytes.as_bytes())
                            };
                            if self.request.size_or_status > self.max_chunk_size {
                                return Err(self.request);
                            }

                            self.request_bytes_read = self.header_size;
                            self.current_offset += remain_count as u64;

                            lore_trace!("QUIC stream read request header {:?}", self.request);

                            // If error there is no more data, otherwise allocate buffer for response payload
                            if !self.request.error && self.request.size_or_status > 0 {
                                if chunk.bytes.len() >= self.request.size_or_status as usize {
                                    // Happy path, we can directly use buffer as it contains the full request
                                    let size = self.request.size_or_status as usize;
                                    let current_payload = chunk.bytes.split_to(size);

                                    self.current_offset += size as u64;

                                    lore_trace!(
                                        "QUIC stream read {} bytes complete payload from single chunk",
                                        size
                                    );

                                    self.request_bytes_read = 0;
                                    messages.push(QuicMessage {
                                        header: self.request,
                                        payload: Some(current_payload),
                                    });
                                } else {
                                    // Allocate buffer for request payload
                                    self.payload = Some(bytes::BytesMut::with_capacity(
                                        self.request.size_or_status as usize,
                                    ));
                                }
                            } else {
                                self.request_bytes_read = 0;
                                messages.push(QuicMessage {
                                    header: self.request,
                                    payload: None,
                                });
                            }
                        }
                    }
                    if let Some(mut current_payload) = self.payload.take() {
                        let size = std::cmp::min(
                            current_payload.capacity() - current_payload.len(),
                            chunk.bytes.len(),
                        );

                        let this_chunk = chunk.bytes.split_to(size);
                        current_payload.extend_from_slice(this_chunk.as_bytes());

                        self.current_offset += size as u64;

                        lore_trace!(
                            "QUIC stream read {} bytes for a total of {} / {} bytes of payload",
                            size,
                            current_payload.len(),
                            current_payload.capacity()
                        );

                        if current_payload.capacity() == current_payload.len() {
                            self.request_bytes_read = 0;

                            messages.push(QuicMessage {
                                header: self.request,
                                payload: Some(current_payload.freeze()),
                            });
                        } else {
                            self.payload = Some(current_payload);
                        }
                    }
                }
            } else {
                // Queue for later processing
                lore_trace!(
                    "Got out of order chunk @ offset {}, current offset is {}",
                    chunk.offset,
                    self.current_offset
                );
                if self.pending_chunks.is_empty() {
                    self.stall_start = Instant::now();
                }
                self.pending_chunks.push(chunk);
                pending_chunk_change = Some(self.pending_chunks.len());
            }

            for (ichunk, chunk) in self.pending_chunks.iter().enumerate() {
                if chunk.offset == self.current_offset {
                    lore_trace!(
                        "Grab out of order chunk @ current offset {} - {} ooo chunks remaining",
                        self.current_offset,
                        self.pending_chunks.len() - 1
                    );
                    next_chunk = Some(self.pending_chunks.swap_remove(ichunk));
                    pending_chunk_change = Some(self.pending_chunks.len());
                    if self.pending_chunks.is_empty()
                        && let Some(metrics) = self.metrics.as_mut()
                    {
                        let _ = metrics.send(ChunkingMetric::Stall(self.stall_start.elapsed()));
                    }
                    break;
                }
            }
        }

        if let Some(pending_chunk_change) = pending_chunk_change
            && let Some(metrics) = self.metrics.as_mut()
        {
            let _ = metrics.send(ChunkingMetric::PendingChunks(pending_chunk_change));
        }

        Ok(())
    }
}
