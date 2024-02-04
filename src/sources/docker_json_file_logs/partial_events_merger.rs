#![deny(missing_docs)]

use bytes::BytesMut;
use futures::{Stream, StreamExt};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use vector_lib::config::LogNamespace;
use vector_lib::lookup::OwnedTargetPath;
use vector_lib::stream::expiration_map::{map_with_expiration, Emitter};
use vrl::owned_value_path;
use crate::event;
use crate::event::{Event, LogEvent, Value};
use crate::sources::docker_json_file_logs::docker_parser::get_message_path;

/// The key we use for `file` field.
const FILE_KEY: &str = "file";

const EXPIRATION_TIME: Duration = Duration::from_secs(30);

struct PartialEventMergeState {
    buckets: HashMap<String, Bucket>,
}

impl PartialEventMergeState {
    fn add_event(
        &mut self,
        event: LogEvent,
        file: &str,
        message_path: &OwnedTargetPath,
        expiration_time: Duration,
    ) {
        if let Some(bucket) = self.buckets.get_mut(file) {
            // merging with existing event

            if let (Some(Value::Bytes(prev_value)), Some(Value::Bytes(new_value))) =
                (bucket.event.get_mut(message_path), event.get(message_path))
            {
                let mut bytes_mut = BytesMut::new();
                bytes_mut.extend_from_slice(prev_value);
                bytes_mut.extend_from_slice(new_value);
                *prev_value = bytes_mut.freeze();
            }
        } else {
            // new event
            self.buckets.insert(
                file.to_owned(),
                Bucket {
                    event,
                    expiration: Instant::now() + expiration_time,
                },
            );
        }
    }

    fn remove_event(&mut self, file: &str) -> Option<LogEvent> {
        self.buckets.remove(file).map(|bucket| bucket.event)
    }

    fn emit_expired_events(&mut self, emitter: &mut Emitter<LogEvent>) {
        let now = Instant::now();
        self.buckets.retain(|_key, bucket| {
            let expired = now >= bucket.expiration;
            if expired {
                emitter.emit(bucket.event.clone());
            }
            !expired
        });
    }

    fn flush_events(&mut self, emitter: &mut Emitter<LogEvent>) {
        for (_, bucket) in self.buckets.drain() {
            emitter.emit(bucket.event);
        }
    }
}

struct Bucket {
    event: LogEvent,
    expiration: Instant,
}

pub fn merge_partial_events(
    stream: impl Stream<Item = Event> + 'static,
    log_namespace: LogNamespace,
) -> impl Stream<Item = Event> {
    merge_partial_events_with_custom_expiration(stream, log_namespace, EXPIRATION_TIME)
}

// internal function that allows customizing the expiration time (for testing)
fn merge_partial_events_with_custom_expiration(
    stream: impl Stream<Item = Event> + 'static,
    log_namespace: LogNamespace,
    expiration_time: Duration,
) -> impl Stream<Item = Event> {
    let partial_flag_path = match log_namespace {
        LogNamespace::Vector => {
            OwnedTargetPath::metadata(owned_value_path!(super::DockerJsonFileLogsConfig::NAME, event::PARTIAL))
        }
        LogNamespace::Legacy => OwnedTargetPath::event(owned_value_path!(event::PARTIAL)),
    };

    let file_path = match log_namespace {
        LogNamespace::Vector => {
            OwnedTargetPath::metadata(owned_value_path!(super::DockerJsonFileLogsConfig::NAME, FILE_KEY))
        }
        LogNamespace::Legacy => OwnedTargetPath::event(owned_value_path!(FILE_KEY)),
    };

    let state = PartialEventMergeState {
        buckets: HashMap::new(),
    };

    let message_path = get_message_path(log_namespace);

    map_with_expiration(
        state,
        stream.map(|e| e.into_log()),
        Duration::from_secs(1),
        move |state: &mut PartialEventMergeState,
              event: LogEvent,
              emitter: &mut Emitter<LogEvent>| {
            // called for each event
            let is_partial = event
                .get(&partial_flag_path)
                .and_then(|x| x.as_boolean())
                .unwrap_or(false);

            let file = event
                .get(&file_path)
                .and_then(|x| x.as_str())
                .map(|x| x.to_string())
                .unwrap_or_default();

            state.add_event(event, &file, &message_path, expiration_time);
            if !is_partial {
                if let Some(log_event) = state.remove_event(&file) {
                    emitter.emit(log_event);
                }
            }
        },
        |state: &mut PartialEventMergeState, emitter: &mut Emitter<LogEvent>| {
            // check for expired events
            state.emit_expired_events(emitter)
        },
        |state: &mut PartialEventMergeState, emitter: &mut Emitter<LogEvent>| {
            // the source is ending, flush all pending events
            state.flush_events(emitter);
        },
    )
    // LogEvent -> Event
    .map(|e| e.into())
}