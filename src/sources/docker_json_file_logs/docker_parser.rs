use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use snafu::{OptionExt, ResultExt, Snafu};
use vrl::owned_value_path;
use vector_lib::config::{LegacyKey, LogNamespace};
use crate::sources::docker_json_file_logs::DockerJsonFileLogsConfig;
use vector_lib::lookup::{self, path, OwnedTargetPath};

use crate::{
    config::log_schema,
    event::{self, Event, LogEvent, Value},
    internal_events::KubernetesLogsDockerFormatParseError,
    transforms::{FunctionTransform, OutputBuffer},
};

pub const MESSAGE_KEY: &str = "log";
pub const STREAM_KEY: &str = "stream";
pub const TIMESTAMP_KEY: &str = "time";
pub const ATTRS_KEY: &str = "attrs";

/// Parser for the Docker log format.
///
/// Expects logs to arrive in a JSONLines format with the fields names and
/// contents specific to the implementation of the Docker `json-file` log driver.
///
/// Normalizes parsed data for consistency.
#[derive(Clone, Debug)]
pub(super) struct DockerParser {
    log_namespace: LogNamespace,
}

impl DockerParser {
    pub const fn new(log_namespace: LogNamespace) -> Self {
        Self { log_namespace }
    }
}

impl FunctionTransform for DockerParser {
    fn transform(&mut self, output: &mut OutputBuffer, mut event: Event) {
        let log = event.as_mut_log();
        if let Err(err) = parse_json(log, self.log_namespace) {
            emit!(KubernetesLogsDockerFormatParseError { error: &err });
            return;
        }
        if let Err(err) = normalize_event(log, self.log_namespace) {
            emit!(KubernetesLogsDockerFormatParseError { error: &err });
            return;
        }
        output.push(event);
    }
}

pub fn get_message_path(log_namespace: LogNamespace) -> OwnedTargetPath {
    match log_namespace {
        LogNamespace::Vector => OwnedTargetPath::event(owned_value_path!()),
        LogNamespace::Legacy => OwnedTargetPath::event(
            log_schema()
                .message_key()
                .expect("global log_schema.message_key to be valid path")
                .clone(),
        ),
    }
}


/// Parses `message` as json object and removes it.
fn parse_json(log: &mut LogEvent, log_namespace: LogNamespace) -> Result<(), ParsingError> {
    let target_path = get_message_path(log_namespace);

    let value = log
        .remove(&target_path)
        .ok_or(ParsingError::NoMessageField)?;

    let bytes = match value {
        Value::Bytes(bytes) => bytes,
        _ => return Err(ParsingError::MessageFieldNotInBytes),
    };

    match serde_json::from_slice(bytes.as_ref()) {
        Ok(JsonValue::Object(object)) => {
            for (key, value) in object {
                match key.as_str() {
                    MESSAGE_KEY => drop(log.insert(&target_path, value)),
                    STREAM_KEY => log_namespace.insert_source_metadata(
                        DockerJsonFileLogsConfig::NAME,
                        log,
                        Some(LegacyKey::Overwrite(path!(STREAM_KEY))),
                        path!(STREAM_KEY),
                        value,
                    ),
                    TIMESTAMP_KEY => log_namespace.insert_source_metadata(
                        DockerJsonFileLogsConfig::NAME,
                        log,
                        log_schema().timestamp_key().map(LegacyKey::Overwrite),
                        path!("timestamp"),
                        value,
                    ),
                    ATTRS_KEY => {
                        for (key, label_val) in value.as_object().unwrap() {
                            log_namespace.insert_source_metadata(
                                DockerJsonFileLogsConfig::NAME,
                                log,
                                Some(LegacyKey::Overwrite(path!("label", key))),
                                path!("labels", key),
                                label_val.clone(),
                            )
                        }
                    },
                    _ => unreachable!("all json-file keys should be matched"),
                };
            }
            Ok(())
        }
        Ok(_) => Err(ParsingError::NotAnObject { message: bytes }),
        Err(err) => Err(ParsingError::InvalidJson {
            source: err,
            message: bytes,
        }),
    }
}

const DOCKER_MESSAGE_SPLIT_THRESHOLD: usize = 16 * 1024; // 16 Kib

fn normalize_event(
    log: &mut LogEvent,
    log_namespace: LogNamespace,
) -> Result<(), NormalizationError> {
    // Parse timestamp.
    let timestamp_key = match log_namespace {
        LogNamespace::Vector => Some(OwnedTargetPath::metadata(lookup::owned_value_path!(
            "kubernetes_logs",
            "timestamp"
        ))),
        LogNamespace::Legacy => log_schema()
            .timestamp_key()
            .map(|path| OwnedTargetPath::event(path.clone())),
    };

    if let Some(timestamp_key) = timestamp_key {
        let time = log.remove(&timestamp_key).context(TimeFieldMissingSnafu)?;

        let time = match time {
            Value::Bytes(val) => val,
            _ => return Err(NormalizationError::TimeValueUnexpectedType),
        };
        let time = DateTime::parse_from_rfc3339(String::from_utf8_lossy(time.as_ref()).as_ref())
            .context(TimeParsingSnafu)?;
        log_namespace.insert_source_metadata(
            DockerJsonFileLogsConfig::NAME,
            log,
            log_schema().timestamp_key().map(LegacyKey::Overwrite),
            path!("timestamp"),
            time.with_timezone(&Utc),
        );
    }

    // Parse message, remove trailing newline and detect if it's partial.
    let message_path = get_message_path(log_namespace);
    let message = log.remove(&message_path).context(LogFieldMissingSnafu)?;
    let mut message = match message {
        Value::Bytes(val) => val,
        _ => return Err(NormalizationError::LogValueUnexpectedType),
    };
    // Here we apply out heuristics to detect if message is partial.
    // Partial messages are only split in docker at the maximum message length
    // (`DOCKER_MESSAGE_SPLIT_THRESHOLD`).
    // Thus, for a message to be partial it also has to have exactly that
    // length.
    // Now, whether that message will or won't actually be partial if it has
    // exactly the max length is unknown. We consider all messages with the
    // exact length of `DOCKER_MESSAGE_SPLIT_THRESHOLD` bytes partial
    // by default, and then, if they end with newline - consider that
    // an exception and make them non-partial.
    // This is still not ideal, and can potentially be improved.
    let mut is_partial = message.len() == DOCKER_MESSAGE_SPLIT_THRESHOLD;
    if message.last().map(|&b| b as char == '\n').unwrap_or(false) {
        message.truncate(message.len() - 1);
        is_partial = false;
    };
    log.insert(&message_path, message);

    // For partial messages add a partial event indicator.
    if is_partial {
        log_namespace.insert_source_metadata(
            DockerJsonFileLogsConfig::NAME,
            log,
            Some(LegacyKey::Overwrite(path!(event::PARTIAL))),
            path!(event::PARTIAL),
            true,
        );
    }

    Ok(())
}

#[derive(Debug, Snafu)]
enum ParsingError {
    NoMessageField,
    MessageFieldNotInBytes,
    #[snafu(display(
        "Could not parse json: {} in message {:?}",
        source,
        String::from_utf8_lossy(message)
    ))]
    InvalidJson {
        source: serde_json::Error,
        message: Bytes,
    },
    #[snafu(display("Message was not an object: {:?}", String::from_utf8_lossy(message)))]
    NotAnObject {
        message: Bytes,
    },
}

#[derive(Debug, Snafu)]
enum NormalizationError {
    TimeFieldMissing,
    TimeValueUnexpectedType,
    TimeParsing { source: chrono::ParseError },
    LogFieldMissing,
    LogValueUnexpectedType,
}