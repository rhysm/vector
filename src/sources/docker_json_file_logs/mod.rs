//! This mod implements `kubernetes_logs` source.
//! The scope of this source is to consume the log files that a kubelet keeps
//! at "/var/log/pods" on the host of the Kubernetes Node when Vector itself is
//! running inside the cluster as a DaemonSet.

#![deny(missing_docs)]

mod docker_parser;
mod partial_events_merger;

use std::{path::PathBuf, time::Duration};
use crate::sources::docker_json_file_logs::docker_parser::DockerParser;
use bytes::Bytes;
use chrono::Utc;
use futures::{future::FutureExt, stream::StreamExt};
use futures_util::{Stream, TryFutureExt};
use glob::MatchOptions;
use serde_with::serde_as;
use tokio::task::spawn_blocking;
use tracing::{Instrument, Span};
use vector_lib::codecs::{BytesDeserializer, BytesDeserializerConfig};
use vector_lib::configurable::configurable_component;
use vector_lib::file_source::{
    calculate_ignore_before, Checkpointer, FileServer, FingerprintStrategy,
    Fingerprinter, Line, ReadFrom, ReadFromConfig,
};
use vector_lib::lookup::{lookup_v2::OptionalTargetPath, owned_value_path, path, OwnedTargetPath};
use vector_lib::{config::LegacyKey, config::LogNamespace};
use vector_lib::{
    TimeZone,
};
use vrl::value::{kind::Collection, Kind};
use vector_lib::file_source::paths_provider::glob::Glob;

use crate::{
    config::{
        log_schema, ComponentKey, DataType, GlobalOptions, SourceConfig,
        SourceContext, SourceOutput,
    },
    event::Event,
    internal_events::{
        FileInternalMetricsConfig, FileSourceInternalEventsEmitter, StreamClosedError,
    },
    shutdown::ShutdownSignal,
    sources,
    SourceSender,
};
use crate::sources::docker_json_file_logs::partial_events_merger::merge_partial_events;
use crate::transforms::{FunctionTransform, OutputBuffer};

/// Configuration for the `kubernetes_logs` source.
#[serde_as]
#[configurable_component(source("docker_json_file_logs", "Collect logs from docker json-files."))]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields, default)]
pub struct DockerJsonFileLogsConfig {
    /// Array of file patterns to include. [Globbing](https://vector.dev/docs/reference/configuration/sources/file/#globbing) is supported.
    #[configurable(metadata(docs::examples = "/var/log/**/*.log"))]
    pub include: Vec<PathBuf>,

    /// Array of file patterns to exclude. [Globbing](https://vector.dev/docs/reference/configuration/sources/file/#globbing) is supported.
    ///
    /// Takes precedence over the `include` option. Note: The `exclude` patterns are applied _after_ the attempt to glob everything
    /// in `include`. This means that all files are first matched by `include` and then filtered by the `exclude`
    /// patterns. This can be impactful if `include` contains directories with contents that are not accessible.
    #[serde(default)]
    #[configurable(metadata(docs::examples = "/var/log/binary-file.log"))]
    pub exclude: Vec<PathBuf>,

    /// Whether or not to automatically merge partial events.
    ///
    /// Partial events are messages that were split by the Kubernetes Container Runtime
    /// log driver.
    auto_partial_merge: bool,

    /// The directory used to persist file checkpoint positions.
    ///
    /// By default, the [global `data_dir` option][global_data_dir] is used.
    /// Make sure the running user has write permissions to this directory.
    ///
    /// If this directory is specified, then Vector will attempt to create it.
    ///
    /// [global_data_dir]: https://vector.dev/docs/reference/configuration/global-options/#data_dir
    #[configurable(metadata(docs::examples = "/var/local/lib/vector/"))]
    #[configurable(metadata(docs::human_name = "Data Directory"))]
    data_dir: Option<PathBuf>,

    #[configurable(derived)]
    #[serde(default = "default_read_from")]
    read_from: ReadFromConfig,

    /// Ignore files with a data modification date older than the specified number of seconds.
    #[serde(default)]
    #[configurable(metadata(docs::type_unit = "seconds"))]
    #[configurable(metadata(docs::examples = 600))]
    #[configurable(metadata(docs::human_name = "Ignore Files Older Than"))]
    ignore_older_secs: Option<u64>,

    /// Max amount of bytes to read from a single file before switching over to the next file.
    /// **Note:** This does not apply when `oldest_first` is `true`.
    ///
    /// This allows distributing the reads more or less evenly across
    /// the files.
    #[configurable(metadata(docs::type_unit = "bytes"))]
    max_read_bytes: usize,

    /// Instead of balancing read capacity fairly across all watched files, prioritize draining the oldest files before moving on to read data from more recent files.
    #[serde(default = "default_oldest_first")]
    pub oldest_first: bool,

    /// The maximum number of bytes a line can contain before being discarded.
    ///
    /// This protects against malformed lines or tailing incorrect files.
    #[configurable(metadata(docs::type_unit = "bytes"))]
    max_line_bytes: usize,

    /// The number of lines to read for generating the checksum.
    ///
    /// If your files share a common header that is not always a fixed size,
    ///
    /// If the file has less than this amount of lines, it won’t be read at all.
    #[configurable(metadata(docs::type_unit = "lines"))]
    fingerprint_lines: usize,

    /// The interval at which the file system is polled to identify new files to read from.
    ///
    /// This is quite efficient, yet might still create some load on the
    /// file system; in addition, it is currently coupled with checksum dumping
    /// in the underlying file server, so setting it too low may introduce
    /// a significant overhead.
    #[serde_as(as = "serde_with::DurationMilliSeconds<u64>")]
    #[configurable(metadata(docs::human_name = "Glob Minimum Cooldown"))]
    glob_minimum_cooldown_ms: Duration,

    /// Overrides the name of the log field used to add the ingestion timestamp to each event.
    ///
    /// This is useful to compute the latency between important event processing
    /// stages. For example, the time delta between when a log line was written and when it was
    /// processed by the `kubernetes_logs` source.
    #[configurable(metadata(docs::examples = ".ingest_timestamp", docs::examples = "ingest_ts"))]
    ingestion_timestamp_field: Option<OptionalTargetPath>,

    /// The default time zone for timestamps without an explicit zone.
    timezone: Option<TimeZone>,

    /// The namespace to use for logs. This overrides the global setting.
    #[configurable(metadata(docs::hidden))]
    #[serde(default)]
    log_namespace: Option<bool>,

    #[configurable(derived)]
    #[serde(default)]
    internal_metrics: FileInternalMetricsConfig,
}

const fn default_read_from() -> ReadFromConfig {
    ReadFromConfig::Beginning
}

impl_generate_config_from_default!(DockerJsonFileLogsConfig);

impl Default for DockerJsonFileLogsConfig {
    fn default() -> Self {
        Self {
            include: vec![PathBuf::from("/var/log/**/*.log")],
            exclude: vec![],
            auto_partial_merge: true,
            data_dir: None,
            read_from: default_read_from(),
            ignore_older_secs: None,
            max_read_bytes: default_max_read_bytes(),
            oldest_first: default_oldest_first(),
            max_line_bytes: default_max_line_bytes(),
            fingerprint_lines: default_fingerprint_lines(),
            glob_minimum_cooldown_ms: default_glob_minimum_cooldown_ms(),
            ingestion_timestamp_field: None,
            timezone: None,
            log_namespace: None,
            internal_metrics: Default::default(),
        }
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "docker_json_file_logs")]
impl SourceConfig for DockerJsonFileLogsConfig {
    async fn build(&self, cx: SourceContext) -> crate::Result<sources::Source> {
        let log_namespace = cx.log_namespace(self.log_namespace);
        let source = Source::new(self, &cx.globals, &cx.key).await?;

        Ok(Box::pin(
            source
                .run(cx.out, cx.shutdown, log_namespace)
                .map(|result| {
                    result.map_err(|error| {
                        error!(message = "Source future failed.", %error);
                    })
                }),
        ))
    }

    fn outputs(&self, global_log_namespace: LogNamespace) -> Vec<SourceOutput> {
        let log_namespace = global_log_namespace.merge(self.log_namespace);
        let schema_definition = BytesDeserializerConfig
            .schema_definition(log_namespace)
            .with_source_metadata(
                Self::NAME,
                Some(LegacyKey::Overwrite(owned_value_path!("file"))),
                &owned_value_path!("file"),
                Kind::bytes(),
                None,
            )
            .with_source_metadata(
                Self::NAME,
                Some(LegacyKey::Overwrite(owned_value_path!("label"))),
                &owned_value_path!("labels"),
                Kind::object(Collection::empty().with_unknown(Kind::bytes())).or_undefined(),
                None,
            )
            .with_source_metadata(
                Self::NAME,
                Some(LegacyKey::Overwrite(owned_value_path!("stream"))),
                &owned_value_path!("stream"),
                Kind::bytes(),
                None,
            )
            .with_source_metadata(
                Self::NAME,
                log_schema()
                    .timestamp_key()
                    .cloned()
                    .map(LegacyKey::Overwrite),
                &owned_value_path!("timestamp"),
                Kind::timestamp(),
                Some("timestamp"),
            )
            .with_standard_vector_source_metadata();

        vec![SourceOutput::new_logs(DataType::Log, schema_definition)]
    }

    fn can_acknowledge(&self) -> bool {
        false
    }
}

#[derive(Clone)]
struct Source {
    include: Vec<PathBuf>,
    exclude: Vec<PathBuf>,
    data_dir: PathBuf,
    auto_partial_merge: bool,
    read_from: ReadFrom,
    ignore_older_secs: Option<u64>,
    max_read_bytes: usize,
    oldest_first: bool,
    max_line_bytes: usize,
    fingerprint_lines: usize,
    glob_minimum_cooldown: Duration,
    ingestion_timestamp_field: Option<OwnedTargetPath>,
    include_file_metric_tag: bool,
}

impl Source {
    async fn new(
        config: &DockerJsonFileLogsConfig,
        globals: &GlobalOptions,
        key: &ComponentKey,
    ) -> crate::Result<Self> {
        let data_dir = globals.resolve_and_make_data_subdir(config.data_dir.as_ref(), key.id())?;

        let glob_minimum_cooldown = config.glob_minimum_cooldown_ms;

        let ingestion_timestamp_field = config
            .ingestion_timestamp_field
            .clone()
            .and_then(|k| k.path);

        Ok(Self {
            include: config.include.clone(),
            exclude: config.exclude.clone(),
            data_dir,
            auto_partial_merge: config.auto_partial_merge,
            read_from: ReadFrom::from(config.read_from),
            ignore_older_secs: config.ignore_older_secs,
            max_read_bytes: config.max_read_bytes,
            oldest_first: config.oldest_first,
            max_line_bytes: config.max_line_bytes,
            fingerprint_lines: config.fingerprint_lines,
            glob_minimum_cooldown,
            ingestion_timestamp_field,
            include_file_metric_tag: config.internal_metrics.include_file_tag,
        })
    }

    async fn run(
        self,
        mut out: SourceSender,
        global_shutdown: ShutdownSignal,
        log_namespace: LogNamespace,
    ) -> crate::Result<()> {
        let Self {
            include,
            exclude,
            data_dir,
            auto_partial_merge,
            read_from,
            ignore_older_secs,
            max_read_bytes,
            oldest_first,
            max_line_bytes,
            fingerprint_lines,
            glob_minimum_cooldown,
            ingestion_timestamp_field,
            include_file_metric_tag,
        } = self;
        let ignore_before = calculate_ignore_before(ignore_older_secs);

        let emitter = FileSourceInternalEventsEmitter {
            include_file_metric_tag,
        };
        let paths_provider = Glob::new(
            &include,
            &exclude,
            MatchOptions::default(),
            emitter.clone(),
        ).expect("invalid glob patterns");

        let checkpointer = Checkpointer::new(&data_dir);
        let file_server = FileServer {
            // Use our special paths provider.
            paths_provider,
            // Max amount of bytes to read from a single file before switching
            // over to the next file.
            // This allows distributing the reads more or less evenly across
            // the files.
            max_read_bytes,
            // We want to use checkpointing mechanism, and resume from where we
            // left off.
            ignore_checkpoints: false,
            // Match the default behavior
            read_from,
            // We're now aware of the use cases that would require specifying
            // the starting point in time since when we should collect the logs,
            // so we just disable it. If users ask, we can expose it. There may
            // be other, more sound ways for users considering the use of this
            // option to solve their use case, so take consideration.
            ignore_before,
            // The maximum number of bytes a line can contain before being discarded. This
            // protects against malformed lines or tailing incorrect files.
            max_line_bytes,
            // Delimiter bytes that is used to read the file line-by-line
            line_delimiter: Bytes::from("\n"),
            // The directory where to keep the checkpoints.
            data_dir,
            // This value specifies not exactly the globbing, but interval
            // between the polling the files to watch from the `paths_provider`.
            glob_minimum_cooldown,
            // The shape of the log files is well-known in the Kubernetes
            // environment, so we pick the a specially crafted fingerprinter
            // for the log files.
            fingerprinter: Fingerprinter {
                strategy: FingerprintStrategy::FirstLinesChecksum {
                    // Max line length to expect during fingerprinting, see the
                    // explanation above.
                    ignored_header_bytes: 0,
                    lines: fingerprint_lines,
                },
                max_line_length: max_line_bytes,
                ignore_not_found: true,
            },
            oldest_first,
            // We do not remove the log files, `kubelet` is responsible for it.
            remove_after: None,
            // The standard emitter.
            emitter: FileSourceInternalEventsEmitter {
                include_file_metric_tag,
            },
            // A handle to the current tokio runtime
            handle: tokio::runtime::Handle::current(),
        };

        let (file_source_tx, file_source_rx) = futures::channel::mpsc::channel::<Vec<Line>>(2);

        let checkpoints = checkpointer.view();
        let events = file_source_rx.flat_map(futures::stream::iter);
        let events = events.map(move |line| {
            let event = create_event(
                line.text,
                &line.filename,
                ingestion_timestamp_field.as_ref(),
                log_namespace,
            );

            checkpoints.update(line.file_id, line.end_offset);
            event
        });

        let mut parser = DockerParser::new(log_namespace);
        let events = events.flat_map(move |event| {
            let mut buf = OutputBuffer::with_capacity(1);
            parser.transform(&mut buf, event);
            futures::stream::iter(buf.into_events())
        });

        let (events_count, _) = events.size_hint();

        let stream = if auto_partial_merge {
            merge_partial_events(events, log_namespace).left_stream()
        } else {
            events.right_stream()
        };
        //let mut stream = events.right_stream();
        let span = Span::current();
        tokio::spawn(async move {
            match out
                .send_event_stream(stream)
                .instrument(span.or_current())
                .await
            {
                Ok(()) => {
                    debug!("Finished sending.");
                }
                Err(_) => {
                    emit!(StreamClosedError { count: events_count });
                }
            }
        });

        // let span = info_span!("file_server");
        // let join_handle = spawn_blocking(move || {
        //     // These will need to be separated when this source is updated
        //     // to support end-to-end acknowledgements.
        //     let shutdown = global_shutdown.shared();
        //     let shutdown2 = shutdown.clone();
        //     let _enter = span.enter();
        //     let result = file_server.run(file_source_tx, shutdown, shutdown2, checkpointer);
        //     result.expect("file server exited with an error")
        // });
        // join_handle.await
        //     .map(|result| match result {
        //         Ok(FileServerShutdown) => info!(message = "File server completed gracefully."),
        //         Err(error) => emit!(KubernetesLifecycleError {
        //                 message: "File server exited with an error.",
        //                 error,
        //                 count: 1,
        //             }),
        //     });
        let span = info_span!("file_server");
        let _ = spawn_blocking(move || {
            let _enter = span.enter();
            let result = file_server.run(file_source_tx, global_shutdown.clone().shared(), global_shutdown.clone(), checkpointer);
            //emit!(FileOpen { count: 0 });
            // Panic if we encounter any error originating from the file server.
            // We're at the `spawn_blocking` call, the panic will be caught and
            // passed to the `JoinHandle` error, similar to the usual threads.
            result.unwrap();
        })
            .map_err(|error| error!(message="File server unexpectedly stopped.", %error))
            .await;
        Ok(())

    }
}

fn create_event(
    line: Bytes,
    file: &str,
    ingestion_timestamp_field: Option<&OwnedTargetPath>,
    log_namespace: LogNamespace,
) -> Event {
    let deserializer = BytesDeserializer;
    let mut log = deserializer.parse_single(line, log_namespace);

    log_namespace.insert_source_metadata(
        DockerJsonFileLogsConfig::NAME,
        &mut log,
        Some(LegacyKey::Overwrite(path!("file"))),
        path!("file"),
        file,
    );

    match (log_namespace, ingestion_timestamp_field) {
        // When using LogNamespace::Vector always set the ingest_timestamp.
        (LogNamespace::Vector, _) => {
            log.metadata_mut()
                .value_mut()
                .insert(path!("vector", "ingest_timestamp"), Utc::now());
        }
        // When LogNamespace::Legacy, only set when the `ingestion_timestamp_field` is configured.
        (LogNamespace::Legacy, Some(ingestion_timestamp_field)) => {
            log.try_insert(ingestion_timestamp_field, Utc::now())
        }
        // The CRI/Docker parsers handle inserting the `log_schema().timestamp_key()` value.
        (LogNamespace::Legacy, None) => (),
    };

    log.into()
}

const fn default_max_read_bytes() -> usize {
    2048
}

// We'd like to consume rotated pod log files first to release our file handle and let
// the space be reclaimed
const fn default_oldest_first() -> bool {
    true
}

const fn default_max_line_bytes() -> usize {
    // NOTE: The below comment documents an incorrect assumption, see
    // https://github.com/vectordotdev/vector/issues/6967
    //
    // The 16KB is the maximum size of the payload at single line for both
    // docker and CRI log formats.
    // We take a double of that to account for metadata and padding, and to
    // have a power of two rounding. Line splitting is countered at the
    // parsers, see the `partial_events_merger` logic.

    32 * 1024 // 32 KiB
}

const fn default_glob_minimum_cooldown_ms() -> Duration {
    Duration::from_millis(5000)
}

const fn default_fingerprint_lines() -> usize {
    1
}

#[test]
fn generate_config() {
    crate::test_util::test_generate_config::<DockerJsonFileLogsConfig>();
}