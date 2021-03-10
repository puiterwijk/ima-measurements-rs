use fallible_iterator::FallibleIterator;
use serde::Serialize;
use std::{env, fs::File};
use thiserror::Error;

use ima_measurements::{Event, Parser, PcrValues};

#[derive(Debug, Error)]
enum ToolError {
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Error parsing measurement log: {0}")]
    EventLog(#[from] ima_measurements::Error),
    #[error("YAML Error: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

#[derive(Debug, Serialize)]
struct Results {
    events: Vec<Event>,
    pcr_values: PcrValues,
}

fn main() -> Result<(), ToolError> {
    let mut args = env::args();
    // Ignore our binary name
    args.next();

    for filename in args {
        let file = File::open(&filename)?;
        let mut parser = Parser::new(file);
        let mut events: Vec<Event> = Vec::new();

        while let Some(event) = parser.next()? {
            events.push(event);
        }

        let pcr_values = parser.pcr_values();

        serde_yaml::to_writer(std::io::stdout(), &Results { events, pcr_values })?;
    }

    Ok(())
}
