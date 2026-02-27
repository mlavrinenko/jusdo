use std::io::{self, Write};
use std::ops::ControlFlow;
use std::path::Path;
use std::process;

use crate::client;
use crate::commands::util::require_just;
use crate::config::Config;
use crate::error::Error;
use crate::protocol::{self, Request, Response};

/// Run the `run` subcommand: ask the daemon to execute `just`.
///
/// Streams stdout/stderr in real time as the daemon sends lines.
///
/// # Errors
///
/// Returns an error if `just` is not installed, the path is invalid,
/// the daemon is unreachable, or the daemon denies the request.
pub fn execute(config: &Config, justfile: &Path, args: Vec<String>) -> Result<(), Error> {
    require_just()?;

    let canonical = justfile
        .canonicalize()
        .map_err(|_| Error::JustfileNotFound(justfile.to_path_buf()))?;

    let request = Request::Run {
        justfile: canonical,
        args,
    };

    let mut stream = client::connect(config)?;
    protocol::send(&mut stream, &request)?;

    let mut final_code: Option<i32> = None;

    protocol::recv_each::<Response, _>(&stream, |response| {
        handle_streamed_response(response, &mut final_code)
    })?;

    if let Some(code) = final_code
        && code != 0
    {
        process::exit(code);
    }

    Ok(())
}

/// Process a single streamed response from the daemon.
///
/// Updates `final_code` when the stream ends (Exit or Error).
/// Returns [`ControlFlow::Continue`] for output lines,
/// [`ControlFlow::Break`] for terminal messages.
pub(crate) fn handle_streamed_response(
    response: Response,
    final_code: &mut Option<i32>,
) -> ControlFlow<()> {
    match response {
        Response::OutputLine { stream, line } => {
            let _ = if stream.as_str() == "stderr" {
                let mut err = io::stderr();
                let _ = writeln!(err, "{line}");
                err.flush()
            } else {
                let mut out = io::stdout();
                let _ = writeln!(out, "{line}");
                out.flush()
            };
            ControlFlow::Continue(())
        }
        Response::Exit { exit_code } => {
            *final_code = Some(exit_code);
            ControlFlow::Break(())
        }
        Response::Error { message } => {
            eprintln!("Error: {message}");
            *final_code = Some(1);
            ControlFlow::Break(())
        }
        _ => ControlFlow::Break(()),
    }
}

#[cfg(test)]
mod tests {
    use std::ops::ControlFlow;

    use crate::protocol::Response;

    use super::handle_streamed_response;

    #[test]
    fn output_line_stdout_continues() {
        let mut code = None;
        let resp = Response::OutputLine {
            stream: String::from("stdout"),
            line: String::from("hello"),
        };
        let flow = handle_streamed_response(resp, &mut code);
        assert!(matches!(flow, ControlFlow::Continue(())));
        assert!(code.is_none());
    }

    #[test]
    fn output_line_stderr_continues() {
        let mut code = None;
        let resp = Response::OutputLine {
            stream: String::from("stderr"),
            line: String::from("warning"),
        };
        let flow = handle_streamed_response(resp, &mut code);
        assert!(matches!(flow, ControlFlow::Continue(())));
        assert!(code.is_none());
    }

    #[test]
    fn exit_zero_breaks_with_code() {
        let mut code = None;
        let resp = Response::Exit { exit_code: 0 };
        let flow = handle_streamed_response(resp, &mut code);
        assert!(matches!(flow, ControlFlow::Break(())));
        assert_eq!(code, Some(0));
    }

    #[test]
    fn exit_nonzero_breaks_with_code() {
        let mut code = None;
        let resp = Response::Exit { exit_code: 42 };
        let flow = handle_streamed_response(resp, &mut code);
        assert!(matches!(flow, ControlFlow::Break(())));
        assert_eq!(code, Some(42));
    }

    #[test]
    fn error_response_sets_code_one() {
        let mut code = None;
        let resp = Response::Error {
            message: String::from("denied"),
        };
        let flow = handle_streamed_response(resp, &mut code);
        assert!(matches!(flow, ControlFlow::Break(())));
        assert_eq!(code, Some(1));
    }

    #[test]
    fn unexpected_response_breaks() {
        let mut code = None;
        let resp = Response::Revoked;
        let flow = handle_streamed_response(resp, &mut code);
        assert!(matches!(flow, ControlFlow::Break(())));
    }
}
