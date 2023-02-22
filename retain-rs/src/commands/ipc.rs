use crate::commands::{Command, Response};
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

const HANDSHAKE_IDENTIFIER: &str = "Test";

/// Message-oriented wrapper for a TcpStream
/// Sends and receives (UTF-8) strings, delimited by 0x4 End-Of-Transmission bytes
pub struct IPCConnection {
    client: BufReader<TcpStream>,
}

enum ReceiveError {
    EmptyReply,
    Timeout,
    IOError(String),
}

impl Display for ReceiveError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&match self {
            ReceiveError::EmptyReply => "Empty reply".to_string(),
            ReceiveError::Timeout => "Connection timeout".to_string(),
            ReceiveError::IOError(msg) => msg.to_string(),
        })
    }
}

impl IPCConnection {
    /// Establish a two-way connection to the server process
    /// Since this is the only way to instantiate a client-side IPCConnection, it is guaranteed to have completed the handshake
    pub async fn connect_to_server() -> Result<Self, String> {
        // Determine the port it's using
        let mut portfile_location = std::env::temp_dir();
        portfile_location.push("retain-rs.port");
        let port = tokio::fs::read_to_string(portfile_location).await;
        // Attempt to connect
        let conn = match port {
            Ok(port) => {
                let port = match port.parse::<u16>() {
                    Ok(p) => p,
                    Err(_) => {
                        return Err("Invalid port number in retain.port".to_string());
                    }
                };
                match tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await {
                    Ok(stream) => {
                        let _ = stream.set_nodelay(true);
                        BufReader::new(stream)
                    }
                    Err(err) => {
                        return Err(format!("Failed to connect to server process - {}", err));
                    }
                }
            }
            Err(_) => {
                return Err("Failed to read retain.port -- Cannot connect to server".to_owned());
            }
        };
        let mut ipc = IPCConnection { client: conn };
        match ipc.client_handshake().await {
            Ok(_) => Ok(ipc),
            Err(err) => Err(err),
        }
    }

    /// Attempt to re-connect by creating a new connection and replacing `self` with the new instance
    async fn reconnect(&mut self) -> Result<(), String> {
        let conn = Self::connect_to_server().await?;
        self.client = conn.client;
        Ok(())
    }

    /// Attempt to send a message to the server
    /// This will retry _once per call_, since the server-side may hang up if we take too long
    // It seems the `raw_send_message` call succeeds, even if the server has closed dropped the `TcpStream`
    // As a result, we need to receive the response to be sure it actually even sent it
    // If we fail to read a valid response, we retry
    pub async fn send_command<T: AsRef<str>>(
        &mut self,
        command: Command,
        data: T,
    ) -> Result<(Response, String), String> {
        match self
            .raw_send_message(format!("{}|{}", command, &data.as_ref()))
            .await
        {
            Ok(_) => match self.receive_response(Duration::from_secs(5)).await {
                Ok(resp) => Ok(resp),
                Err(err) => {
                    eprintln!("Something went wrong, retrying ({err})");
                    self.reconnect().await?;
                    self.raw_send_message(format!("{}|{}", command, &data.as_ref()))
                        .await
                        .map_err(|err| format!("Sending message failed: {err:?}"))?;
                    self.receive_response(Duration::from_secs(5)).await
                }
            },
            Err(err) => Err(format!("Sending message failed: {}", err)),
        }
    }

    /// Attempt to send a message without any checks
    /// The server-side should always use this
    async fn raw_send_message<T: AsRef<str>>(&mut self, message: T) -> tokio::io::Result<()> {
        self.client
            .write_all(format!("{}\x04", message.as_ref()).as_bytes())
            .await
    }

    /// Receive a message from the client, timing out if the given duration elapses
    async fn receive_message(&mut self, timeout: Duration) -> Result<String, ReceiveError> {
        let mut buf = Vec::with_capacity(256);
        // Read until we get an EOT byte
        match tokio::time::timeout(timeout, self.client.read_until(0x4, &mut buf)).await {
            Ok(res) => match res {
                Ok(count) => {
                    if count == 0 {
                        return Err(ReceiveError::EmptyReply);
                    }
                }
                Err(err) => {
                    return Err(ReceiveError::IOError(format!("Read error: {err:?}")));
                }
            },
            Err(_) => {
                return Err(ReceiveError::Timeout);
            }
        }
        // Remove the EOT byte before parsing
        buf.pop().expect("Failed to pop EOT byte??");
        match String::from_utf8(buf) {
            Ok(s) => Ok(s),
            Err(err) => Err(ReceiveError::IOError(format!("Invalid UTF-8: {err:?}"))),
        }
    }

    /// Try to receive a command from the client
    pub async fn receive_command(
        &mut self,
        timeout: Duration,
    ) -> Result<(Command, String), String> {
        let message = self
            .receive_message(timeout)
            .await
            .map_err(|err| err.to_string())?;
        let mut split = message.split('|');
        let cmd_str = split.next().ok_or_else(|| "Invalid syntax".to_string())?;
        let data_str = split.next().ok_or_else(|| "Invalid syntax".to_string())?;

        Command::from_str(cmd_str).map(|cmd| (cmd, data_str.to_string()))
    }

    /// Sends a response
    pub async fn send_response<T: AsRef<str>>(
        &mut self,
        response: Response,
        data: T,
    ) -> tokio::io::Result<()> {
        self.raw_send_message(format!("{}|{}", response, &data.as_ref()))
            .await
    }

    /// Receive a response from the server
    ///
    /// Returns either Response::Ok with some data or Response::Err with an error message
    /// Note that this function returns a Result. Ok indicates successful communication, but it does
    /// not necessarily mean that the command succeeded
    async fn receive_response(&mut self, timeout: Duration) -> Result<(Response, String), String> {
        let message = self
            .receive_message(timeout)
            .await
            .map_err(|err| err.to_string())?;
        let mut split = message.split('|');
        let cmd_str = split.next().ok_or_else(|| "Invalid syntax".to_string())?;
        let data_str = split.next().ok_or_else(|| "Invalid syntax".to_string())?;

        Response::from_str(cmd_str).map(|resp| (resp, data_str.to_string()))
    }

    /// Perform handshake (from the client to the server)
    /// This consists of an identifier (to confirm client and server agrees on protocol)
    /// and the client's version number
    /// The server will reject the connection if either identifier or version numbers are different
    async fn client_handshake(&mut self) -> Result<(), String> {
        if let Err(err) = self.raw_send_message(HANDSHAKE_IDENTIFIER).await {
            return Err(format!("Failed to send handshake identifier - {}", err));
        }
        if let Err(err) = self.raw_send_message(env!("CARGO_PKG_VERSION")).await {
            return Err(format!("Failed to send handshake version - {}", err));
        }

        // Read server response
        let line = match self.receive_message(Duration::from_secs(5)).await {
            Ok(line) => line,
            Err(err) => {
                return Err(format!(
                    "Error reading server response during handshake - {}",
                    err
                ))
            }
        };

        // If "OK", continue.
        // Any other response in an error
        match line.as_ref() {
            "OK" => Ok(()),
            msg => Err(format!("Got bad response to handshake - {}", msg)),
        }
    }

    /// Performs the server-side part of the handshake
    /// An Err return value means the connection should be dropped
    async fn server_handshake(&mut self) -> Result<(), String> {
        let identifier = self
            .receive_message(Duration::from_secs(5))
            .await
            .map_err(|e| e.to_string())?;
        let version = self
            .receive_message(Duration::from_secs(5))
            .await
            .map_err(|e| e.to_string())?;

        match (identifier.as_ref(), version.as_ref()) {
            (HANDSHAKE_IDENTIFIER, env!("CARGO_PKG_VERSION")) => {
                match self.raw_send_message("OK").await {
                    Ok(_) => Ok(()),
                    Err(err) => Err(format!("Failed to send OK message - {}", err)),
                }
            }
            (x, y) => Err(format!(
                "Handshake failed - Expected: {} {} - Got: {} {}",
                HANDSHAKE_IDENTIFIER,
                env!("CARGO_PKG_VERSION"),
                x,
                y
            )),
        }
    }

    /// Attempt to construct a server-side IPCConnection
    /// Note that we cannot use `TryFrom` (yet), since async traits are unsupported
    pub async fn try_serverside_from(stream: TcpStream) -> Result<Self, String> {
        let _ = stream.set_nodelay(true);
        let mut ipc = IPCConnection {
            client: BufReader::new(stream),
        };
        match ipc.server_handshake().await {
            Ok(_) => Ok(ipc),
            Err(err) => Err(err),
        }
    }
}
