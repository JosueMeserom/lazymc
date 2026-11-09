use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use minecraft_protocol::decoder::Decoder;
use minecraft_protocol::version::v1_14_4::handshake::Handshake;
use minecraft_protocol::version::v1_20_3::status::{
    PingRequest, PingResponse, ServerStatus, StatusRequest,
};
use rand::Rng;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time;

use crate::config::Config;
use crate::proto::client::{Client, ClientState};
use crate::proto::{packet, packets};
use crate::proxy;
use crate::server::{Server, State};

/// Monitor ping inverval in seconds.
const MONITOR_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Status request timeout in seconds.
const STATUS_TIMEOUT: u64 = 20;

/// Ping request timeout in seconds.
const PING_TIMEOUT: u64 = 10;

/// Monitor server.
pub async fn monitor_server(config: Arc<Config>, server: Arc<Server>) {
    // Server address
    let addr = config.server.address;

    let mut poll_interval = time::interval(MONITOR_POLL_INTERVAL);

    loop {
        poll_interval.tick().await;

        // Poll server state and update internal status
        trace!(target: "lazymc::monitor", "Fetching status for {} ... ", addr);
        let status = poll_server(&config, &server, addr).await;
        match status {
            // Got status, update
            Ok(Some(status)) => server.update_status(&config, Some(status)).await,

            // Error, reset status
            Err(_) => server.update_status(&config, None).await,

            // Didn't get status, but ping fallback worked, leave as-is, show warning
            Ok(None) => {
                warn!(target: "lazymc::monitor", "Failed to poll server status, ping fallback succeeded");
            }
        }

        // Sleep server when it's bedtime
        if server.should_sleep(&config).await {
            info!(target: "lazymc::monitor", "Server has been idle, sleeping...");
            server.stop(&config).await;
        }

        // Check whether we should force kill server
        if server.should_kill().await {
            error!(target: "lazymc::monitor", "Force killing server, took too long to start or stop");
            if !server.force_kill().await {
                warn!(target: "lazymc", "Failed to force kill server");
            }
        }
    }
}

/// Poll server state.
///
/// Returns `Ok` if status/ping succeeded, includes server status most of the time.
/// Returns `Err` if no connection could be established or if an error occurred.
pub async fn poll_server(
    config: &Config,
    server: &Server,
    addr: SocketAddr,
) -> Result<Option<ServerStatus>, ()> {
    // Fetch status
    if let Ok(status) = fetch_status(config, addr).await {
        return Ok(Some(status));
    }

    // Try ping fallback if server is currently started
    if server.state() == State::Started {
        debug!(target: "lazymc::monitor", "Failed to get status from started server, trying ping...");
        do_ping(config, addr).await?;
    }

    Err(())
}

/// Attemp to fetch status from server.
async fn fetch_status(config: &Config, addr: SocketAddr) -> Result<ServerStatus, ()> {
    let mut stream = TcpStream::connect(addr).await.map_err(|_| ())?;

    // Add proxy header
    if config.server.send_proxy_v2 {
        trace!(target: "lazymc::monitor", "Sending local proxy header for server connection");
        stream
            .write_all(&proxy::local_proxy_header().map_err(|_| ())?)
            .await
            .map_err(|_| ())?;
    }

    // Dummy client
    let client = Client::dummy();

    send_handshake(&client, &mut stream, config, addr).await?;
    request_status(&client, &mut stream).await?;
    wait_for_status_timeout(&client, &mut stream).await
}

/// Attemp to ping server.
async fn do_ping(config: &Config, addr: SocketAddr) -> Result<(), ()> {
    let mut stream = TcpStream::connect(addr).await.map_err(|_| ())?;

    // Add proxy header
    if config.server.send_proxy_v2 {
        trace!(target: "lazymc::monitor", "Sending local proxy header for server connection");
        stream
            .write_all(&proxy::local_proxy_header().map_err(|_| ())?)
            .await
            .map_err(|_| ())?;
    }

    // Dummy client
    let client = Client::dummy();

    send_handshake(&client, &mut stream, config, addr).await?;
    let token = send_ping(&client, &mut stream).await?;
    wait_for_ping_timeout(&client, &mut stream, token).await
}

/// Send handshake.
async fn send_handshake(
    client: &Client,
    stream: &mut TcpStream,
    config: &Config,
    addr: SocketAddr,
) -> Result<(), ()> {
    packet::write_packet(
        Handshake {
            protocol_version: config.public.protocol as i32,
            server_addr: addr.ip().to_string(),
            server_port: addr.port(),
            next_state: ClientState::Status.to_id(),
        },
        client,
        &mut stream.split().1,
    )
    .await
}

/// Send status request.
async fn request_status(client: &Client, stream: &mut TcpStream) -> Result<(), ()> {
    packet::write_packet(StatusRequest {}, client, &mut stream.split().1).await
}

/// Send status request.
async fn send_ping(client: &Client, stream: &mut TcpStream) -> Result<u64, ()> {
    let token = rand::thread_rng().gen();
    packet::write_packet(PingRequest { time: token }, client, &mut stream.split().1).await?;
    Ok(token)
}

/// Wait for a status response.
async fn wait_for_status(client: &Client, stream: &mut TcpStream) -> Result<ServerStatus, ()> {
    // Get stream reader, set up buffer
    let (mut reader, mut _writer) = stream.split();
    let mut buf = BytesMut::new();

    loop {
        // Read packet from stream
        let (packet, _raw) = match packet::read_packet(client, &mut buf, &mut reader).await {
            Ok(Some(packet)) => packet,
            Ok(None) => break,
            Err(_) => continue,
        };

        // Catch status response
        if packet.id == packets::status::CLIENT_STATUS {
            return decode_status(&packet.data).map_err(|err| {
                debug!(target: "lazymc", "Failed to decode status response from backend server, ignoring: {err}");
            });
        }
    }

    // Some error occurred
    Err(())
}

/// Wait for a status response.
async fn wait_for_status_timeout(
    client: &Client,
    stream: &mut TcpStream,
) -> Result<ServerStatus, ()> {
    let status = wait_for_status(client, stream);
    tokio::time::timeout(Duration::from_secs(STATUS_TIMEOUT), status)
        .await
        .map_err(|_| ())?
}

/// Wait for a status response.
async fn wait_for_ping(client: &Client, stream: &mut TcpStream, token: u64) -> Result<(), ()> {
    // Get stream reader, set up buffer
    let (mut reader, mut _writer) = stream.split();
    let mut buf = BytesMut::new();

    loop {
        // Read packet from stream
        let (packet, _raw) = match packet::read_packet(client, &mut buf, &mut reader).await {
            Ok(Some(packet)) => packet,
            Ok(None) => break,
            Err(_) => continue,
        };

        // Catch ping response
        if packet.id == packets::status::CLIENT_PING {
            let ping = PingResponse::decode(&mut packet.data.as_slice()).map_err(|_| ())?;

            // Ping token must match
            if ping.time == token {
                return Ok(());
            } else {
                debug!(target: "lazymc", "Got unmatched ping response when polling server status by ping");
            }
        }
    }

    // Some error occurred
    Err(())
}

/// Wait for a status response.
async fn wait_for_ping_timeout(
    client: &Client,
    stream: &mut TcpStream,
    token: u64,
) -> Result<(), ()> {
    let status = wait_for_ping(client, stream, token);
    tokio::time::timeout(Duration::from_secs(PING_TIMEOUT), status)
        .await
        .map_err(|_| ())?
}

/// Decode a status response from the server.
///
/// Servers send a description with colors or formatting as a text component (a JSON object), which the
/// protocol library can't read: it is turned into a legacy string with § codes first.
fn decode_status(data: &[u8]) -> Result<ServerStatus, String> {
    let json = String::decode(&mut &data[..]).map_err(|err| format!("{err:?}"))?;
    let mut status: serde_json::Value = serde_json::from_str(&json).map_err(|err| err.to_string())?;
    if let Some(description) = status.get_mut("description") {
        if !description.is_string() {
            let mut legacy = String::new();
            component_to_legacy(description, &Style::default(), &mut legacy);
            *description = serde_json::Value::String(legacy);
        }
    }
    serde_json::from_value(status).map_err(|err| err.to_string())
}

/// Text component style, inherited by its children.
#[derive(Clone, Default)]
struct Style {
    color: Option<char>,
    formats: String,
}

/// Append a text component as legacy text with § codes.
fn component_to_legacy(component: &serde_json::Value, parent: &Style, out: &mut String) {
    use serde_json::Value;

    match component {
        Value::String(text) => push_styled(text, parent, out),
        Value::Array(parts) => parts.iter().for_each(|part| component_to_legacy(part, parent, out)),
        Value::Object(map) => {
            let mut style = parent.clone();
            if let Some(color) = map.get("color").and_then(Value::as_str).and_then(color_code) {
                style.color = Some(color);
                style.formats.clear();
            }
            for (key, code) in [
                ("obfuscated", 'k'),
                ("bold", 'l'),
                ("strikethrough", 'm'),
                ("underlined", 'n'),
                ("italic", 'o'),
            ] {
                match map.get(key).and_then(Value::as_bool) {
                    Some(true) if !style.formats.contains(code) => style.formats.push(code),
                    Some(false) => style.formats.retain(|c| c != code),
                    _ => {}
                }
            }
            if let Some(text) = map.get("text").and_then(Value::as_str) {
                push_styled(text, &style, out);
            }
            if let Some(extra) = map.get("extra") {
                component_to_legacy(extra, &style, out);
            }
        }
        _ => {}
    }
}

/// Append text with the codes of its style.
fn push_styled(text: &str, style: &Style, out: &mut String) {
    if text.is_empty() {
        return;
    }
    if style.color.is_some() || !style.formats.is_empty() || !out.is_empty() {
        out.push_str("§r");
    }
    if let Some(color) = style.color {
        out.push('§');
        out.push(color);
    }
    for code in style.formats.chars() {
        out.push('§');
        out.push(code);
    }
    out.push_str(text);
}

/// Legacy code of a named color (hex colors have none in legacy text).
fn color_code(name: &str) -> Option<char> {
    let colors = [
        "black", "dark_blue", "dark_green", "dark_aqua", "dark_red", "dark_purple", "gold", "gray",
        "dark_gray", "blue", "green", "aqua", "red", "light_purple", "yellow", "white",
    ];
    colors
        .iter()
        .position(|c| *c == name)
        .map(|i| std::char::from_digit(i as u32, 16).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use minecraft_protocol::encoder::EncoderWriteExt;

    fn packet(json: &str) -> Vec<u8> {
        let mut data = Vec::new();
        data.write_string(json, 32_767).unwrap();
        data
    }

    #[test]
    fn plain_description() {
        let status = decode_status(&packet(
            r#"{"version":{"name":"1.21.11","protocol":774},"players":{"max":20,"online":2},"description":"Hola"}"#,
        ))
        .unwrap();
        assert_eq!(status.description, "Hola");
        assert_eq!(status.players.online, 2);
    }

    #[test]
    fn colored_description() {
        // What Paper sends for "§aVerde §lnegrita\n§7gris"
        let status = decode_status(&packet(
            r##"{"version":{"name":"Paper 1.21.11","protocol":774},"players":{"max":20,"online":0,"sample":[]},
            "description":{"text":"","extra":[{"text":"Verde ","color":"green"},{"text":"negrita","color":"green","bold":true},
            "\n",{"text":"gris","color":"gray"},{"text":"hex","color":"#123456"}]},"favicon":"data:image/png;base64,AA=="}"##,
        ))
        .unwrap();
        assert_eq!(status.description, "§r§aVerde §r§a§lnegrita§r\n§r§7gris§rhex");
    }

    #[test]
    fn inherited_style() {
        let status = decode_status(&packet(
            r#"{"version":{"name":"x","protocol":1},"players":{"max":1,"online":0},
            "description":{"text":"A","color":"red","italic":true,"extra":[{"text":"B","italic":false},{"text":"C","color":"blue"}]}}"#,
        ))
        .unwrap();
        assert_eq!(status.description, "§r§c§oA§r§cB§r§9C");
    }

    #[test]
    fn broken_status() {
        assert!(decode_status(&packet(r#"{"description":"falta todo"}"#)).is_err());
        assert!(decode_status(&[0xff]).is_err());
    }
}
