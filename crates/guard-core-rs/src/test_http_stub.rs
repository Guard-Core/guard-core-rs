//! Test-only request reader shared by the loopback HTTP stubs.

use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;

const READ_TIMEOUT: Duration = Duration::from_secs(1);
const HEAD_CAP: usize = 64 * 1024;
const HEAD_END: &[u8] = b"\r\n\r\n";

fn head_end(received: &[u8]) -> Option<usize> {
    received
        .windows(HEAD_END.len())
        .position(|window| window == HEAD_END)
}

fn content_length(head: &str) -> usize {
    head.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if !name.eq_ignore_ascii_case("content-length") {
                return None;
            }
            value.trim().parse().ok()
        })
        .unwrap_or(0)
}

fn is_complete(received: &[u8]) -> bool {
    head_end(received).map_or(received.len() >= HEAD_CAP, |end| {
        let head = String::from_utf8_lossy(&received[..end]);
        received.len() >= end + HEAD_END.len() + content_length(&head)
    })
}

/// Reads one whole request: the head up to the blank line (capped at 64 KiB),
/// then `Content-Length` body bytes when the header is present. A client that
/// stops sending gets 1 second, then the stub answers with what it has.
pub fn read_request(stream: &mut TcpStream) -> String {
    // macOS hands back the listener's non-blocking mode.
    stream.set_nonblocking(false).expect("blocking stream");
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .expect("read timeout");
    let mut received = Vec::new();
    let mut chunk = [0_u8; 4096];
    while !is_complete(&received) {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(count) => received.extend_from_slice(&chunk[..count]),
        }
    }
    String::from_utf8_lossy(&received).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    fn read_from(pieces: Vec<(Vec<u8>, u64)>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let client = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
            for (bytes, pause_ms) in pieces {
                stream.write_all(&bytes).expect("write");
                std::thread::sleep(Duration::from_millis(pause_ms));
            }
            stream
        });
        let (mut accepted, _) = listener.accept().expect("accept");
        let request = read_request(&mut accepted);
        drop(client.join().expect("client"));
        request
    }

    #[test]
    fn a_post_body_sent_after_its_head_is_read_in_full() {
        let request = read_from(vec![
            (
                b"POST /v1/traces HTTP/1.1\r\ncontent-length: 7\r\n\r\n".to_vec(),
                200,
            ),
            (b"{\"x\":1}EXTRA".to_vec(), 0),
        ]);
        assert!(request.ends_with("{\"x\":1}EXTRA"), "{request}");
    }

    #[test]
    fn a_body_cut_short_returns_what_arrived() {
        let request = read_from(vec![(
            b"POST / HTTP/1.1\r\nContent-Length: 50\r\n\r\nabc".to_vec(),
            0,
        )]);
        assert!(request.ends_with("abc"), "{request}");
    }

    #[test]
    fn an_unparsable_length_means_no_body() {
        let request = read_from(vec![(
            b"POST / HTTP/1.1\r\nContent-Length: nope\r\nX-Other: 1\r\n\r\n".to_vec(),
            0,
        )]);
        assert!(request.ends_with("\r\n\r\n"), "{request}");
    }

    #[test]
    fn a_head_without_an_end_stops_at_the_cap() {
        let request = read_from(vec![(vec![b'a'; HEAD_CAP + 100], 0)]);
        assert!(request.len() >= HEAD_CAP, "{}", request.len());
    }

    #[test]
    fn a_silent_client_ends_the_read_by_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let _silent = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let (mut accepted, _) = listener.accept().expect("accept");
        assert_eq!(read_request(&mut accepted), "");
    }
}
