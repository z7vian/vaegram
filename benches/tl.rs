//! TL and session micro-benchmarks in plain std: `cargo bench --bench tl`.

#[path = "support/seal.rs"]
mod seal;
#[path = "support/timing.rs"]
mod timing;

use std::hint::black_box;
use std::io::{Read, Write};

use timing::{bench, bench_bytes};
use vaegram::connection::{Connection, Framing, Options, RecvBuf, Transport};
use vaegram::crypto::{aes, mtproto};
use vaegram::raw::{Deserializable, Identifiable, Serializable, base, functions, types};
use vaegram::session::internals::data_center::Dc;
use vaegram::storage::{SessionData, session_string};

const VECTOR: u32 = 0x1cb5c415;
const TEXT: &str = "Hello there, this is a fairly ordinary chat message.";
// The payload sizes Go's MTProto benchmarks use, so the two report comparable rows.
const SIZES: [usize; 6] = [16, 128, 1 << 10, 8 << 10, 64 << 10, 512 << 10];
const BIG: usize = 512 << 10;

fn message_bytes(id: i32, out: &mut Vec<u8>) {
    types::Message::CONSTRUCTOR_ID.serialize(out);
    0u32.serialize(out);
    0u32.serialize(out);
    id.serialize(out);
    types::PeerUser::CONSTRUCTOR_ID.serialize(out);
    777000i64.serialize(out);
    1_700_000_000i32.serialize(out);
    TEXT.to_owned().serialize(out);
}

fn updates_bytes(n: usize) -> Vec<u8> {
    let mut b = Vec::new();
    types::Updates::CONSTRUCTOR_ID.serialize(&mut b);
    VECTOR.serialize(&mut b);
    (n as u32).serialize(&mut b);
    for i in 1..=n as i32 {
        types::UpdateNewMessage::CONSTRUCTOR_ID.serialize(&mut b);
        message_bytes(i, &mut b);
        i.serialize(&mut b);
        1i32.serialize(&mut b);
    }
    for _ in 0..2 {
        VECTOR.serialize(&mut b);
        0u32.serialize(&mut b);
    }
    1_700_000_000i32.serialize(&mut b);
    0i32.serialize(&mut b);
    b
}

fn peer_user(b: &mut Vec<u8>, user_id: i64) {
    types::PeerUser::CONSTRUCTOR_ID.serialize(b);
    user_id.serialize(b);
}

fn new_message_updates() -> Vec<u8> {
    let mut b = Vec::new();
    types::Updates::CONSTRUCTOR_ID.serialize(&mut b);

    VECTOR.serialize(&mut b);
    1i32.serialize(&mut b);
    types::UpdateNewMessage::CONSTRUCTOR_ID.serialize(&mut b);
    types::Message::CONSTRUCTOR_ID.serialize(&mut b);
    ((1u32 << 8) | (1 << 7)).serialize(&mut b); // from_id, entities
    0u32.serialize(&mut b);
    42i32.serialize(&mut b);
    peer_user(&mut b, 777000);
    peer_user(&mut b, 777000);
    1_700_000_000i32.serialize(&mut b);
    "hello there, see https://example.com".to_owned().serialize(&mut b);
    VECTOR.serialize(&mut b);
    2i32.serialize(&mut b);
    types::MessageEntityBold::CONSTRUCTOR_ID.serialize(&mut b);
    0i32.serialize(&mut b);
    5i32.serialize(&mut b);
    types::MessageEntityTextUrl::CONSTRUCTOR_ID.serialize(&mut b);
    17i32.serialize(&mut b);
    19i32.serialize(&mut b);
    "https://example.com".to_owned().serialize(&mut b);
    1000i32.serialize(&mut b);
    1i32.serialize(&mut b);

    VECTOR.serialize(&mut b);
    1i32.serialize(&mut b);
    types::User::CONSTRUCTOR_ID.serialize(&mut b);
    (1u32 | (1 << 1) | (1 << 3) | (1 << 5) | (1 << 6) | (1 << 22)).serialize(&mut b);
    (1u32 << 8).serialize(&mut b); // color
    777000i64.serialize(&mut b);
    0x1234_5678_9abc_def0i64.serialize(&mut b);
    "Alice".to_owned().serialize(&mut b);
    "alice".to_owned().serialize(&mut b);
    types::UserProfilePhoto::CONSTRUCTOR_ID.serialize(&mut b);
    (1u32 << 1).serialize(&mut b);
    5_000_000_000i64.serialize(&mut b);
    vec![1u8; 33].serialize(&mut b);
    2i32.serialize(&mut b);
    types::UserStatusOnline::CONSTRUCTOR_ID.serialize(&mut b);
    1_700_000_300i32.serialize(&mut b);
    "en".to_owned().serialize(&mut b);
    types::PeerColor::CONSTRUCTOR_ID.serialize(&mut b);
    1u32.serialize(&mut b);
    3i32.serialize(&mut b);

    VECTOR.serialize(&mut b);
    0i32.serialize(&mut b);
    1_700_000_000i32.serialize(&mut b);
    0i32.serialize(&mut b);
    b
}

fn main() {
    timing::header();

    let ping = functions::Ping { ping_id: 0x1234_5678 };
    let mut buf = Vec::with_capacity(1 << 20);
    bench("ping serialize (reused buf)", || {
        buf.clear();
        black_box(&ping).serialize(&mut buf);
        black_box(&buf);
    });
    bench("ping to_bytes", || {
        black_box(black_box(&ping).to_bytes());
    });
    let pong = types::Pong { msg_id: 1, ping_id: 0x1234_5678 }.to_bytes();
    bench("pong deserialize", || {
        black_box(base::Pong::from_bytes(black_box(&pong)).unwrap());
    });

    let mut msg = Vec::new();
    message_bytes(42, &mut msg);
    bench("message deserialize", || {
        black_box(base::Message::from_bytes(black_box(&msg)).unwrap());
    });
    let parsed = base::Message::from_bytes(&msg).unwrap();
    assert_eq!(parsed.to_bytes(), msg);
    bench("message serialize", || {
        buf.clear();
        black_box(&parsed).serialize(&mut buf);
        black_box(&buf);
    });

    let typical = new_message_updates();
    let parsed = base::Updates::from_bytes(&typical).unwrap();
    assert_eq!(parsed.to_bytes(), typical);
    bench("typical new-message updates deserialize", || {
        black_box(base::Updates::from_bytes(black_box(&typical)).unwrap());
    });
    bench("typical new-message updates serialize", || {
        buf.clear();
        black_box(&parsed).serialize(&mut buf);
        black_box(&buf);
    });

    for n in [1, 10, 100] {
        let raw = updates_bytes(n);
        bench(&format!("updates x{n} deserialize"), || {
            black_box(base::Updates::from_bytes(black_box(&raw)).unwrap());
        });
        let parsed = base::Updates::from_bytes(&raw).unwrap();
        assert_eq!(parsed.to_bytes(), raw);
        bench(&format!("updates x{n} serialize"), || {
            buf.clear();
            black_box(&parsed).serialize(&mut buf);
            black_box(&buf);
        });
    }

    let part = functions::upload::SaveFilePart { file_id: 1, file_part: 0, bytes: vec![0xab; 512 * 1024] };
    bench("save_file_part 512K ser", || {
        buf.clear();
        black_box(&part).serialize(&mut buf);
        black_box(&buf);
    });
    let part_bytes = part.to_bytes();
    bench("bytes 512K deserialize", || {
        black_box(Vec::<u8>::from_bytes(black_box(&part_bytes[16..])).unwrap());
    });

    let auth_key = [7u8; 256];
    let auth_key_id = [1u8; 8];
    let session_id = [2u8; 8];
    let mut packet = Vec::new();
    for size in SIZES {
        let body = vec![0xab; size];
        bench_bytes(&format!("mtproto seal {size} B"), size, || {
            packet.clear();
            packet.resize(mtproto::HEADER, 0);
            packet.extend_from_slice(black_box(&body));
            mtproto::header(&mut packet, 0, &session_id, 1 << 32, 1);
            mtproto::seal(&mut packet, 0, &auth_key, &auth_key_id);
        });
        // Each round copies the ciphertext back in, since opening decrypts it in place.
        let sealed = seal::seal(&auth_key, &auth_key_id, &session_id, (1 << 32) + 1, 1, &body);
        bench_bytes(&format!("mtproto open {size} B"), size, || {
            packet.clear();
            packet.extend_from_slice(black_box(&sealed));
            black_box(mtproto::open(&mut packet, &auth_key, &auth_key_id, &session_id).unwrap());
        });
    }

    let (key, ige_iv) = ([3u8; 32], [4u8; 32]);
    let mut data = vec![0x5a; BIG];
    bench_bytes("ige256_decrypt 512 KiB", BIG, || {
        aes::ige256_decrypt(black_box(&mut data), &key, &ige_iv).unwrap();
    });
    let (mut ctr_iv, mut used) = ([5u8; 16], 0u8);
    bench_bytes("ctr256 512 KiB", BIG, || {
        aes::ctr256(black_box(&mut data), &key, &mut ctr_iv, &mut used);
    });

    for transport in [Transport::Abridged, Transport::Intermediate, Transport::PaddedIntermediate, Transport::Full] {
        framing(transport, &mut buf);
    }

    for size in [256, 64 << 10, BIG] {
        recv_loopback(size, false);
    }
    for size in [64 << 10, BIG] {
        recv_loopback(size, true);
    }

    let mut session = SessionData::new(2, auth_key);
    (session.api_id, session.user_id, session.is_bot) = (12345, 777000, true);
    bench("session string export", || {
        black_box(session_string::export(black_box(&session)));
    });
    let exported = session_string::export(&session);
    bench("session string parse", || {
        black_box(session_string::parse(black_box(&exported)).unwrap());
    });
}

// Framing alone, without a socket: `frame` builds the header around a payload, `decode` takes it back off a buffer
// that the frame was just copied into, as a socket read would.
fn framing(transport: Transport, buf: &mut Vec<u8>) {
    for size in SIZES {
        let payload = vec![0x5a; size];
        let mut sender = Framing::new(transport);
        bench_bytes(&format!("{transport:?} frame {size} B"), size, || {
            buf.clear();
            buf.resize(Framing::ROOM, 0);
            buf.extend_from_slice(black_box(&payload));
            black_box(sender.frame(buf));
        });
        buf.clear();
        buf.resize(Framing::ROOM, 0);
        buf.extend_from_slice(&payload);
        let start = Framing::new(transport).frame(buf);
        let frame = buf[start..].to_vec();
        let mut recv = RecvBuf::default();
        bench_bytes(&format!("{transport:?} decode {size} B"), size, || {
            // A fresh receiver each round, so the full transport's sequence number matches the one frame.
            let mut receiver = Framing::new(transport);
            recv.extend_from_slice(black_box(&frame));
            black_box(receiver.decode(&mut recv).unwrap().unwrap());
        });
    }
}

// A loopback server streams `size`-byte intermediate frames; each op reads one through the real Connection,
// so syscalls and buffering are part of the number. Obfuscated, the server encrypts its stream as it writes,
// on its own thread.
fn recv_loopback(size: usize, obfuscated: bool) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mut frames = Vec::new();
    while frames.len() < 1 << 20 {
        frames.extend_from_slice(&(size as u32).to_le_bytes());
        frames.resize(frames.len() + size, 0x5a);
    }
    std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        if !obfuscated {
            s.read_exact(&mut [0; 4]).unwrap();
            while s.write_all(&frames).is_ok() {}
            return;
        }
        // The client decrypts with the reversed key and iv bytes of its 64-byte header.
        let mut header = [0u8; 64];
        s.read_exact(&mut header).unwrap();
        let mut reversed = [0u8; 48];
        reversed.copy_from_slice(&header[8..56]);
        reversed.reverse();
        let key: [u8; 32] = reversed[..32].try_into().unwrap();
        let (mut iv, mut used): ([u8; 16], u8) = (reversed[32..].try_into().unwrap(), 0);
        let mut chunk = Vec::with_capacity(frames.len());
        loop {
            chunk.clear();
            chunk.extend_from_slice(&frames);
            aes::ctr256(&mut chunk, &key, &mut iv, &mut used);
            if s.write_all(&chunk).is_err() {
                return;
            }
        }
    });
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let dc = Dc { id: 2, addr, test: false };
    let options = Options { obfuscated, ..Options::default() };
    let mut conn = rt.block_on(Connection::connect(&dc, &options)).unwrap();
    let name = if obfuscated { "recv loopback obfuscated" } else { "recv loopback" };
    bench_bytes(&format!("{name} {size} B"), size, || {
        black_box(rt.block_on(conn.recv()).unwrap());
    });
}
