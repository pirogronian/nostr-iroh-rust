
use std::vec::Vec;
use std::io::Read;
use std::sync::LazyLock;
use bytes::{Bytes, BytesMut};
use thiserror::Error;
use std::convert::TryInto;
use std::array::TryFromSliceError;
use std::str::Utf8Error;
use iroh::endpoint::{RecvStream, ReadError};
use log::{error, warn, info, debug};

pub const ALPN: &[u8] = b"nostr-iroh-proxy/0";

pub static ALPNs: LazyLock<Vec<Vec<u8>>> = LazyLock::new(|| { vec![(ALPN.to_vec())] });

pub struct ClientIrohPacket {
    pub flags: u32,
    pub id: String,
    pub payload: String
}

impl ClientIrohPacket {
    pub const EPHEMERAL: u32 = 1;
    fn is_ephemeral(&self) -> bool {
        ClientIrohPacket::EPHEMERAL & self.flags > 0
    }
    fn is_persistent(&self) -> bool {
        ClientIrohPacket::EPHEMERAL & self.flags == 0
    }
    fn new() -> ClientIrohPacket {
        return ClientIrohPacket { flags: 0, id: "".to_string(), payload: "".to_string() }
    }
}

pub struct RelayIrohPacket {
    pub payload: String
}

#[derive(Error, Debug)]
pub enum IrohPacketError {
    #[error("Data read error: {0}")]
    DataReadError(#[from] ReadError),
    #[error("Error while converting bytes into u32: {0}")]
    U32ConvertError(#[from] TryFromSliceError),
    #[error("Error while converting bytes into UTF-8: {0}")]
    Utf8Error(#[from] Utf8Error)
}

pub struct RelayIrohRecvStream {
    stream: RecvStream,
    current_chunk: Bytes
}

impl RelayIrohRecvStream {
    pub const MAX_CHUNK_SIZE: usize = 1024*8;

    fn new(mut stream: RecvStream) -> RelayIrohRecvStream {
        return RelayIrohRecvStream { stream: stream, current_chunk: Bytes::new() }
    }

    async fn read_packet(&mut self) -> Result<Option<ClientIrohPacket>, IrohPacketError> {
        let mut packet: ClientIrohPacket = ClientIrohPacket::new();
        let mut buf: BytesMut = BytesMut::new();
        let mut id_len;
        let mut payl_len;
        if self.current_chunk.len() == 0 {
            let op = self.stream.read_chunk(Self::MAX_CHUNK_SIZE).await?;
            if op == None { return Ok(None) }
            self.current_chunk = op.unwrap();
        }
        if self.current_chunk.len() >= 12 {
            packet.flags = u32::from_be_bytes(self.current_chunk[..4].try_into()?);
            id_len = u32::from_be_bytes(self.current_chunk[4..8].try_into()?) as usize;
            payl_len = u32::from_be_bytes(self.current_chunk[8..12].try_into()?) as usize;
            self.current_chunk.split_to(12);
        } else {
            buf.extend_from_slice(&self.current_chunk);
            loop {
                let op = self.stream.read_chunk(Self::MAX_CHUNK_SIZE).await?;
                if op == None { return Ok(None) }
                self.current_chunk = op.unwrap();
                if buf.len() + self.current_chunk.len() <= 12 {
                    let rest = self.current_chunk.split_to(12 - buf.len());
                    buf.extend_from_slice(&rest);
                    break;
                }
                buf.extend_from_slice(&self.current_chunk)
            }
            packet.flags = u32::from_be_bytes(buf[..4].try_into()?);
            id_len = u32::from_be_bytes(buf[4..8].try_into()?) as usize;
            payl_len = u32::from_be_bytes(buf[8..12].try_into()?) as usize;
        }

        if self.current_chunk.len() >= id_len {
            let rest = self.current_chunk.split_to(id_len);
            packet.id = std::str::from_utf8(&rest)?.to_string();
        } else {
            buf.clear();
            if self.current_chunk.len() > 0 { buf.extend_from_slice(&self.current_chunk); }
            loop {
                let op = self.stream.read_chunk(Self::MAX_CHUNK_SIZE).await?;
                if op == None { return Ok(None) }
                self.current_chunk = op.unwrap();
                if self.current_chunk.len() + buf.len() >= id_len {
                    let rest = self.current_chunk.split_to(id_len - buf.len());
                    if buf.len() > 0 {
                        buf.extend_from_slice(&rest);
                        packet.id = std::str::from_utf8(&buf)?.to_string();
                    } else {
                        packet.id = std::str::from_utf8(&rest)?.to_string();
                    }
                    break;
                } else { buf.extend_from_slice(&self.current_chunk); }
            }
        }
        if self.current_chunk.len() >= payl_len {
            let rest = self.current_chunk.split_to(payl_len);
            packet.payload = std::str::from_utf8(&rest)?.to_string();
        } else {
            buf.clear();
            if self.current_chunk.len() > 0 { buf.extend_from_slice(&self.current_chunk); }
            loop {
                let op = self.stream.read_chunk(Self::MAX_CHUNK_SIZE).await?;
                if op == None { return Ok(None) }
                self.current_chunk = op.unwrap();
                if self.current_chunk.len() + buf.len() >= payl_len {
                    let rest = self.current_chunk.split_to(payl_len - buf.len());
                    if buf.len() > 0 {
                        buf.extend_from_slice(&rest);
                        packet.payload = std::str::from_utf8(&buf)?.to_string();
                    } else {
                        packet.payload = std::str::from_utf8(&rest)?.to_string();
                    }
                    break;
                } else { buf.extend_from_slice(&self.current_chunk); }
            }
        }
        return Ok(Some(packet));
    }
}
