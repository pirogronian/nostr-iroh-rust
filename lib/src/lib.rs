
use std::vec::Vec;
use std::io::Read;
use std::sync::LazyLock;
use bytes::{Bytes, BytesMut, BufMut};
use thiserror::Error;
use std::convert::TryInto;
use std::array::TryFromSliceError;
use std::str::Utf8Error;
use std::num::TryFromIntError;
use iroh::endpoint::{RecvStream, SendStream, ReadError, WriteError, Connection, Endpoint, presets};
use iroh_tickets::{Ticket, endpoint::EndpointTicket};
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
    fn dump(&self) {
        println!("Packet from client:");
        println!("Flags: {}", self.flags);
        println!("Id: ({}) \"{}\"", self.id.len(), self.id);
        println!("Payload: ({}) \"{}\"", self.payload.len(), self.id);
        println!("-------------------------");
    }
}

pub struct RelayIrohPacket {
    pub payload: String
}

#[derive(Error, Debug)]
pub enum GetIrohPacketError {
    #[error("Data read error: {0}")]
    DataReadError(#[from] ReadError),
    #[error("Error while converting bytes into u32: {0}")]
    U32ConvertError(#[from] TryFromSliceError),
    #[error("Error while converting bytes into UTF-8: {0}")]
    Utf8Error(#[from] Utf8Error)
}

#[derive(Error, Debug)]
pub enum SendIrohPacketError {
    #[error("Data write error: {0}")]
    DataWriteError(#[from] WriteError),
    #[error("Error while converting u32 into bytes: {0}")]
    U32ConvertError(#[from]  TryFromIntError)
}

pub struct RelayIrohRecvStream {
    stream: RecvStream,
    current_chunk: Bytes
}

impl RelayIrohRecvStream {
    pub const MAX_CHUNK_SIZE: usize = 1024*8;

    fn new(stream: RecvStream) -> RelayIrohRecvStream {
        return RelayIrohRecvStream { stream: stream, current_chunk: Bytes::new() }
    }

    async fn read_packet(&mut self) -> Result<Option<ClientIrohPacket>, GetIrohPacketError> {
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

pub struct ClientIrohSendStream {
    stream: SendStream
}

impl ClientIrohSendStream {
    fn new(stream: SendStream) -> ClientIrohSendStream {
        return ClientIrohSendStream { stream: stream }
    }

    async fn write_packet(&mut self, packet: &ClientIrohPacket) -> Result<(), SendIrohPacketError> {
        let mut buf: BytesMut = BytesMut::new();
        buf.put_u32(packet.flags);
        let id_len: u32 = packet.id.len().try_into()?;
        buf.put_u32(id_len);
        let payl_len: u32 = packet.payload.len().try_into()?;
        buf.put_u32(payl_len);
        buf.extend_from_slice(packet.id.as_bytes());
        buf.extend_from_slice(packet.payload.as_bytes());
        self.stream.write_chunk(buf.freeze()).await?;
        Ok(())
    }
}

async fn test_relay_iroh_packet_receiver(stream: RecvStream) {
    let mut rs = RelayIrohRecvStream::new(stream);
    loop {
        let ret = rs.read_packet().await;
        match ret {
            Ok(o) => {
                match o {
                    Some(p) => { p.dump(); },
                    None => { debug!("Stream closed."); break; }
                }
            },
            Err(e) => { error!("Error while reading packet from client: {}", e); break; }
        }
    }
}

async fn test_relay_iroh_connection_handler(conn: Connection) {

}

async fn test_client_iroh_packet_sender(ticket: EndpointTicket) {
    let ret_ep = Endpoint::bind(presets::N0).await;
    if let Err(e) = ret_ep { error!("Error while binding a test client endpoint: {}", e); return }
    let ep = ret_ep.unwrap();
    let ret_conn = ep.connect(ticket, ALPN).await;
    if let Err(e) = ret_conn { error!("Error while connect a test client endpoint to a relay: {}", e); return }
    let conn = ret_conn.unwrap();
    let ret_stream = conn.open_uni().await;
    if let Err(e) = ret_stream { error!("Error while opening a test sending stream to a relay: {}", e); return }
    let stream = ret_stream.unwrap();
    let sstream = ClientIrohSendStream::new(stream);
}
