
use std::vec::Vec;
use std::io::Read;
use std::sync::LazyLock;
use bytes::{Bytes, BytesMut, BufMut};
use thiserror::Error;
use std::convert::TryInto;
use std::array::TryFromSliceError;
use std::str::Utf8Error;
use std::num::TryFromIntError;
use iroh::{EndpointAddr, endpoint::{Connection, Endpoint, ReadError, RecvStream, SendStream, WriteError, presets}};
use iroh_tickets::{Ticket, endpoint::EndpointTicket};
use log::{error, warn, info, debug};
use tokio;
use sonic_rs::{JsonPointer, PointerNode, JsonValueTrait};
use ahash::RandomState;
use std::fmt::{Formatter};

use crate::GetIrohPacketError::UnexpectedEOS;

pub mod test;

pub const ALPN: &[u8] = b"nostr-iroh-proxy/0";

pub static ALPNs: LazyLock<Vec<Vec<u8>>> = LazyLock::new(|| { vec![(ALPN.to_vec())] });

pub struct IrohPacket {
    pub flags: u32,
    pub id: String,
    pub payload: String
}

impl IrohPacket {
    pub const EPHEMERAL: u32 = 1;
    fn is_ephemeral(&self) -> bool {
        IrohPacket::EPHEMERAL & self.flags > 0
    }
    fn is_persistent(&self) -> bool {
        IrohPacket::EPHEMERAL & self.flags == 0
    }
    fn new(flags: u32, id: String, payload: String) -> IrohPacket {
        return IrohPacket { flags: flags, id: id, payload: payload }
    }
    fn dump(&self) {
        println!("Packet from client:");
        println!("Flags: {}", self.flags);
        println!("Id: ({}) \"{}\"", self.id.len(), self.id);
        println!("Payload: ({}) \"{}\"", self.payload.len(), self.payload);
        println!("-------------------------");
    }
}

#[derive(Error, Debug)]
pub enum GetIrohPacketError {
    #[error("Data read error: {0}")]
    DataReadError(#[from] ReadError),
    #[error("Error while converting bytes into u32: {0}")]
    U32ConvertError(#[from] TryFromSliceError),
    #[error("Error while converting bytes into UTF-8: {0}")]
    Utf8Error(#[from] Utf8Error),
    #[error("Unexpected EOS")]
    UnexpectedEOS
}

#[derive(Error, Debug)]
pub enum SendIrohPacketError {
    #[error("Data write error: {0}")]
    DataWriteError(#[from] WriteError),
    #[error("Error while converting u32 into bytes: {0}")]
    U32ConvertError(#[from]  TryFromIntError)
}

pub struct IrohRecvStream {
    stream: RecvStream,
    current_chunk: Bytes
}

impl IrohRecvStream {
    pub const MAX_CHUNK_SIZE: usize = 1024*8;

    fn new(stream: RecvStream) -> IrohRecvStream {
        return IrohRecvStream { stream: stream, current_chunk: Bytes::new() }
    }

    async fn read_packet(&mut self) -> Result<Option<IrohPacket>, GetIrohPacketError> {
        let mut packet: IrohPacket = IrohPacket::new(0, "".to_string(), "".to_string());
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
                if op == None { return Err(UnexpectedEOS) }
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
                if op == None { return Err(UnexpectedEOS) }
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
                if op == None { return Err(UnexpectedEOS) }
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

pub struct IrohSendStream {
    stream: SendStream
}

impl IrohSendStream {
    pub fn new(stream: SendStream) -> IrohSendStream {
        return IrohSendStream { stream: stream }
    }

    pub fn finish(&mut self) { self.stream.finish(); }

    pub async fn send_packet(&mut self, packet: &IrohPacket) -> Result<(), SendIrohPacketError> {
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

pub struct PacketSessionInfo<'a> {
    id: sonic_rs::LazyValue<'a>,
    closing: bool
}

struct WebSocketPacketInfo<'a> {
    id_path: &'a sonic_rs::JsonPointer,
    closing: bool
}
pub struct WebSocketPacketsDatabase<'a> {
    map: hashbrown::HashMap<String, WebSocketPacketInfo<'a>, RandomState>
}

impl<'a> WebSocketPacketsDatabase<'a> {
    pub fn new() -> Self {
        Self {
            map: hashbrown::HashMap::with_hasher(RandomState::default())
        }
    }

    pub fn add(&mut self, cmd: &str, ptr: &'a JsonPointer, closing: bool) {
        self.map.insert(format!("\"{}\"", cmd), WebSocketPacketInfo { id_path: ptr, closing: closing });
    }

    pub fn get(&self, cmd: &str) -> Option<&WebSocketPacketInfo<'_>> {
        self.map.get(cmd)
    }
}

pub struct WebSocketPacketAnalyzer<'db, 'a> {
    db: &'db WebSocketPacketsDatabase<'a>
}

impl<'db, 'a> WebSocketPacketAnalyzer<'db, 'a> {
    pub fn new(db: &'db WebSocketPacketsDatabase<'a>) -> Self {
        Self { db: db }
    }

    pub fn get_info<'s>(&self, data: &'s str) -> Result<Option<PacketSessionInfo<'s>>, sonic_rs::Error> {
        let ret_cmd = sonic_rs::get(data, sonic_rs::pointer![0])?;
        let cmd = ret_cmd.as_raw_str();
        let Some(info) = self.db.get(cmd)
        else { return Ok(None) };
        let id = sonic_rs::get(data, info.id_path)?;
        Ok(Some(PacketSessionInfo { id, closing: info.closing }))
    }
}

//type IrohRecvStreamMap = dashmap::DashMap<String, RecvStream, ahash::RandomState>;
type IrohSendStreamMap = dashmap::DashMap<String, IrohSendStream, ahash::RandomState>;

pub struct IrohConnection {
    connection: Connection,
//    recv_streams: IrohRecvStreamMap,
    send_streams: IrohSendStreamMap
}

pub enum IrohConnectionSendStreamOrId {
    SendStream(IrohSendStream),
    StreamExternalId(String)
}

impl IrohConnection {
    pub fn new(conn: Connection) -> Self {
        Self { connection: conn,
            send_streams: IrohSendStreamMap::with_hasher(ahash::RandomState::new()) }
    }

    pub async fn handle_recv_stream(
        &self,
        stream: RecvStream,
        ss_or_id: IrohConnectionSendStreamOrId) -> Result<(), GetIrohPacketError>
    {
        let mut irs: IrohRecvStream = IrohRecvStream::new(stream);
        let mut res: Result<(), GetIrohPacketError> = Ok(());
        let mut stream_id = "".to_string();
        let mut external_id: Option<String> = None;
        let mut iroh_send_stream: Option<IrohSendStream> = None;
        match ss_or_id {
            IrohConnectionSendStreamOrId::StreamExternalId(s) => { stream_id = s; },
            IrohConnectionSendStreamOrId::SendStream(ss) => { iroh_send_stream = Some(ss); }
        };
        let mut first_packet = true;
        loop {
            let packet_result = irs.read_packet().await;
            let packet_op: Option<IrohPacket> = match packet_result {
                Ok(packet) => packet,
                Err(e) => { error!("Read packet error: {}", e); res = Err(e); break; }
            };
            match packet_op {
                None => { debug!("Stream closed."); break },
                Some(packet) => {
                    if first_packet && let Some(s) = iroh_send_stream.take() {
                        stream_id = packet.id; first_packet = false;
                        if self.send_streams.contains_key(&stream_id) {
                            error!("Another stream with id {} already registered!", stream_id);
                        }
                        self.send_streams.insert(stream_id.clone(), s);
                    } else {
                        if stream_id != packet.id {
                            error!("Packet id inequal to stream id: {} != {}", stream_id, packet.id);
                        }
                        /* TODO: Froward data to WebSocket */
                    }
                }
            };
        }
        Ok(())
    }
}
