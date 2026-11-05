
use iroh::{EndpointAddr, endpoint::{Connection, Endpoint, ReadError, RecvStream, SendStream, WriteError, presets}};
use iroh_tickets::{Ticket, endpoint::EndpointTicket};
use log::{error, warn, info, debug};
use tokio;

use crate::{IrohRecvStream, IrohSendStream, IrohPacket, ALPN};

pub async fn test_relay_iroh_packet_receiver(stream: RecvStream) {
    let mut rs = IrohRecvStream::new(stream);
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

pub async fn test_relay_iroh_connection_handler(conn: Connection) {
    loop {
        let ret_stream = conn.accept_uni().await;
        if let Err(e) = ret_stream {
            error!("Error while waiting for stream: {}", e);
            break;
        }
        let stream = ret_stream.unwrap();
        debug!("Test relay: Spawning stream handler.");
        tokio::spawn(test_relay_iroh_packet_receiver(stream));
    }
}

pub async fn test_relay_handler(endpoint: Endpoint) {
    loop {
        let ret_incoming = endpoint.accept().await;
        if ret_incoming.is_none() { info!("No more connection to accept, breaking."); break; }
        let ret_acc = ret_incoming.unwrap().accept();
        if let Err(e) = ret_acc { info!("Error while accepting connection: {}", e); continue; }
        let ret_con = ret_acc.unwrap().await;
        if let Err(e) = ret_con { info!("Error while remote connection: {}", e); continue; }
        let conn = ret_con.unwrap();
        debug!("Test relay: Spawning connection handler.");
        tokio::spawn(test_relay_iroh_connection_handler(conn));
    }
    endpoint.close().await;
}

pub async fn test_client_iroh_packet_sender(addr: EndpointAddr) {
    debug!("Test client started. Connecting to: {:?}", addr);
    let ret_ep = Endpoint::bind(presets::N0).await;
    if let Err(e) = ret_ep {
        error!("Error while binding a test client endpoint: {}", e);
        return
    }
    let ep = ret_ep.unwrap();
    let ret_conn = ep.connect(addr, ALPN).await;
    if let Err(e) = ret_conn {
        error!("Error while connect a test client endpoint to a relay: {}", e);
        ep.close().await;
        ep.closed().await;
        return
    }
    let conn = ret_conn.unwrap();
    let ret_stream = conn.open_uni().await;
    if let Err(e) = ret_stream {
        error!("Error while opening a test sending stream to a relay: {}", e);
        conn.close(0u32.into(), &[]);
        conn.closed().await;
        return
    }
    let stream = ret_stream.unwrap();
    let mut sstream = IrohSendStream::new(stream);
    let packet = IrohPacket::new(13, "id123".to_string(), "Kubuś Puchatek".to_string());
    let ret_send = sstream.send_packet(&packet).await;
    if let Err(e) = ret_send { error!("Error while sending test packet to relay: {}", e); }
    sstream.finish();
    conn.closed().await;
    ep.close().await;
    debug!("Test client closed.");
}
