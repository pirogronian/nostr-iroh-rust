
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tokio_websockets::tls::MaybeTlsStream;

pub enum VariantStream {
    Plain(TcpStream),
    Tls(TlsStream<TcpStream>),
    MaybeTls(MaybeTlsStream<TcpStream>)
}

impl AsyncRead for VariantStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            VariantStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            VariantStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
            VariantStream::MaybeTls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for VariantStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            VariantStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            VariantStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
            VariantStream::MaybeTls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            VariantStream::Plain(s) => Pin::new(s).poll_flush(cx),
            VariantStream::Tls(s) => Pin::new(s).poll_flush(cx),
            VariantStream::MaybeTls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            VariantStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            VariantStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
            VariantStream::MaybeTls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}
