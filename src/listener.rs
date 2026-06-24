use std::{
    io,
    net::{IpAddr, SocketAddr},
};

use tokio::net::{TcpListener, TcpSocket};

#[cfg(unix)]
use std::os::fd::AsRawFd;

pub fn bind_tcp_listener(addr: SocketAddr, backlog: u32) -> io::Result<TcpListener> {
    bind_tcp_listener_with_reuse_port(addr, backlog, false)
}

pub fn bind_tcp_listeners(
    addr: SocketAddr,
    backlog: u32,
    shards: usize,
) -> io::Result<Vec<TcpListener>> {
    let shards = shards.max(1);
    let reuse_port = shards > 1;
    let mut listeners = Vec::with_capacity(shards);
    let mut bind_addr = addr;
    for idx in 0..shards {
        let listener = bind_tcp_listener_with_reuse_port(bind_addr, backlog, reuse_port)?;
        if idx == 0 && addr.port() == 0 {
            bind_addr = listener.local_addr()?;
        }
        listeners.push(listener);
    }
    Ok(listeners)
}

fn bind_tcp_listener_with_reuse_port(
    addr: SocketAddr,
    backlog: u32,
    reuse_port: bool,
) -> io::Result<TcpListener> {
    let socket = match addr.ip() {
        IpAddr::V4(_) => TcpSocket::new_v4()?,
        IpAddr::V6(_) => TcpSocket::new_v6()?,
    };
    socket.set_reuseaddr(true)?;
    if reuse_port {
        set_reuse_port(&socket)?;
    }
    socket.bind(addr)?;
    socket.listen(backlog.max(1))
}

#[cfg(unix)]
fn set_reuse_port(socket: &TcpSocket) -> io::Result<()> {
    let value: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_reuse_port(_socket: &TcpSocket) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "accept_shards above 1 requires SO_REUSEPORT support",
    ))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::{bind_tcp_listener, bind_tcp_listeners};

    #[tokio::test]
    async fn binds_ipv4_listener_with_custom_backlog() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = bind_tcp_listener(addr, 32).unwrap();

        assert_eq!(listener.local_addr().unwrap().ip(), addr.ip());
    }

    #[tokio::test]
    async fn binds_reuse_port_listener_shards_on_one_port() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listeners = bind_tcp_listeners(addr, 32, 2).unwrap();

        assert_eq!(listeners.len(), 2);
        assert_eq!(
            listeners[0].local_addr().unwrap(),
            listeners[1].local_addr().unwrap()
        );
    }
}
