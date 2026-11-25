//! Static PID-1 / socketpair binary entrypoint for `aos-guest`.

#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    use std::path::PathBuf;
    use std::thread;
    use std::time::Duration;

    use aos_guest::cgroup::DEFAULT_WORKLOAD_CGROUP;
    use aos_guest::linux_backend::LinuxGuestBackend;
    use aos_guest::linux_sys;
    use aos_guest::server::AgentServer;

    let mut vsock_port: u32 = 5000;
    let mut socketpair_fd: Option<i32> = None;
    let mut workload_cgroup = PathBuf::from(DEFAULT_WORKLOAD_CGROUP);
    let mut no_cgroup = false;
    let mut exec_cgroup_fds: Option<(i32, i32)> = None;
    let mut pid1_mode = std::process::id() == 1;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--vsock-port" => {
                let val = args
                    .next()
                    .ok_or("missing value for --vsock-port")?;
                vsock_port = val.parse()?;
            }
            "--socketpair-fd" => {
                let val = args
                    .next()
                    .ok_or("missing value for --socketpair-fd")?;
                socketpair_fd = Some(val.parse()?);
            }
            "--workload-cgroup" => {
                let val = args
                    .next()
                    .ok_or("missing value for --workload-cgroup")?;
                workload_cgroup = PathBuf::from(val);
            }
            "--no-cgroup" => {
                no_cgroup = true;
            }
            "--exec-cgroup-fds" => {
                let val = args
                    .next()
                    .ok_or("missing value for --exec-cgroup-fds")?;
                let (procs, kill) = val
                    .split_once(',')
                    .ok_or("--exec-cgroup-fds expects PROCS_FD,KILL_FD")?;
                exec_cgroup_fds = Some((procs.parse()?, kill.parse()?));
            }
            "--pid1" => {
                pid1_mode = true;
            }
            "--help" | "-h" => {
                eprintln!(
                    "aos-guest [--vsock-port PORT | --socketpair-fd FD] [--workload-cgroup PATH] [--no-cgroup] [--exec-cgroup-fds PROCS_FD,KILL_FD] [--pid1]"
                );
                return Ok(());
            }
            other => {
                return Err(format!("unknown argument: {other}").into());
            }
        }
    }

    if pid1_mode {
        linux_sys::mount_pid1_filesystems();
        if let Err(err) = linux_sys::bring_up_loopback() {
            eprintln!("aos-guest: warning: failed to bring up loopback interface lo: {err}");
        }
        // Background orphan reaper for orphaned grandchildren when running as PID 1.
        // Coordinates with `ActiveChildren` so direct Exec/hook children are never stolen.
        thread::Builder::new()
            .name("aos-guest-reaper".to_owned())
            .spawn(|| loop {
                linux_sys::reap_orphans_nonblocking();
                thread::sleep(Duration::from_millis(50));
            })?;
    }

    let backend = match exec_cgroup_fds {
        Some((procs, kill)) => LinuxGuestBackend::with_inherited_exec_cgroup(procs, kill)?,
        None => LinuxGuestBackend::new(workload_cgroup, !no_cgroup),
    };
    if !no_cgroup && exec_cgroup_fds.is_none() {
        let _ = backend.cgroup().ensure_root();
    }

    let mut server = AgentServer::new(backend);

    if let Some(fd) = socketpair_fd {
        let (mut reader, mut writer) = linux_sys::stream_from_inherited_fd(fd)?;
        server.serve_connection(&mut reader, &mut writer)?;
        return Ok(());
    }

    // Firecracker vsock loop: accepts repeated host connections so snapshot-restored
    // clones seamlessly reconnect while AgentServer preserves Frozen state.
    let listener = linux_sys::VsockListener::bind(vsock_port)?;
    loop {
        match listener.accept() {
            Ok((mut reader, mut writer)) => {
                if let Err(err) = server.serve_connection(&mut reader, &mut writer) {
                    eprintln!("aos-guest: vsock connection closed with error: {err}");
                }
            }
            Err(err) => {
                eprintln!("aos-guest: vsock accept error: {err}");
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    Err("aos-guest runtime daemon targets Linux guests (use `cargo test -p aos-guest` on host platforms)".into())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("aos-guest fatal: {err}");
        std::process::exit(1);
    }
}
