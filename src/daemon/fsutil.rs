//! Small filesystem and fd helpers.

use std::io::IoSliceMut;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Component, Path};

use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl, openat};
use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};
use nix::sys::stat::{Mode, mkdirat};
use nix::unistd::{Gid, Uid, fchown};

pub fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// Writes a world-readable file by renaming it into place, so readers never see half of it.
pub fn write_atomic(path: &Path, content: &str) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");

    std::fs::write(&tmp, content)?;
    set_mode(&tmp, 0o644)?;
    std::fs::rename(tmp, path)
}

/// Creates `rel` under `base` and returns it opened, never following symlinks.
///
/// The agent controls the workdir. If a writable directory were looked up by path, the
/// agent could replace it with a symlink and have something else mounted read-write.
/// New directories are given to `owner` (uid, gid) if set.
pub fn pin_dir(base: &Path, rel: &Path, owner: Option<(u32, u32)>) -> Result<OwnedFd, String> {
    let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let describe = |e| {
        let path = base.join(rel);
        format!("{}: {e} (symlinks are not allowed here)", path.display())
    };

    let mut dir = nix::fcntl::open(base, flags, Mode::empty()).map_err(describe)?;

    for component in rel.components() {
        let Component::Normal(name) = component else {
            continue;
        };

        let created = mkdirat(&dir, name, Mode::from_bits_truncate(0o755)).is_ok();
        let child = openat(&dir, name, flags, Mode::empty()).map_err(describe)?;

        if let (true, Some((uid, gid))) = (created, owner) {
            let _ = fchown(&child, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)));
        }

        dir = child;
    }

    Ok(dir)
}

/// Writes `content` to `name` inside an already pinned directory.
pub fn write_in_dir(dir: &OwnedFd, name: &str, content: &[u8]) {
    let flags = OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;

    if let Ok(file) = openat(dir, name, flags, Mode::from_bits_truncate(0o644)) {
        let _ = nix::unistd::write(&file, content);
    }
}

/// Receives the three stdio fds the CLI sends with SCM_RIGHTS.
pub fn recv_stdio(socket: &UnixStream) -> anyhow::Result<Vec<OwnedFd>> {
    let mut byte = [0u8; 1];
    let mut iov = [IoSliceMut::new(&mut byte)];
    let mut space = nix::cmsg_space!([RawFd; 3]);

    let message = recvmsg::<()>(
        socket.as_raw_fd(),
        &mut iov,
        Some(&mut space),
        MsgFlags::empty(),
    )?;

    let mut fds = Vec::new();
    for control in message.cmsgs()? {
        let ControlMessageOwned::ScmRights(received) = control else {
            continue;
        };

        for raw in received {
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };
            fcntl(&fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
            fds.push(fd);
        }
    }

    anyhow::ensure!(fds.len() == 3, "expected 3 fds, got {}", fds.len());
    Ok(fds)
}
