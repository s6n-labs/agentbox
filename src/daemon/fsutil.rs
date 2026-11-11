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

/// Receives the three stdio fds the CLI sends with `SCM_RIGHTS`.
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
            // SAFETY: the kernel just handed us this descriptor; nothing else owns it.
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };
            fcntl(&fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
            fds.push(fd);
        }
    }

    anyhow::ensure!(fds.len() == 3, "expected 3 fds, got {}", fds.len());
    Ok(fds)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt, symlink};

    use super::*;

    #[test]
    fn pin_dir_creates_missing_directories() {
        let base = tempfile::tempdir().unwrap();

        pin_dir(base.path(), Path::new("a/b/c"), None).unwrap();
        // Existing directories are fine too.
        pin_dir(base.path(), Path::new("a/b"), None).unwrap();

        assert!(base.path().join("a/b/c").is_dir());
    }

    #[test]
    fn pin_dir_opens_the_directory_itself() {
        let base = tempfile::tempdir().unwrap();

        let fd = pin_dir(base.path(), Path::new("./out"), None).unwrap();

        let pinned = std::fs::File::from(fd).metadata().unwrap();
        let expected = std::fs::metadata(base.path().join("out")).unwrap();
        assert_eq!(pinned.ino(), expected.ino());
    }

    #[test]
    fn pin_dir_refuses_a_symlink_as_the_directory() {
        let base = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), base.path().join("out")).unwrap();

        let error = pin_dir(base.path(), Path::new("out"), None).unwrap_err();

        assert!(error.contains("symlinks are not allowed"), "{error}");
    }

    #[test]
    fn pin_dir_refuses_a_symlink_on_the_way() {
        let base = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), base.path().join("link")).unwrap();

        assert!(pin_dir(base.path(), Path::new("link/sub"), None).is_err());

        // Nothing was created on the other side of the link.
        assert!(!outside.path().join("sub").exists());
    }

    #[test]
    fn pin_dir_refuses_a_file_in_the_way() {
        let base = tempfile::tempdir().unwrap();
        std::fs::write(base.path().join("out"), "a file").unwrap();

        assert!(pin_dir(base.path(), Path::new("out"), None).is_err());
    }

    #[test]
    fn write_in_dir_does_not_follow_symlinks() {
        let base = tempfile::tempdir().unwrap();
        let victim = base.path().join("victim");
        std::fs::write(&victim, "untouched").unwrap();

        let dir = pin_dir(base.path(), Path::new("private"), None).unwrap();
        symlink(&victim, base.path().join("private/.gitignore")).unwrap();
        write_in_dir(&dir, ".gitignore", b"*\n");

        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "untouched");
    }

    #[test]
    fn write_in_dir_writes_into_the_pinned_directory() {
        let base = tempfile::tempdir().unwrap();

        let dir = pin_dir(base.path(), Path::new("private"), None).unwrap();
        write_in_dir(&dir, ".gitignore", b"*\n");

        let written = std::fs::read_to_string(base.path().join("private/.gitignore")).unwrap();
        assert_eq!(written, "*\n");
    }

    #[test]
    fn write_atomic_replaces_the_file_and_leaves_no_temporary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("env.sh");

        write_atomic(&path, "first").unwrap();
        write_atomic(&path, "second").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "second");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);

        // Readable by the sandbox user, whoever that is.
        let mode = std::fs::metadata(&path).unwrap().mode();
        assert_eq!(mode & 0o777, 0o644);
    }

    #[test]
    fn stdio_is_received_over_a_socket() {
        use std::io::{IoSlice, Read, Write};

        use nix::sys::socket::{ControlMessage, sendmsg};

        let (sender, receiver) = UnixStream::pair().unwrap();
        let (mut pipe_read, pipe_write) = std::io::pipe().unwrap();

        // Send the write end three times, like a CLI sending stdin, stdout and stderr.
        let fds = [pipe_write.as_raw_fd(); 3];
        sendmsg::<()>(
            sender.as_raw_fd(),
            &[IoSlice::new(b"x")],
            &[ControlMessage::ScmRights(&fds)],
            MsgFlags::empty(),
            None,
        )
        .unwrap();

        let received = recv_stdio(&receiver).unwrap();
        assert_eq!(received.len(), 3);

        // The received descriptors really are the pipe.
        drop(pipe_write);
        let mut stderr = std::fs::File::from(received.into_iter().nth(2).unwrap());
        stderr.write_all(b"hello").unwrap();
        drop(stderr);

        let mut text = String::new();
        pipe_read.read_to_string(&mut text).unwrap();
        assert_eq!(text, "hello");
    }

    #[test]
    fn a_message_without_three_descriptors_is_rejected() {
        use std::io::Write;

        let (mut sender, receiver) = UnixStream::pair().unwrap();
        sender.write_all(b"x").unwrap();

        assert!(recv_stdio(&receiver).is_err());
    }
}
