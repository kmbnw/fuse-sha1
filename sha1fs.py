#!/usr/bin/env python

# SHA1 checksum filesystem.  Calculates checksums for all files, storing them in a database given
# by the --database argument.  Any files removed/added/modified via this script will have
# their checksums updated on release and unlink.
#
# Enhanced version of xmp.py (part of the FUSE Python download), with various bits and pieces
# copied verbatim.
# Docstring, several other comments, and much general understanding taken from templatefs.py
# by Matt Giuca (https://code.launchpad.net/~mgiuca/fuse-python-docs/trunk).
#
# Copyright (C) 2009-2011 Krysta Bouzek  <nwkrystab@gmail.com>
#
#
#    This program can be distributed under the terms of the GNU LGPL.
#    See the file COPYING.
#

import os, sys
from os.path import join
from errno import *
from stat import *
import fcntl
# pull in some spaghetti to make this stuff work without fuse-py being installed
try:
  import _find_fuse_parts
except ImportError:
  pass
import fuse
from fuse import Fuse

import xmp
from xmp import Xmp
from xmp import flag2mode

from fusesha1util import ewrap
from sha1db import Sha1DB

from pysqlite2 import dbapi2 as sqlite
import logging

# xmp.py has a number of useful FUSE version checks and other assertions that we rely on here

LOG_FILENAME = "LOG"
logging.basicConfig(filename=LOG_FILENAME,level=logging.INFO,)

# Converts OS R/W flags to filesystem R/W flags; here to support access controls
def flag2accessflag(flags):
  md = {os.O_RDONLY: os.R_OK, os.O_WRONLY: os.W_OK, os.O_RDWR: (os.W_OK | os.R_OK)}
  m = md[flags & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR)]

  return m

# The required FUSE class
class Sha1FS(Xmp):
  def __init__(self, *args, **kw):
    Xmp.__init__(self, *args, **kw)

    # Initialize so we can look for this option even if the user didn't specify it
    self.rescan = False
    # Null all the other options so we can correctly handle errors if they are missing
    self.database = None
    self.root = None
    self.useMd5 = False

  # Initializes the database for this class.  If rescan is enabled, this will scan for new/updated files
  # The latter operates on the root filesystem directly here as it is basically a non FUSE operation
  def initDB(self):
    self.sha1db = Sha1DB(self.database, self.useMd5)

    if (self.rescan):
      self.sha1db.updateAllChecksums(self.root)

  def getattr(self, path):
    """
    Retrieves information about a file (the "stat" of a file).
    Returns a fuse.Stat object containing details about the file or
    directory.
    Returns -errno.ENOENT if the file is not found, or another negative
    errno code if another error occurs.
    """
    with ewrap("getattr"):
      if os.path.exists("." + path):
        logging.debug("getattr: %s" % path)
        return Xmp.getattr(self, path)
      else:
        logging.debug("Skipping getattr for nonexistent path %s" % path)
        return -ENOENT

  def readlink(self, path):
    """
    Get the target of a symlink.
    Returns a bytestring with the contents of a symlink (its target).
    May also return an int error code.
    """
    with ewrap("readlink"):
      logging.debug("readlink: %s" % path)
      return Xmp.readlink(self, path)

  def readdir(self, path, offset):
    """
    Generator function. Produces a directory listing.
    Yields individual fuse.Direntry objects, one per file in the
    directory. Should always yield at least "." and "..".
    Should yield nothing if the file is not a directory or does not exist.
    (Does not need to raise an error).

    offset: I don't know what this does, but I think it allows the OS to
    request starting the listing partway through (which I clearly don't
    yet support). Seems to always be 0 anyway.
    """
    with ewrap("readdir"):
      logging.debug("readdir: %s (offset %s)" % (path, offset))
      return Xmp.readdir(self, path, offset)

  def unlink(self, path):
    """Deletes a file."""
    with ewrap("unlink"):
      logging.debug("unlink: %s" % path)
      Xmp.unlink(self, path)
      self.sha1db.removeChecksum(self.root + path)

  def rmdir(self, path):
    """Deletes a directory."""
    with ewrap("rmdir"):
      logging.debug("rmdir: %s" % path)
      Xmp.rmdir(self, path)

  def symlink(self, target, name):
    """
    Creates a symbolic link from path to target.

    The 'name' is a regular path like any other method (absolute, but
    relative to the filesystem root).
    The 'target' is special - it works just like any symlink target. It
    may be absolute, in which case it is absolute on the user's system,
    NOT the mounted filesystem, or it may be relative. It should be
    treated as an opaque string - the filesystem implementation should not
    ever need to follow it (that is handled by the OS).

    Hence, if the operating system creates a link FROM this system TO
    another system, it will call this method with a target pointing
    outside the filesystem.
    If the operating system creates a link FROM some other system TO this
    system, it will not touch this system at all (symlinks do not depend
    on the target system unless followed).
    """
    with ewrap("symlink"):
      logging.debug("symlink: target %s, name: %s" % (target, name))
      Xmp.symlink(self, target, name)

  def rename(self, old, new):
    """
    Moves a file from old to new. (old and new are both full paths, and
    may not be in the same directory).

    Note that both paths are relative to the mounted file system.
    If the operating system needs to move files across systems, it will
    manually copy and delete the file, and this method will not be called.
    """
    with ewrap("rename"):
      logging.debug("rename: target %s, name: %s" % (self.root + old, self.root + new))
      Xmp.rename(self, old, new)
      self.sha1db.updatePath(self.root + old, self.root + new)

  def link(self, target, name):
    """
    Creates a hard link from name to target. Note that both paths are
    relative to the mounted file system. Hard-links across systems are not
    supported.
    """
    with ewrap("link"):
      logging.debug("link: target %s, name: %s" % (target, name))
      Xmp.link(self, target, name)

  def chmod(self, path, mode):
    """Changes the mode of a file or directory."""
    with ewrap("chmod"):
      logging.debug("chmod: %s (mode %s)" % (path, oct(mode)))
      Xmp.chmod(self, path, mode)

  def chown(self, path, user, group):
    """Changes the owner of a file or directory."""
    with ewrap("chown"):
      logging.debug("chown: %s (uid %s, gid %s)" % (path, user, group))
      Xmp.chown(self, path, user, group)

  def truncate(self, path, len):
    # rewritten to ensure file closing
    with ewrap("truncate"):
      with file("." + path, "a") as f:
        f.truncate(len)

  def mknod(self, path, mode, rdev):
    """
    Creates a non-directory file (or a device node).
    mode: Unix file mode flags for the file being created.
    rdev: Special properties for creation of character or block special
        devices (I've never gotten this to work).
        Always 0 for regular files or FIFO buffers.
    """
    # Note: mode & 0770000 gives you the non-permission bits.
    # Common ones:
    # S_IFREG:  0100000 (A regular file)
    # S_IFIFO:  010000  (A fifo buffer, created with mkfifo)

    # Potential ones (I have never seen them):
    # Note that these could be made by copying special devices or sockets
    # or using mknod, but I've never gotten FUSE to pass such a request
    # along.
    # S_IFCHR:  020000  (A character special device, created with mknod)
    # S_IFBLK:  060000  (A block special device, created with mknod)
    # S_IFSOCK: 0140000 (A socket, created with mkfifo)

    # Also note: You can use self.GetContext() to get a dictionary
    #   {'uid': ?, 'gid': ?}, which tells you the uid/gid of the user
    #   executing the current syscall. This should be handy when creating
    #   new files and directories, because they should be owned by this
    #   user/group.
    with ewrap("mknod"):
      logging.debug("mknod: %s (mode %s, rdev %s)" % (path, oct(mode), rdev))
      Xmp.mknod(self, path, mode, rdev)

  def mkdir(self, path, mode):
    """
    Creates a directory.
    mode: Unix file mode flags for the directory being created.
    """
    # Note: mode & 0770000 gives you the non-permission bits.
    # Should be S_IDIR (040000); I guess you can assume this.
    # Also see note about self.GetContext() in mknod.
    with ewrap("mkdir"):
      logging.debug("mkdir: %s (mode %s)" % (path, oct(mode)))
      Xmp.mkdir(self, path, mode)

  def utime(self, path, times):
    """
    Sets the access and modification times on a file.
    times: (atime, mtime) pair. Both ints, in seconds since epoch.
    Deprecated in favour of utimens.
    """
    with ewrap("utime"):
      atime, mtime = times
      logging.debug("utime: %s (atime %s, mtime %s)" % (path, atime, mtime))
      Xmp.utime(self, path, times)

  def access(self, path, flags):
    """
    Checks permissions for accessing a file or directory.
    mode: As described in man 2 access (Linux Programmer's Manual).
        Either os.F_OK (test for existence of file), or ORing of
        os.R_OK, os.W_OK, os.X_OK (test if file is readable, writable and
        executable, respectively. Must pass all tests).
    Should return 0 for "allowed", or -errno.EACCES if disallowed.
    May not always be called. For example, when opening a file, open may
    be called and access avoided.
    """
    # rewritten to use flag2accessflag and explicitly return 0 in the case of allowed access
    with ewrap("access"):
      logging.debug("access: %s (flags %s)" % (path, oct(flags)))
      if not os.access("." + path, flag2accessflag(flags)):
        return -EACCES
      else:
        return 0

  def statfs(self):
    """
    Should return an object with statvfs attributes (f_bsize, f_frsize...).
    Eg., the return value of os.statvfs() is such a thing (since py 2.2).
    If you are not reusing an existing statvfs object, start with
    fuse.StatVFS(), and define the attributes.

    To provide usable information (ie., you want sensible df(1)
    output, you are suggested to specify the following attributes:

        - f_bsize - preferred size of file blocks, in bytes
        - f_frsize - fundamental size of file blcoks, in bytes
            [if you have no idea, use the same as blocksize]
        - f_blocks - total number of blocks in the filesystem
        - f_bfree - number of free blocks
        - f_files - total number of file inodes
        - f_ffree - nunber of free file inodes
    """
    with ewrap("statfs"):
      return Xmp.statfs(self)

  def fsinit(self):
    """
    Will be called after the command line arguments are successfully
    parsed. It doesn't have to exist or do anything, but as options to the
    filesystem are not available in __init__, fsinit is more suitable for
    the mounting logic than __init__.

    To access the command line passed options and nonoption arguments, use
    cmdline.

    The mountpoint is not stored in cmdline.
    """
    with ewrap("fsinit"):
      logging.debug("Nonoption arguments: " + str(self.cmdline[1]))


      #self.xyz = self.cmdline[0].xyz
      #if self.xyz != None:
      #   logging.debug("xyz set to '" + self.xyz + "'")
      #else:
      #   logging.debug("xyz not set")

      Xmp.fsinit(self)
      logging.debug("Filesystem %s mounted" % self.root)

  ### FILE OPERATION METHODS ###
  # Methods in this section are operations for opening files and working on
  # open files.
  # "open" and "create" are methods for opening files. They *may* return an
  # arbitrary Python object (not None or int), which is used as a file
  # handle by the methods for working on files.
  # All the other methods (fgetattr, release, read, write, fsync, flush,
  # ftruncate and lock) are methods for working on files. They should all be
  # prepared to accept an optional file-handle argument, which is whatever
  # object "open" or "create" returned.

  # Rewritten by Krysta Bouzek to avoid use of a File class, which was making it difficult to
  # access the SQLite database.  Most of the code came from XmpFile, with some exceptions,
  # notable open(), which required some funky access checking
  ##################################
  def open(self, path, flags):
    """
    Open a file for reading/writing, and check permissions.
    flags: As described in man 2 open (Linux Programmer's Manual).
        ORing of several access flags, including one of os.O_RDONLY,
        os.O_WRONLY or os.O_RDWR. All other flags are in os as well.

    On success, *may* return an arbitrary Python object, which will be
    used as the "fh" argument to all the file operation methods on the
    file. Or, may just return None on success.
    On failure, should return a negative errno code.
    Should return -errno.EACCES if disallowed.
    """
    with ewrap("open"):
      mode = flag2mode(flags)
      logging.debug("open: %s (flags %s) (mode %s)" % (path, oct(flags), mode))

      fh = os.fdopen(os.open("." + path, flags), flag2mode(flags))

      if fh is None:
        return -ENOENT

      context = self.GetContext()
      accessflags = flag2accessflag(flags)
      #if not fh.stat.check_permission(context['uid'], context['gid'], accessflags):
      if not os.access("." + path, accessflags):
        return -EACCES

      return fh


  # def create(self, path, mode, rdev):
    # """
    # Creates a file and opens it for writing.
    # Will be called in favour of mknod+open, but it's optional (OS will
    # fall back on that sequence).
    # mode: Unix file mode flags for the file being created.
    # rdev: Special properties for creation of character or block special
        # devices (I've never gotten this to work).
        # Always 0 for regular files or FIFO buffers.
    # See "open" for return value.
    # """
    # logging.debug("create: %s (mode %s, rdev %s)" % (path,oct(mode),rdev))
    # self.mknod(path, mode, rdev)
    # return self.open(path, flags)

  def read(self, path, size, offset, fh=None):
    """
    Get all or part of the contents of a file.
    size: Size in bytes to read.
    offset: Offset in bytes from the start of the file to read from.
    Does not need to check access rights (operating system will always
    call access or open first).
    Returns a byte string with the contents of the file, with a length no
    greater than 'size'. May also return an int error code.

    If the length of the returned string is 0, it indicates the end of the
    file, and the OS will not request any more. If the length is nonzero,
    the OS may request more bytes later.
    To signal that it is NOT the end of file, but no bytes are presently
    available (and it is a non-blocking read), return -errno.EAGAIN.
    If it is a blocking read, just block until ready.
    """
    with ewrap("read"):
      logging.debug("read: %s (size %s, offset %s, fh %s)" % (path, size, offset, fh))
      fh.seek(offset)
      return fh.read(size)

  def write(self, path, buf, offset, fh=None):
    """
    Write over part of a file.
    buf: Byte string containing the text to write.
    offset: Offset in bytes from the start of the file to write to.
    Does not need to check access rights (operating system will always
    call access or open first).
    Should only overwrite the part of the file from offset to
    offset+len(buf).

    Must return an int: the number of bytes successfully written (should
    be equal to len(buf) unless an error occured). May also be a negative
    int, which is an errno code.
    """
    with ewrap("write"):
      logging.debug("write: %s (offset %s, fh %s)" % (path, offset, fh))
      logging.debug("  buf: %r" % buf)
      fh.seek(offset)
      fh.write(buf)
      return len(buf)

  def fgetattr(self, path, fh=None):
    """
    Retrieves information about a file (the "stat" of a file).
    Same as Fuse.getattr, but may be given a file handle to an open file,
    so it can use that instead of having to look up the path.
    """
    with ewrap("fgetattr"):
      logging.debug("fgetattr: %s (fh %s)" % (path, fh))
      return os.fstat(fh.fileno())

  def ftruncate(self, path, size, fh=None):
    """
    Shrink or expand a file to a given size.
    Same as Fuse.truncate, but may be given a file handle to an open file,
    so it can use that instead of having to look up the path.
    """
    with ewrap("ftruncate"):
      logging.debug("ftruncate: %s (size %s, fh %s)" % (path, size, fh))
      fh.truncate(size)

  def _fflush(self, fh):
    if 'w' in fh.mode or 'a' in fh.mode:
      fh.flush()

  def flush(self, path, fh=None):
    """
    Flush cached data to the file system.
    This is NOT an fsync (I think the difference is fsync goes both ways,
    while flush is just one-way).
    """
    with ewrap("flush"):
      logging.debug("flush: %s (fh %s)" % (path, fh))
      self._fflush(fh)
      # cf. xmp_flush() in fusexmp_fh.c
      os.close(os.dup(fh.fileno()))

  def release(self, path, flags, fh=None):
    """
    Closes an open file. Allows filesystem to clean up.
    flags: The same flags the file was opened with (see open).
    """
    with ewrap("release"):
      logging.debug("release: %s (flags %s, fh %s)" % (path, oct(flags), fh))
      fh.close()

      if not self._blacklisted(path):
        saved = False
        count = 0
        while (not saved and count < 5):
          count += 1
          try:
            self.sha1db.updateChecksum(self.root + path)
            saved = True
          except Exception as einst:
            logging.warn("Update failed; trying again")

        if not saved:
          logging.error("Unable to update checksum; quitting")

  def fsync(self, path, datasync, fh=None):
    """
    Synchronises an open file.
    datasync: If True, only flush user data, not metadata.
    """
    with ewrap("fsync"):
      logging.debug("fsync: %s (datasync %s, fh %s)" % (path, datasync, fh))
      self._fflush(fh)
      if datasync and hasattr(os, 'fdatasync'):
        os.fdatasync(fh.fileno())
      else:
        os.fsync(fh.fileno())

  def _blacklisted(self, path):
    """Returns true if the path should not be kept in the checksum list."""
    return path.find(".Trash") >= 0

  def main(self, *a, **kw):
    #self.file_class = self.Sha1File
    return Fuse.main(self, *a, **kw)

def main():
  usage = """
Userspace SHA1 checksum FS: mirror the filesystem tree, adding and updating file checksums.

  """ + Fuse.fusage

  server = Sha1FS(version="%prog " + fuse.__version__,
                  usage=usage,
                  dash_s_do='setsingle')

  server.parser.add_option(mountopt="root", metavar="PATH", default='/',
    help="mirror filesystem from under PATH [default: %default]")

  server.parser.add_option("--database",
                         dest = "database",
                         help = "location of SQLite checksum database (required)",
                         metavar="DATABASE")
  server.parser.add_option("--rescan",
                         action = "store_true",
                         dest = "rescan",
                         default = False,
                         help = "(Re)calculate checksums at mount time.")

  server.parser.add_option("--use-md5",
                         action = "store_true",
                         dest = "useMd5",
                         default = False,
                         help = "Use the (faster) MD5 checksum instead of SHA1.")

  server.parse(values=server, errex=1)
  if not server.fuse_args.mountpoint:
    server.parser.print_help()
    print >> sys.stderr, "Error: missing FUSE mountpoint."
    sys.exit(2)

  if not server.database:
    server.parser.print_help()
    print >> sys.stderr, "Error: Missing database argument."
    sys.exit(2)

  if not server.root:
    server.parser.print_help()
    print >> sys.stderr, "Error: Missing root filesystem."
    sys.exit(2)

  try:
    if server.fuse_args.mount_expected():
      #print "Mounting", server.root, "at", server.fuse_args.mountpoint
      server.initDB()
      os.chdir(server.root)
  except OSError:
    print >> sys.stderr, "can't enter root of underlying filesystem"
    sys.exit(1)

  server.main()

if __name__ == '__main__':
  main()
