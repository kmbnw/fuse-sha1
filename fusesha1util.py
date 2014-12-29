# Calculate an SHA1 hex digest for a file
# Copyright (C) 2009-2011 Krysta Bouzek  <nwkrystab@gmail.com>
#
#
#    This program can be distributed under the terms of the GNU LGPL.
#    See the file COPYING.
#

import hashlib
import logging
import os

from contextlib import contextmanager
from pysqlite2 import dbapi2 as sqlite

LOG_FILENAME = "LOG"
logging.basicConfig(filename=LOG_FILENAME,level=logging.WARN,)

def fileChecksum(path, checksum_func=hashlib.sha1):
  '''Returns a hash for the file located at the given path.

    path - The path to the file
    checksum_func - the checksum function to call.  Defaults to hashlib.sha1.
  '''
  if None == path:
    raise IOError("fileChecksum requires a path to be specified")
  with open(path, 'rb') as fobj:
    m = checksum_func()
    chunksize = 128 * m.block_size
    while True:
      d = fobj.read(chunksize)
      if not d:
        break
      m.update(d)
    return m.hexdigest()

def safeMakedirs(path):
  """Checks the parent of the path (via dirname) and makes sure it exists by calling os.makedirs.
  Returns the parent directory name."""
  if None == path:
    raise OSError("safeMakedirs requires a path to be specified")
  parent = os.path.dirname(path)
  if not os.path.exists(parent):
    os.makedirs(parent)
  return parent

def safeUnlink(path):
  """Checks that path exists and if so, unlinks it"""
  if None == path:
    raise OSError("safeUnlink requires a path to be specified")
  if os.path.exists(path):
    os.unlink(path)

def dstWithSubdirectory(src, dstdir):
  """Returns a destination filename that includes the subdirectory structure that is not common
  to both src and dstdir.  This can be used to determine where to move a file including
  subdirectories."""
  if (None == src) or ("" == src):
    raise IOError("dstWithSubdirectory requires src to be specified")

  if (None == dstdir) or ("" == dstdir):
    raise IOError("dstWithSubdirectory requires dstdir to be specified")

  absSrc = os.path.abspath(src)
  dstdir = os.path.abspath(dstdir)
  # remove any common prefixes so that we can create a subdirectory structure
  prefix = os.path.commonprefix([dstdir, absSrc])

  if not prefix.endswith("/"):
    prefix = prefix + "/"
  newdst = os.path.join(dstdir, absSrc.replace(prefix, '', 1))

  if newdst == absSrc:
    raise IOError("Unable to determine new destination; %s and %s are the same path" % (newdst, absSrc))

  return newdst

def moveFile(src, dst, rmEmptyDirs = True):
  """Moves the file at src to the dstdir, removing any common prefixes between src
  and dstdir.  if rmEmptyDirs is true, then this will remove the parent directory for src after the
  file move if the directory is empty."""
  safeMakedirs(dst)

  logging.info("Moving %s to %s" % (src, dst))
  os.rename(src, dst)

  oldparent = os.path.dirname(src)
  if len(os.listdir(oldparent)) <= 0:
    os.rmdir(oldparent)

def symlinkFile(target, link):
  """Symlink link to target."""
  if (None == target) or (not os.path.exists(target)):
    raise OSError("symlinkFile requires a target to be specified")

  if (None == link) or ("" == link):
    raise OSError("symlinkFile requires a link path to be specified")

  absTarget = os.path.abspath(target)
  absLink = os.path.abspath(link)
  safeMakedirs(absLink)
  safeUnlink(absLink)
  logging.info("Symlinking %s to %s" % (absLink, absTarget))
  os.symlink(absTarget, absLink)

def linkFile(target, link):
  """Creates a hard link from link to target.  Both must be on the same filesystem.  If both
  target and link have the same inode, this is a no-op.
  """
  if (None == target) or (not os.path.exists(target)):
    raise OSError("linkFile requires a target to be specified")

  if (None == link) or ("" == link):
    raise OSError("linkFile requires a link path to be specified")

  sameFile = os.path.exists(link)
  if sameFile:
    sameFile = (os.stat(target).st_ino == os.stat(link).st_ino)

  if not sameFile:
    absTarget = os.path.abspath(target)
    absLink = os.path.abspath(link)
    safeMakedirs(absLink)
    safeUnlink(absLink)
    logging.info("Linking %s to %s" % (absLink, absTarget))
    os.link(absTarget, absLink)

def isLinkAsNum(path):
  """ Returns 1 if the given path is a symlink, 0 otherwise """
  if os.path.islink(path):
    return 1
  return 0

@contextmanager
def sqliteConn(database):
  """Opens an SQLite connection to the given database file and provides a cursor that can be used
for operations on that SQLite connection.  The connection and cursor will always be closed, any
exceptions trapped at this level will be reraised, and the connection will be committed if the SQL
op succeeds or rolled back if it does not.  Can be used with the Python 'with' keyword."""
  with sqlite.connect(database, timeout=30.0) as connection:
    cursor = None
    try:
      # return the cursor
      cursor = connection.cursor()
      yield cursor
    except:
      if connection != None:
        connection.rollback()
      raise
    else:
      connection.commit()
    finally:
      if cursor != None:
        cursor.close()

# Wraps a code block so that if an exception occurs, it is logged
class ewrap:
  def __init__(self, funcName):
    self.funcName = funcName
  def __enter__(self):
    return self.funcName
  def __exit__(self, type, value, trace):
    if None != value:
      logging.error("!! Exception in %s: %s" % (self.funcName, value))
