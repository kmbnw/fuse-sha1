#!/usr/bin/python
# utility functions for dealing with MD5 hashing
# Copyright (C) 2009-2011 Krysta Bouzek  <nwkrystab@gmail.com>
#
#
#    This program can be distributed under the terms of the GNU LGPL.
#    See the file COPYING.
#

import os
import logging
import hashlib
from fusesha1util import fileChecksum, moveFile, sqliteConn, symlinkFile
from fusesha1util import isLinkAsNum, linkFile, dstWithSubdirectory

from optparse import OptionParser

LOG_FILENAME = "LOG"
logging.basicConfig(filename=LOG_FILENAME,level=logging.INFO,)
CHECKSUM_UPDATE = "insert or replace into files(path, chksum, symlink) values(?, ?, ?);"
LINK_UPDATE = "update files set link = ? where path = ?;"
# old path, new path, old path with %
PATH_UPDATE = "update files set path = replace(path, ?, ?) where path like ?;"
REMOVE_ROW = "delete from files where path = ?;"

class Sha1DB:
  # Creates a new Sha1DB.  If the database given does not exist, it will be created.
  def __init__(self, database, useMd5=False):
    self.database = database

    dbExists = os.path.exists(database)

    usingMd5 = useMd5
    if not dbExists:
      logging.info("Sha1DB initialized with connection string %s" % database)
      self._execSql("""create table if not exists files(
path varchar not null primary key,
chksum varchar not null,
symlink boolean default 0);""")
      self._execSql("create index csum_idx on files(chksum);")
      self._execSql("create table if not exists versioning(chksum_type varchar not null)");
      self._execSql("insert into versioning(chksum_type) values(?)", ("md5" if useMd5 else "sha1", ));
    else:
      # pull the checksum type out of the database
      with sqliteConn(self.database) as cursor:
        cursor.execute("select chksum_type from versioning")
        for row in cursor:
          (chksum_type, ) = row
          usingMd5 = "md5" == chksum_type

    self.checksum = hashlib.md5 if usingMd5 else hashlib.sha1

  def dedup(self, dupdir, doSymlink):
    """ Moves duplicate entries (based on checksum) into the dupdir.  Uses the entry's path to
    reconstruct a subdirectory hierarchy in dupdir.  This will remove any common prefixes
    between dupdir and the file path itself so as to make a useful subdirectory structure.
    If doSymlink is true, then the original paths of the files that were moved will be symlinked
    back to the canonical file; in addition, it will keep the file entry in the database rather than
    removing it."""
    logging.info("De-duping database")

    if os.path.exists(dupdir) and not len(os.listdir(dupdir)) <= 0:
      raise Exception("%s is not empty; refusing to move files" % dupdir)

    try:
      pathmap = {} # store duplicate paths keyed by file checksum

      with sqliteConn(self.database) as cursor:
        cursor.execute("""select chksum, path, link from files
where chksum in(
select chksum from files where symlink = 0 group by chksum having count(chksum) > 1)
and symlink = 0
and link = 1
order by chksum, link;""")
        for row in cursor:
          (chksum, path, islink) = row
          if not chksum in pathmap:
            # ensure existence of list for checksum
            pathmap[chksum] = []
          paths = pathmap[chksum]
          paths.append(path)

        for chksum, paths in pathmap.iteritems():
          # the query above will result in single rows for symlinked files, so fix that here
          # rather than mucking about with temp tables
          paths = filter(lambda path: not os.path.islink(path), paths)

          # we'll have at least two elements due to the inner part of the query above
          for path in paths:
            dst = dstWithSubdirectory(path, dupdir)
            moveFile(path, dst, (not doSymlink)) # don't rm empty dirs if we are symlinking
            if not doSymlink:
              cursor.execute(REMOVE_ROW, (path, ))
            else:
              cursor.execute("update files set symlink = 1 where path = ?;", (path, ))
              symlinkFile(canonicalPath, path)
      logging.info("De-duping complete")
    except Exception as einst:
      logging.error("Unable to de-dup database: %s" % einst)
      raise

  def vacuum(self):
    """ Check the paths in the database, removing entries for which no actual file exists """
    logging.info("Vacuuming database")

    try:
      paths = [] # store nonexistent paths
      with sqliteConn(self.database) as cursor:
        cursor.execute("select path from files;")
        for row in cursor:
          (path, ) = row
          if not os.path.exists(path):
            paths.append(path)

        for path in paths:
          logging.info("Removing entry for %s; file does not exist" % path)
          cursor.execute("delete from files where path = ?;", (path, ))
        logging.info("Vacuum complete")
    except Exception as einst:
      logging.error("Unable to vacuum database: %s" % einst)
      raise

  def updateChecksum(self, path):
    """ Update/insert checksums for a given path.  If the path points at a symlink, the entry will
    be marked as being a symlink."""
    try:
      with sqliteConn(self.database) as cursor:
        self._updateChecksumAndLink(path, cursor)
    except Exception as einst:
      logging.error("Unable to update checksum for %s: %s" % (path, einst))
      raise

  def updatePath(self, old, new):
    """Updates the path in the database for a given file.  This is meant to be used by functions
    like rename, which may use directories rather than individual files for renames, thus old and
    new may be directories."""
    try:
      with sqliteConn(self.database) as cursor:
        cursor.execute(PATH_UPDATE, (old, new, old + '%'))
    except Exception as einst:
      logging.error("Unable to update path for %s to %s: %s" % (old, new, einst))
      raise

  def updateAllChecksums(self, fsroot):
    logging.info("Updating all checksums under %s" % fsroot)
    """ Update/insert checksums for all of the files located under fsroot.  This is meant as an
    optimization for rescanning the database, as it uses a single connection and transaction."""
    with sqliteConn(self.database) as cursor:
      try:
        for root, dirs, files in os.walk(fsroot):
          for name in files:
            path = os.path.join(root, name)
            logging.info("Updating %s" % path)
            self._updateChecksumAndLink(path, cursor)
      except Exception as einst:
        logging.error("Unable to update checksum for %s: %s" % (path, einst))
        raise
    logging.info("Done updating all checksums")

  def removeChecksum(self, path):
    """ Remove the checksum/path entry for the given path from the database """
    self._execSql(REMOVE_ROW, (path, ))

  # Calculates the checksum and link status for the given path, then updates the DB entry
  # and creates a hard link if the file has the same checksum as another file
  # If path is nonexistent, this will log an error
  def _updateChecksumAndLink(self, path, cursor):
    if os.path.exists(path):
      chksum = fileChecksum(path, self.checksum)
      cursor.execute(CHECKSUM_UPDATE, (path, chksum, isLinkAsNum(path)))
      self._hardlinkDup(path, chksum, cursor)
    else:
      # this happens for broken symlinks
      logging.error("Path %s does not exist; skipping update" % path)

  # internal helper to link a path using an existing cursor.  This is in some sense an
  # antipattern method, but I really don't want to deal with this as a duplicated code
  # block.  Note that this will skip any paths given to it that are symlinks
  def _hardlinkDup(self, path, chksum, cursor):
    if not os.path.islink(path):
      pathInode = os.stat(path).st_ino
      links = []
      cursor.execute("select path from files where chksum = ? and path != ? and symlink = 0;",
            (chksum, path))

      # i.e. find all different files with the same checksum
      for row in cursor:
        (link, ) = row
        if os.stat(link).st_ino != pathInode:
          links.append(link) # only hardlink files that don't point at the same inode

      if len(links) > 0:
        # let's assume that an existing entry is newer than this one.  Otherwise, we are constantly
        # relinking files
        canonicalLink = links[0]
        del links[0]
        links.append(path)

        # clean up any links with different inodes
        for link in links:
          cursor.execute(LINK_UPDATE, (1, link))
          linkFile(canonicalLink, link)

  # Makes sure the SQL statement has a "; at the end"
  def _formatSql(self, sql):
    if not sql.endswith(";"):
      sql = sql + ";"
    return sql

  # internal method used to run arbitrary SQL on the SQLite database
  def _execSql(self, sql, sqlargs = None):
    sql = self._formatSql(sql)
    logging.debug("Running SQL %s with args %s" % (sql, sqlargs))

    try:
      with sqliteConn(self.database) as cursor:
        if sqlargs != None:
          cursor.execute(sql, sqlargs)
        else:
          cursor.execute(sql)
    except Exception as einst:
      logging.error("Unable to exec %s with args %s: %s" % (sql, sqlargs, einst))
      raise

def main():
  usage = """%prog perform operations on the FUSE SHA1 filesystem database.  [options] database."""
  parser = OptionParser(usage = usage)
  parser.add_option("--dedup",
                    dest = "dupdir",
                    help = "Move duplicates into DUPDIR",
                    metavar="DUPDIR")

  parser.add_option("--symlink",
                    action = "store_true",
                    dest = "doSymlink",
                    default = False,
                    help = "Symlinks original paths for duplicates after moving them during --dedup.")

  parser.add_option("--vacuum",
                    action = "store_true",
                    dest = "vacuum",
                    default = False,
                    help = "Remove entries for nonexistent files")

  (options, args) = parser.parse_args()

  if len(args) != 1:
    parser.error("You must give the path to the SQLite database to use.")

  database = args[0]

  if not os.path.exists(database):
    parser.error("%s does not exist" % database)

  sha1db = Sha1DB(database)

  # vacuum first, then dedup
  if options.vacuum:
    sha1db.vacuum()

  if None != options.dupdir:
    sha1db.dedup(options.dupdir, options.doSymlink)


if __name__ == '__main__':
  main()
