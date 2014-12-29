# Calculate an SHA1 hex digest for a file
# Copyright (C) 2009-2011 Krysta Bouzek  <nwkrystab@gmail.com>
#
#
#    This program can be distributed under the terms of the GNU LGPL.
#    See the file COPYING.
#

import unittest
import sys
import os
import hashlib

sys.path.append("../")
import fusesha1util as fsu

class TestSha1FuseUtil(unittest.TestCase):
	_sha1file = "sha1test.txt"

	def testDstWithSubdirectoryBad(self):
		self.assertRaises(IOError, lambda: fsu.dstWithSubdirectory("", ""))
		self.assertRaises(IOError, lambda: fsu.dstWithSubdirectory("", None))
		self.assertRaises(IOError, lambda: fsu.dstWithSubdirectory("", "subdir"))

		self.assertRaises(IOError, lambda: fsu.dstWithSubdirectory(None, None))
		self.assertRaises(IOError, lambda: fsu.dstWithSubdirectory(None, ""))

		self.assertRaises(IOError, lambda: fsu.dstWithSubdirectory("uouoeuoaeuu", ""))

		self.assertRaises(IOError, lambda: fsu.dstWithSubdirectory(self._sha1file, ""))
		self.assertRaises(IOError, lambda: fsu.dstWithSubdirectory(self._sha1file, None))

		self.assertRaises(IOError,
			lambda: fsu.dstWithSubdirectory("/media/cdrom/test.txt", "/media/cdrom"))

	def testDstWithSubdirectory(self):
		newdst = os.path.join(os.path.dirname(os.path.abspath(self._sha1file)), "newsubdir")
		expected = "/home/belisarius/github/fuse-sha1/test/newsubdir/subdir/file.txt"
		self.assertEqual(expected, fsu.dstWithSubdirectory("subdir/file.txt", newdst))

		self.assertEqual("/media/cdrom/usr/local/test.txt",
			fsu.dstWithSubdirectory("/usr/local/test.txt", "/media/cdrom"))
		self.assertEqual("/media/cdrom/subdir/othersubdir/test.txt",
			fsu.dstWithSubdirectory("/media/cdrom/othersubdir/test.txt", "/media/cdrom/subdir"))

	# Test the variations on fileChecksum
	def testFileChecksum(self):
		self.assertRaises(IOError, lambda: fsu.fileChecksum(""))
		self.assertRaises(IOError, lambda: fsu.fileChecksum(None))
		self.assertEqual("9519b846c2b3a933bd348cc983f3796180ad2761", fsu.fileChecksum(self._sha1file))
		self.assertEqual("5af12c8f98e305b8ecfd91a4d5d0a302", fsu.fileChecksum(self._sha1file, hashlib.md5))

	def testLinkFileBad(self):
		self.assertRaises(OSError, lambda: fsu.linkFile(None, None))
		self.assertRaises(OSError, lambda: fsu.linkFile("", ""))
		self.assertRaises(OSError, lambda: fsu.linkFile(None, ""))
		self.assertRaises(OSError, lambda: fsu.linkFile("", None))
		self.assertRaises(OSError, lambda: fsu.linkFile(self._sha1file, ""))
		self.assertRaises(OSError, lambda: fsu.linkFile(self._sha1file, None))

	def testLinkFile(self):
		link = "sha1hardlink.txt"
		fsu.linkFile(self._sha1file, link)

		self.assertLink(link)

		# link again, just to make sure it won't fail
		fsu.linkFile(self._sha1file, link)

		self.assertLink(link)
		self.assertUnlinked(link)

	def testSymlinkFileBad(self):
		self.assertRaises(OSError, lambda: fsu.symlinkFile(None, None))
		self.assertRaises(OSError, lambda: fsu.symlinkFile("", ""))
		self.assertRaises(OSError, lambda: fsu.symlinkFile(None, ""))
		self.assertRaises(OSError, lambda: fsu.symlinkFile("", None))
		self.assertRaises(OSError, lambda: fsu.symlinkFile(self._sha1file, ""))
		self.assertRaises(OSError, lambda: fsu.symlinkFile(self._sha1file, None))

	def testSymlinkFile(self):
		link = "sha1link.txt"
		fsu.symlinkFile(self._sha1file, link)

		self.assertSymlink(link)

		# link again, just to make sure it won't fail
		fsu.symlinkFile(self._sha1file, link)

		self.assertSymlink(link)
		self.assertUnlinked(link)

	# make a symlink and try to hardlink to it
	def testLinkSymlink(self):
		link = "sha1link.txt"
		fsu.symlinkFile(self._sha1file, link)

		self.assertSymlink(link)

		# try to hard link link; this should be a no-op
		fsu.linkFile(self._sha1file, link)

		self.assertSymlink(link)
		self.assertUnlinked(link)

	def testSafeMakeDirs(self):
		parent = "testdirnoexist"
		subdir = os.path.join(parent, "somesubdir")
		subfile = os.path.join(subdir, "file.txt")
		if os.path.exists(subdir): os.removedirs(subdir)
		self.assertFalse(os.path.exists(parent))
		self.assertFalse(os.path.exists(subdir))
		self.assertEqual(subdir, fsu.safeMakedirs(subfile))
		# run again to make sure it doesn't choke
		self.assertEqual(subdir, fsu.safeMakedirs(subfile))
		self.assertTrue(os.path.exists(parent))
		self.assertTrue(os.path.exists(subdir))
		if os.path.exists(subdir): os.removedirs(subdir)

	def testSafeMakeDirsBad(self):
		self.assertRaises(OSError, lambda: fsu.safeMakedirs(""))
		self.assertRaises(OSError, lambda: fsu.safeMakedirs(None))

	def testSafeUnlink(self):
		fsu.safeUnlink("")
		self.assertRaises(OSError, lambda: fsu.safeUnlink(None))

		testfile = "unlinktest.txt"
		if os.path.exists(testfile): os.unlink(testfile)
		self.assertFalse(os.path.exists(testfile))

		with open(testfile, 'w') as f:
			f.write("test text")
		self.assertTrue(os.path.exists(testfile))
		fsu.safeUnlink(testfile)
		self.assertFalse(os.path.exists(testfile))

	def assertSymlink(self, link):
		self.assertTrue(os.path.exists(link))
		self.assertTrue(os.path.islink(link))
		self.assertEquals(os.stat(self._sha1file).st_ino, os.stat(link).st_ino)

	def assertLink(self, link):
		self.assertTrue(os.path.exists(link))
		self.assertFalse(os.path.islink(link))
		self.assertEquals(os.stat(self._sha1file).st_ino, os.stat(link).st_ino)

	def assertUnlinked(self, link):
		fsu.safeUnlink(link)
		self.assertFalse(os.path.exists(link))

if __name__ == '__main__':
	unittest.main()
