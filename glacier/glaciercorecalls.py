#!/usr/bin/env python
# encoding: utf-8
"""
.. module:: botocorecalls
   :platform: Unix, Windows
   :synopsis: boto calls to access Amazon Glacier.

This depends on the boto library, use version 2.6.0 or newer.


     writer = GlacierWriter(glacierconn, GLACIER_VAULT)
     writer.write(block of data)
     writer.close()
     # Get the id of the newly created archive
     archive_id = writer.get_archive_id()from boto.connection import AWSAuthConnection
"""

import io
import hashlib
import math
import logging
import six

import boto.glacier.layer1

from mmap import ALLOCATIONGRANULARITY
from glacierexception import *

# Placeholder, effectively renaming the class.
class GlacierConnection(boto.glacier.layer1.Layer1):
    pass

def find(f, seq):
  """Return first item in sequence where f(item) == True."""
  for item in seq:
    if f(item):
      return item


def chunk_hashes(data):
    """
    Break up the byte-string into 1MB chunks and return sha256 hashes
    for each.
    """

    chunk = 1024*1024
    chunk_count = int(math.ceil(len(data)/float(chunk)))
    return [hashlib.sha256(data[i*chunk:(i+1)*chunk]).digest() for i in range(chunk_count)]

def tree_hash(fo):
    """
    Given a hash of each 1MB chunk (from chunk_hashes) this will hash
    together adjacent hashes until it ends up with one big one. So a
    tree of hashes.
    """

    hashes = []
    hashes.extend(fo)
    while len(hashes) > 1:
        new_hashes = []
        while True:
            if len(hashes) > 1:
                first = hashes.pop(0)
                second = hashes.pop(0)
                new_hashes.append(hashlib.sha256(first + second).digest())
            elif len(hashes) == 1:
                only = hashes.pop(0)
                new_hashes.append(only)
            else:
                break
        hashes.extend(new_hashes)
    return hashes[0]

def bytes_to_hex(str):
    return ''.join( [ "%02x" % ord( x ) for x in str] ).strip()

def is_sequential(f):
    """
    Detects if file descriptor is sequential or not

    :param f: File descriptor
    :type f: FileIO

    :returns: Is file descriptor sequential or not
    :rtype: boolean
    """

    try:
        f.seek(0)
    except IOError as e:
        # illegal seek
        if e.errno==errno.ESPIPE:
            self.logger.info("Fd is sequential")
            return True
        else:
            msg = "Cannot read input file, fd %s" %f
            raise InputException(msg, code='FileError', cause=e)

    return False

class Part(object):
    pagesize = ALLOCATIONGRANULARITY

    def _readpart(self, seqoffset=-1):
        """
        Reads part into memory

        :param seqoffset: Sequential input stream offset
        :type seqoffset: int

        :returns: Readed part buffer
        :rtype: byte array
        """

        if self.sequential:
            if self.start < seqoffset:
                msg = ("Sequential offset %d is already over part %s start"
                       %(seqoffset, self))
                self.logger.exception(msg)

                raise InputException(msg, code='FileError')
            if seqoffset >= 0 and self.start != seqoffset:
                try:
                    self.f.read(self.start-seqoffset-1)
                    if not self.f.read(1):
                        raise EOFError()
                except IOError as e:
                    msg="Cannot read fd %s"  %self.f
                    raise InputException(msg, code='FileError',
                                         cause=e, data=self)
                except EOFError as e:
                    msg = ("End of stream for file %s detected "
                           "before skipping the whole part" %self.f)
                    self.logger.debug(msg)
                    raise InputException(msg, code='InternalError',
                                         cause=e, data=self)
                except Exception as e:
                    msg="Cannot read fd %s"  %self.f
                    raise InputException(msg, cause=e, data=self)
        else:
            try:
                self.f.seek(start-1)
            except IOError as e:
                if e.errno == errno.ESPIPE:
                    msg = "Is your fd %s really non-sequential?" %self.f
                    raise InputException(msg, code='InternalError',
                                         cause=e, data=self)
                else:
                    msg = "Problem seeking fd %s" %self.f
                    raise InputException(msg, code='FileError', cause=e, data=self)
            except Exception as e:
                msg = "Problem seeking fd %s" %self.f
                raise InputException(msg, cause=e, data=self)

            # Ugly hack to detect if we are at the end of the file
            if not f.read(1):
                raise EOFError()

            try:
                self.logger.debug("Reading part %s into memory" %self)
                buffer = self.f.read(self.size)
                self.logger.debug("Reading part succesfull")
            except MemoryError as e:
                msg = "Cannot read part %s into memory" %self
                raise InputException(msg, code='MemoryError', cause=e, data=self)
            except IOError as e:
                msg="Cannot read fd %s"  %self.f
                raise InputException(msg, code='FileError', cause=e, data=self)
            except Exception as e:
                msg="Cannot read fd %s"  %self.f
                raise InputException(msg, cause=e, data=self)

            return buffer

    def _mmappart(self):
        """
        Mmaps part into memory

        :returns: Readed part buffer
        :rtype: byte array
        """

        if self.sequential:
            msg = "Sequential file descriptors cannot be mmaped, part %s" %self
            raise InputException(msg, code='InternalError', data=self)

        if self.start%self.pagesize!=0:
            msg = "Part %s start is not multiple of mmap page size" %self
            raise InputException(msg, code='MemoryError', data=self)


        if self.start+1 > self.file_size:
            self.logger.debug("EOF detected for file %s" %self.f)
            raise EOFError()

        # Files can grow while we are uploading so let's do that all the time
        self.file_size = os.fstat(self.f.fileno()).st_size

        # Correct read size if we are at the end
        if (self.start+1-self.file_size) < self.size:
            self.size = self.start+1-self.file_size

        try:
            self.logger.debug("Mmaping part %s" %self)
            buffer = mmap.mmap(f.fileno(),
                               self.size,
                               offset=self.start,
                               prot=mmap.PROT_READ)
            self.mmap = buffer
            self.logger.debug("Mmaping part %s successfull" %self)
        except ValueError as e:
            msg = ("Problem with mmaping part %s, "
                   "offset or size incorrect?" %self)
            raise InputException(msg, code='InternalError', cause=e, data=self)
        except MemoryError as e:
            msg = ("Problems with mmaping part %s, "
                   "is your address space big enough?" %self)
            raise InputException(msg, code='MemoryError', cause=e, data=self)
        except Exception as e:
            raise InputException("Problem mmaping part %s" %self, cause=e, data=self)

        return buffer

    def getBuffer(self, f, seqoffset=-1):
        """
        Buffers part into memory

        It uses two methods:

            * Reading part into memory
            * MMaping part into memory

        If input buffer is sequential mmaping cannot be performed, so
        reading is performed instead.
        Also if mmaping fails, reading is performed.

        :param fd: File descriptor
        :type fd: FileIO
        :param seqoffset: Sequential input stream offset
        :type seqoffset: int
        :param reopen: Reopen file descriptor (for parallel access to file)
        :type reopen: boolean

        :returns: Readed buffer part
        :rtype: byte array or mmap
        """

        # Reopen if reopen flag
        if self.reopen:
            self.f = io.FileIO(f.name, "rb")

        # Detect if file descriptor is sequential or not
        # Sequential descirptors cannot be seeked, so mmaping won't work
        self.sequential = is_sequential(self.f)

        self.buffer= None
        if not self.sequential and not self.dont_mmap:
            try:
                self.buffer = self._mmappart()
                self.mmap = self.buffer
            except InputException as e:
                if e.code != GlacierException.ERRORCODE['MemoryError']:
                    raise

                try:
                    self.buffer = self._readpart()
                    self.dont_mmap = True
                except InputException as e:
                    raise
        else:
            try:
                self.buffer = self._readpart()
            except InputException as e:
                raise

        return self.buffer

    def emptyBuffer(self):
        """
        Empties buffer, by first closing all descriptors
        and then reseting buffer to None
        """

        if self.mmap:
            try:
                self.mmap.close()
            except Exception as e:
                msg = "Error closing mmap, part %s" %self
                raise InputException(msg, code='FileError', cause=e)

            self.mmap = None

        # Only close if file descriptor has been reopened
        if self.f and reopen:
            try:
                self.f.close()
            except Exception as e:
                msg = "Error closing fd" %self.f
                raise InputException(msg, code='FileError', cause=e)

        self.f = None
        self.buffer = None

    def getTreeHash(self, recheck=False):
        """
        Hashes data stream using tree hash

        :returns: Tree hash of data
        :rtype: str
        """

        if self.tree_hash and not recheck:
            return self.tree_hash

        if not self.buffer:
            raise InputException(
                "Buffer must be filled with part %s data, "
                "before calculating hash" %self,
                code='InternalError')

        self.tree_hash = bytes_to_hex(tree_hash(chunk_hashes(self.buffer)))
        return self.tree_hash

    def verifyTreeHash(self):
        current_tree_hash = self.tree_hash
        if not current_tree_hash:
            return self.getHash()

        return self.getHash(True)==current_tree_hash

    def getHash(self, recheck=False):
        """
        Gets hashed data stream using sha256

        :returns: SHA256 hash of data
        :rtype: str
        """

        if self.hash and not recheck:
            return self.hash

        if not self.buffer:
            raise InputException(
                "Buffer must be filled with part %s data, "
                "before calculating hash" %self,
                code='InternalError')

        self.hash = hashlib.sha256(self.buffer.hexdigest())
        return self.hash

    def toJson(self):
        return {
            "RangeInBytes": "%d-%d" %(self.start,self.stop),
            "SHA256TreeHash": getTreeHash()
        }

    def __getitem__(self, key):
        if key=="RangeInBytes":
            return "%d-%d" %(self.start, self.stop)
        elif key=="SHA256TreeHash":
            return getTreeHash()

        raise KeyError

    def repr():
        return ("<Part %d-%d, fd: %s, tree_hash: %s>"
                %(self.start, self.stop, self.f, self.tree_hash))

    def __del__(self):
        self.emptyBuffer()

    def __init__(part, dont_mmap=False, reopen=True):
        """
        Constructor

        .. note::

            Mmapping will be automatically be disabled if there will be
            an error with mmaping, and fallback to reading to memory
            will be used.

        .. warning::

            Disable mmaping if your disk can cause problems. This
            library will crash if disk is removed or data can't be read!

        :part part: Part descriptions to use
        :type part: json
        :param dont_mmap: Prevent mmaping non-sequential data stream
        :type dont_mmap: boolean
        :param reopen: Should we reopen file descriptor
        :type reopen: boolean
        :type dont_mmap: boolean
        """

        self.logger = logging.getLogger(self.__class__.__name__)

        if not part.get('RangeInBytes'):
            msg =  ("RangeInBytes must be provided to Part constructor")
            raise InputException(msg, code='InternalError')

        self.start = int(part['RangeInBytes'].split('-')[0])
        self.stop = int(part['RangeInBytes'].split('-')[1])
        self.size = stop - start
        self.dont_mmap = dont_mmap
        self.reopen = reopen and (not sequential)
        self.tree_hash = part.get('SHA256TreeHash')

        self.f = None
        self.mmap = None
        self.hash = None

def upload_part(glacierconn, vault_name, upload_id, uploaded_parts,
                 part):
    logger = logging.getLogger(_upload_part.func_name)

    try:
        logger.debug("Getting buffer for part %s" %part)
        part.getBuffer()
    except InputException as e:
        return e
    # Make shure we don't crash here
    except Exception as e:
        return InputException("Unknown error while getting buffer "
                              "for part %s" %part,
                              code='InternalError',
                              cause=e,
                              data=part)

    try:
        logger.debug("Verifing tree hash for part %s" %part)
        if part.verifyTreeHash():
            logger.debug("Part %s already uploaded" %part)

            part.emptyBuffer()
            return part

    except InputException as e:
        not part.sequential and part.emptyBuffer()
        return e
    # Make shure we don't crash here
    except Exception as e:
        not part.sequential and part.emptyBuffer()
        return InputException("Unknown error while verifing tree hash "
                              "for part %s" %part,
                              code='InternalError',
                              cause=e,
                              data=part)

    logger.debug("Part %s verification incorrect" %part)

    # TODO: Add advanced exception handler
    try:
        logger.debug("Uploading part %s; vault name %s, "
                     "hash: %s, tree_hash: %s, start: %d, len: %"
                     %(part, self.vault_name, upload_id, part.getHash(),
                       part.getTreeHash(), part.start, len(part.getBuffer())))
        self.glacierconn.upload_part(vault_name,
                                upload_id,
                                part.getHash(),
                                part.getTreeHash(),
                                (part.start, part.start+len(part.getBuffer())-1),
                                part.getBuffer())
    # Make shure we don't crash here
    except Exception as e:
        not part.sequential and part.emptyBuffer()
        return CommunicationException("Unknown error while uploading "
                                      "part %s" %part,
                                      cause=e,
                                      data=part)

    logger.debug("Part %s upload successfull" %part)

    try:
        # Empty buffer so memory gets cleaned and file descriptors gets closed
        part.emptyBuffer()
    except InputException as e:
        return e

    return part

DEFAULT_PART_SIZE = 128 # in MB, power of 2.

def _next_power_of_2(self, v):
    """
    Returns the next power of 2, or the argument if it's
    already a power of 2.

    :param v: the value to be tested.
    :type v: int

    :returns: the next power of 2.
    :rtype: int
    """

    if v == 0:
        return 1

    v -= 1
    v |= v >> 1
    v |= v >> 2
    v |= v >> 4
    v |= v >> 8
    v |= v >> 16
    return v + 1

def _get_part_size(self, part_size, total_size):
    """
    Gets the part size:

    - check whether we have a part size, if not: use default.
    - check whether part size is a power of two: if not,
        increase until it is.
    - check wehther part size is big enough for the archive
        total size: if not, increase until it is.

    Return part size to use.
    """

    def _part_size_for_total_size(total_size):
        return self._next_power_of_2(
            int(math.ceil(
                    float(total_size) / (1024 * 1024 * self.MAX_PARTS)
            )))

    if part_size < 0:
        if total_size > 0:
            part_size = _part_size_for_total_size(total_size)
        else:
            part_size = DEFAULT_PART_SIZE
    else:
        part_size = self._next_power_of_2(part_size)

    # Check whether user specified value is big enough, and adjust if needed.
    if total_size > part_size*1024*1024*self.MAX_PARTS:
        part_size = _part_size_for_total_size(total_size)

    return part_size
