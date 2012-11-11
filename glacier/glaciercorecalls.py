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
            if self.start<seqoffset:
                msg = ("Sequential offset %d is already over part %s start"
                       %(seqoffset, self))
                self.logger.exception(msg)

                raise InputException(msg, code='FileError')
            if seqoffset>=0 and self.start!=seqoffset:
                try:
                    self.f.read(self.start-seqoffset)
                except IOError as e:
                    msg="Cannot read fd %s"  %self.f
                    raise InputException(msg, code='FileError', cause=e)
                except Exception as e:
                    msg="Cannot read fd %s"  %self.f
                    raise InputException(msg, cause=e)
        else:
            try:
                self.f.seek(start)
            except IOError as e:
                if e.errno==errno.ESPIPE:
                    msg = "Is your fd %s really non-sequential?" %self.f
                    raise InputException(msg, code='FileError', cause=e)
                else:
                    msg = "Problem seeking fd %s" %self.f
                    raise InputException(msg, code='FileError', cause=e)
            except Exception as e:
                msg = "Problem seeking fd %s" %self.f
                raise InputException(msg, cause=e)

            try:
                self.logger.debug("Reading part %s into memory" %self)
                buffer = self.f.read(self.size)
                self.logger.debug("Reading part succesfull")
            except MemoryError as e:
                msg = "Cannot read part %s into memory" %self
                raise InputException(msg, code='MemoryError', cause=e)
            except IOError as e:
                msg="Cannot read fd %s"  %self.f
                raise InputException(msg, code='FileError', cause=e)
            except Exception as e:
                msg="Cannot read fd %s"  %self.f
                raise InputException(msg, cause=e)

            return buffer

    def _mmappart(self):
        """
        Mmaps part into memory

        :returns: Readed part buffer
        :rtype: byte array
        """

        if self.sequential:
            msg = "Sequential file descriptors cannot be mmaped, part %s" %self
            raise InputException(msg, code='FileError')

        if self.start%self.pagesize!=0:
            msg = "Part %s start is not multiple of mmap page size" %self
            raise InputException(msg, code='MemoryError')

        try:
            self.logger.debug("Mmaping part %s" %self)
            buffer = mmap.mmap(f.fileno(),
                               self.size,
                               offset=self.start,
                               prot=mmap.PROT_READ)
            self.mmap = buffer
            self.logger.debug("Mmaping part %s successfull" %self)
        except MemoryError as e:
            msg = ("Problems with mmaping part %s, "
                   "is your address space big enough?" %self)
            raise InputException(msg, code='MemoryError', cause=e)
        except Exception as e:
            raise InputException("Problem mmaping part %s" %self, cause=e)

        return buffer

    def getBuffer(self, f, seqoffset=-1, reopen=True):
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

        :part part: Part descriptions to use
        :type part: json
        :param dont_mmap: Prevent mmaping non-sequential data stream
        :type dont_mmap: boolean
        :param reopen: Should we reopen file descriptor
        :type reopen: boolean

        .. note::

            Mmapping will be automatically be disabled if there will be
            an error with mmaping, and fallback to reading to memory
            will be used.

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
        part.getBuffer()
    except InputException as e:
        return e

    if part.verifyTreeHash():
        return part

    # TODO: Add advanced exception handler
    try:
        self.glacierconn.upload_part(vault_name,
                                upload_id,
                                part.getHash(),
                                part.getTreeHash(),
                                (part.start, part.start+len(part.getBuffer())-1),
                                part.getBuffer())
    except Exception as e:
        # Allow callback to handle exceptions
        return e

    # Empty buffer so memory gets cleaned and file descriptors gets closed
    part.emptyBuffer()

    return part


DEFAULT_PART_SIZE = 128 # in MB, power of 2.

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
            part_size = GlacierWriter.DEFAULT_PART_SIZE
    else:
        ps = self._next_power_of_2(part_size)
        if not ps == part_size:
            self.logger.warning("Part size in MB must be a power of 2, "
                                "e.g. 1, 2, 4, 8 MB; automatically increase "
                                "part size from %s to %s."% (part_size, ps))

        part_size = ps

    # Check whether user specified value is big enough, and adjust if needed.
    if total_size > part_size*1024*1024*self.MAX_PARTS:
        part_size = _part_size_for_total_size(total_size)
        self.logger.warning("Part size given is too small;"
                            "using %s MB parts to upload."% part_size)

    return part_size

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

    def __init__(self, connection, vault_name,
                 description=None, part_size_in_bytes=DEFAULT_PART_SIZE*1024*1024,
                 uploadid=None, logger=None):

        self.part_size = part_size_in_bytes
        self.vault_name = vault_name
        self.connection = connection
        self.logger = logger

        if uploadid:
            self.uploadid = uploadid
        else:
            response = self.connection.initiate_multipart_upload(self.vault_name,
                                                                 self.part_size,
                                                                 description)
            self.uploadid = response['UploadId']

        self.uploaded_size = 0
        self.tree_hashes = []
        self.closed = False
##        self.upload_url = response.getheader("location")

    def write(self, data):

        if self.closed:
            raise CommunicationError(
                "Tried to write to a GlacierWriter that is already closed.",
                code='InternalError')

        if len(data) > self.part_size:
            raise InputException (
                'Block of data provided must be equal to or smaller than the set block size.',
                code='InternalError')

        part_tree_hash = tree_hash(chunk_hashes(data))
        self.tree_hashes.append(part_tree_hash)
        headers = {
                   "x-amz-glacier-version": "2012-06-01",
                    "Content-Range": "bytes %d-%d/*" % (self.uploaded_size,
                                                       (self.uploaded_size+len(data))-1),
                    "Content-Length": str(len(data)),
                    "Content-Type": "application/octet-stream",
                    "x-amz-sha256-tree-hash": bytes_to_hex(part_tree_hash),
                    "x-amz-content-sha256": hashlib.sha256(data).hexdigest()
                  }

        self.connection.upload_part(self.vault_name,
                                    self.uploadid,
                                    hashlib.sha256(data).hexdigest(),
                                    bytes_to_hex(part_tree_hash),
                                    (self.uploaded_size, self.uploaded_size+len(data)-1),
                                    data)

##        retries = 0
##        while True:
##            response = self.connection.make_request(
##                "PUT",
##                self.upload_url,
##                headers,
##                data)
##
##            # Success.
##            if response.status == 204:
##                break
##
##            # Time-out recieved: sleep for 5 minutes and try again.
##            # Do not try more than five times; after that it's over.
##            elif response.status == 408:
##                if retries >= 5:
##                    resp = json.loads(response.read())
##                    raise ResonseException(
##                        resp['message'],
##                        cause='Timeout',
##                        code=resp['code'])
##
##                if self.logger:
##                    logger.warning(resp['message'])
##                    logger.warning('sleeping 300 seconds (5 minutes) before retrying.')
##
##                retries += 1
##                time.sleep(300)
##
##            else:
##                raise ResponseException(
##                    "Multipart upload part expected response status 204 (got %s):\n%s"\
##                        % (response.status, response.read()),
##                    cause=resp['message'],
##                    code=resp['code'])

##        response.read()
        self.uploaded_size += len(data)

    def close(self):

        if self.closed:
            return

        # Complete the multiplart glacier upload
        response = self.connection.complete_multipart_upload(self.vault_name,
                                                             self.uploadid,
                                                             bytes_to_hex(tree_hash(self.tree_hashes)),
                                                             self.uploaded_size)
        self.archive_id = response['ArchiveId']
        self.location = response['Location']
        self.hash_sha256 = bytes_to_hex(tree_hash(self.tree_hashes))
        self.closed = True

    def get_archive_id(self):
        self.close()
        return self.archive_id

    def get_location(self):
        self.close()
        return self.location

    def get_hash(self):
        self.close()
        return self.hash_sha256
