# Author: s3raph
# Purpose: To Make the Butter
# Version: .742
# Description: This Python Autopsy Module pulls out Android executable files for additional triage and analysis.

import os
import shutil
import struct
import binascii
import codecs
import jarray
import inspect
import random
import subprocess

from datetime import datetime
from string import ascii_letters, punctuation, digits
from random import choice, randint

from javax.swing import JCheckBox
from javax.swing import JList
from javax.swing import JTextArea
from javax.swing import BoxLayout
from java.awt import GridLayout
from java.awt import BorderLayout
from javax.swing import BorderFactory
from javax.swing import JToolBar
from javax.swing import JPanel
from javax.swing import JFrame
from javax.swing import JScrollPane
from javax.swing import JComponent
from javax.swing import JLabel
from java.awt.event import KeyListener

from java.lang import Class
from java.lang import System
from java.sql  import DriverManager, SQLException
from java.util.logging import Level
from java.io import File
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import GenericIngestModuleJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import PlatformUtil
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.casemodule.services import Blackboard
from org.sleuthkit.autopsy.datamodel import ContentUtils

class YAAAATDataSourceIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Yet Another Android Analysis Tool Module (YAAAAT)."
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Yet Another Android Analysis Tool (YAAAAT)."
    
    
    def getModuleVersionNumber(self):
        return "0.742"
    
    def getDefaultIngestJobSettings(self):
        return GenericIngestModuleJobSettings()

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return YAAAATIngestModule(self.settings)
 
class YAAAATIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(YAAAATDataSourceIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings

    def startUp(self, context):
        self.context = context
        self.job_id = context.getJobId()
        
        if PlatformUtil.isWindowsOS():
            self.path_to_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "win\\bin\\jadx.bat")
            if not os.path.exists(self.path_to_exe):
                raise IngestModuleException("Windows Executable was not found in module folder: " + self.path_to_exe)
        elif PlatformUtil.getOSName() == 'Linux':
            self.path_to_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'nix\\bin\\jadx')
            if not os.path.exists(self.path_to_exe):
                raise IngestModuleException("Linux Executable was not found in module folder")

    def process(self, dataSource, progressBar):
        self.log(Level.INFO, "YAAAAT has started." + " Job id is => " + str(self.job_id))
        job_id = self.job_id

        TimeDate = datetime.now()
        TimeString = TimeDate.strftime("%H-%M-%S")

        var_rand_min = 8
        var_rand_max = 8
        var_rand_string_format = ascii_letters + digits

        var_test_check = 1

        var_all_exe  = 1
        var_apk_exe  = 1
        var_jar_exe  = 1
        var_oat_exe  = 1
        var_dex_exe  = 1
        var_so_exe   = 1
        var_elf_exe  = 1
        
        if var_all_exe == 1:
            var_test_check = 1
        if var_apk_exe == 1:
            var_test_check = 1
        if var_jar_exe == 1:
            var_test_check = 1
        if var_oat_exe == 1:
            var_test_check = 1
        if var_dex_exe == 1:
            var_test_check = 1
        if var_so_exe == 1:
            var_test_check = 1
        if var_elf_exe == 1:
            var_test_check = 1
            
        if var_test_check == 0:
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "YAAAAT:", " No Executable Types Selected." )
            IngestServices.getInstance().postMessage(message)
            return IngestModule.ProcessResult.ERROR
        else:
            skCase = Case.getCurrentCase().getSleuthkitCase();
            blkBrd = skCase.getBlackboard()

            progressBar.switchToIndeterminate()

            files = []		
            fileManager = Case.getCurrentCase().getServices().getFileManager()

            var_username = os.environ.get('USERNAME')
            var_case_extract_directory = "C:\\Users\\" + var_username + "\\Desktop\\case_extract\\"

            try:
                os.mkdir(var_case_extract_directory)
            except:
                self.log(Level.INFO, "Case Extract Directory already exists.")            
                
            Temp_Dir = os.path.join(var_case_extract_directory, TimeString)
            try:
                os.mkdir(Temp_Dir)
            except:
                self.log(Level.INFO, "Temp Directory already exists: " + Temp_Dir)

            ### APK Extract Folder Creation ###
            if var_all_exe == 1 or var_apk_exe == 1:
                fileapk = fileManager.findFiles(dataSource, "%.apk")
                apk_temp_dir = os.path.join(Temp_Dir, "apk_storage")
                try:
                    os.mkdir(apk_temp_dir)
                except:
                    self.log(Level.INFO, "apk_storage Directory already exists: " + apk_temp_dir)
          
            ### XAPK Extract Folder Creation ###
            if var_all_exe == 1 or var_xapk_exe == 1:
                filexapk = fileManager.findFiles(dataSource, "%.xapk")
                xapk_temp_dir = os.path.join(Temp_Dir, "xapk_storage")
                try:
                    os.mkdir(xapk_temp_dir)
                except:
                    self.log(Level.INFO, "xapk_storage Directory already exists: " + xapk_temp_dir)

            ### JAR Extract Folder Creation ###
            if var_all_exe == 1 or var_jar_exe == 1:
                filejar = fileManager.findFiles(dataSource, "%.jar")
                jar_temp_dir = os.path.join(Temp_Dir, "jar_storage")
                try:
                    os.mkdir(jar_temp_dir)
                except:
                    self.log(Level.INFO, "jar_storage Directory already exists: " + jar_temp_dir)

            ### OAT Extract Folder Creation ###
            if var_all_exe == 1 or var_oat_exe == 1:
                fileoat = fileManager.findFiles(dataSource, "%.oat")
                oat_temp_dir = os.path.join(Temp_Dir, "oat_storage")
                try:
                    os.mkdir(oat_temp_dir)
                except:
                    self.log(Level.INFO, "oat_storage Directory already exists: " + oat_temp_dir)

            ### DEX Extract Folder Creation ###
            if var_all_exe == 1 or var_dex_exe == 1:
                filedex = fileManager.findFiles(dataSource, "%.dex")
                dex_temp_dir = os.path.join(Temp_Dir, "dex_storage")
                try:
                    os.mkdir(dex_temp_dir)
                except:
                    self.log(Level.INFO, "dex_storage Directory already exists: " + dex_temp_dir)

            ### SO Extract Folder Creation ###
            if var_all_exe == 1 or var_so_exe == 1:
                fileso = fileManager.findFiles(dataSource, "%.so")
                so_temp_dir = os.path.join(Temp_Dir, "so_storage")
                try:
                    os.mkdir(so_temp_dir)
                except:
                    self.log(Level.INFO, "so_storage Directory already exists: " + so_temp_dir)

            ### ELF Extract Folder Creation ###
            if var_all_exe == 1 or var_elf_exe == 1:
                fileelf = fileManager.findFiles(dataSource, "%.elf")
                elf_temp_dir = os.path.join(Temp_Dir, "elf_storage")
                try:
                    os.mkdir(elf_temp_dir)
                except:
                    self.log(Level.INFO, "elf_storage Directory already exists " + elf_temp_dir)

            files = filedex + fileoat + filejar + filexapk + fileapk + fileso + fileelf
            numFiles = len(files)
            
            progressBar.switchToDeterminate(numFiles)

            if var_all_exe == 1 or var_apk_exe == 1:
                for file in fileapk:
                    if self.context.isJobCancelled():
                        return IngestModule.ProcessResult.OK

                    self.log(Level.INFO, "Processing file: " + file.getName())
                    var_file_generated_string = "".join(choice(var_rand_string_format) for x in range(randint(var_rand_min, var_rand_max)))
                    var_file_name = file.getName()
                    var_file_rand_name = var_file_generated_string + "_" + var_file_name
                    
                    lclDbPath = os.path.join(apk_temp_dir, var_file_rand_name)
                    ContentUtils.writeToFile(file, File(lclDbPath))

                    art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
                    att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), YAAAATDataSourceIngestModuleFactory.moduleName, "APK by Extension")
                    art.addAttribute(att)

            if var_all_exe == 1 or var_xapk_exe == 1:
                for file in filexapk:
                    if self.context.isJobCancelled():
                        return IngestModule.ProcessResult.OK

                    self.log(Level.INFO, "Processing file: " + file.getName())
                    var_file_generated_string = "".join(choice(var_rand_string_format) for x in range(randint(var_rand_min, var_rand_max)))
                    var_file_name = file.getName()
                    var_file_rand_name = var_file_generated_string + "_" + var_file_name
                    
                    lclDbPath = os.path.join(xapk_temp_dir, var_file_rand_name)
                    ContentUtils.writeToFile(file, File(lclDbPath))
                    
                    art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
                    att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), YAAAATDataSourceIngestModuleFactory.moduleName, "XAPK by Extension")
                    art.addAttribute(att)

            if var_all_exe == 1 or var_jar_exe == 1:
                for file in filejar:
                    if self.context.isJobCancelled():
                        return IngestModule.ProcessResult.OK

                    self.log(Level.INFO, "Processing file: " + file.getName())
                    var_file_generated_string = "".join(choice(var_rand_string_format) for x in range(randint(var_rand_min, var_rand_max)))
                    var_file_name = file.getName()
                    var_file_rand_name = var_file_generated_string + "_" + var_file_name
                    
                    lclDbPath = os.path.join(jar_temp_dir, var_file_rand_name)
                    ContentUtils.writeToFile(file, File(lclDbPath))
                    
                    art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
                    att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), YAAAATDataSourceIngestModuleFactory.moduleName, "JAR by Extension")
                    art.addAttribute(att)

            if var_all_exe == 1 or var_oat_exe == 1:
                for file in fileoat:
                    if self.context.isJobCancelled():
                        return IngestModule.ProcessResult.OK

                    self.log(Level.INFO, "Processing file: " + "_" + file.getName())
                    var_file_generated_string = "".join(choice(var_rand_string_format) for x in range(randint(var_rand_min, var_rand_max)))
                    var_file_name = file.getName()
                    var_file_rand_name = var_file_generated_string + "_" + var_file_name
                    
                    lclDbPath = os.path.join(oat_temp_dir, var_file_rand_name)
                    ContentUtils.writeToFile(file, File(lclDbPath))
                                
                    art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
                    att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), YAAAATDataSourceIngestModuleFactory.moduleName, "OAT by Extension")
                    art.addAttribute(att)

            if var_all_exe == 1 or var_dex_exe == 1:
                for file in filedex:
                    if self.context.isJobCancelled():
                        return IngestModule.ProcessResult.OK

                    self.log(Level.INFO, "Processing file: " + file.getName())
                    var_file_generated_string = "".join(choice(var_rand_string_format) for x in range(randint(var_rand_min, var_rand_max)))
                    var_file_name = file.getName()
                    var_file_rand_name = var_file_generated_string + "_" + var_file_name
                    
                    lclDbPath = os.path.join(dex_temp_dir, var_file_rand_name)
                    ContentUtils.writeToFile(file, File(lclDbPath))
                    
                    art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
                    att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), YAAAATDataSourceIngestModuleFactory.moduleName, "DEX by Extension")
                    art.addAttribute(att)

            if var_all_exe == 1 or var_so_exe == 1:
                for file in fileso:
                    if self.context.isJobCancelled():
                        return IngestModule.ProcessResult.OK

                    self.log(Level.INFO, "Processing file: " + file.getName())
                    var_file_generated_string = "".join(choice(var_rand_string_format) for x in range(randint(var_rand_min, var_rand_max)))
                    var_file_name = file.getName()
                    var_file_rand_name = var_file_generated_string + "_" + var_file_name
                    
                    lclDbPath = os.path.join(so_temp_dir, var_file_rand_name)
                    ContentUtils.writeToFile(file, File(lclDbPath))
                                
                    art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
                    att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), YAAAATDataSourceIngestModuleFactory.moduleName, "SO by Extension")
                    art.addAttribute(att)

            if var_all_exe == 1 or var_elf_exe == 1:
                for file in fileelf:
                    if self.context.isJobCancelled():
                        return IngestModule.ProcessResult.OK

                    self.log(Level.INFO, "Processing file: " + file.getName())
                    var_file_generated_string = "".join(choice(var_rand_string_format) for x in range(randint(var_rand_min, var_rand_max)))
                    var_file_name = file.getName()
                    var_file_rand_name = var_file_generated_string + "_" + var_file_name
                    
                    lclDbPath = os.path.join(elf_temp_dir, var_file_rand_name)
                    ContentUtils.writeToFile(file, File(lclDbPath))
                    
                    art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
                    att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), YAAAATDataSourceIngestModuleFactory.moduleName, "ELF by Extension")
                    art.addAttribute(att)

            # After all executables have been parsed, post a message to the ingest messages in box.
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                "YAAAAT:", " YAAAAT Has Been Ran." )
            IngestServices.getInstance().postMessage(message)
            
            return IngestModule.ProcessResult.OK
		
    # Return the settings used
    def getSettings(self):
        return self.local_settings

# Copyright (C)  2025  s3raph
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.
# If not, see <https://www.gnu.org/licenses/>.
