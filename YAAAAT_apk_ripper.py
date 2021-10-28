import os
import shutil
import sys
import getopt
import glob
import hashlib
import re
from zipfile import ZipFile
from struct import pack, unpack
from xml.sax.saxutils import escape
import traceback

def main(argv):
    inputdirectory_var = ''
    
    try:
        opts, args = getopt.getopt(argv,"hi:",["idir="])
    except getopt.GetoptError:
        print("YAAAAT_apk_ripper.py -i <directory_to_scan_for_apks>")
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print("YAAAAT_apk_ripper.py -i <directory_to_scan_for_apks>")
            sys.exit()
        elif opt in ("-i", "--idir"):
            inputdirectory_var = arg

    inputdirectory = os.path.dirname(inputdirectory_var)
    var_case_delivery_directory = inputdirectory + "\\" + "_case_info"
    try:
        os.mkdir(var_case_delivery_directory)
    except:
		print("[WARN]: Error Making Main Case Directory, likely already exists: " + var_case_delivery_directory)
    
    case_log_file_txt = var_case_delivery_directory + "\\log.txt"
    log_txt_update = open(case_log_file_txt, "a")
    log_txt_update.write("--- APK Ripper Script Started ---\n")
    
    directory_search_pattern = (inputdirectory+"\\apk_storage\\*.apk")
    for apk_full_path in glob.glob(directory_search_pattern):
        apk_with_extension = os.path.basename(apk_full_path)
        apk, discard_ext = os.path.splitext(apk_with_extension)
        log_txt_update.write("[INFO]: Found The APK: " + apk_with_extension + " - Processing Now\n")

        apk_main_dir = inputdirectory + "\\apk_post_run\\"
        try:
            os.mkdir(apk_main_dir)
        except:
            log_txt_update.write("[WARN]: Error Making APK Post-Run Directory, likely already exists: " + apk_main_dir + "\n")

        apk_main_dir_apk = inputdirectory + "\\apk_post_run\\" + apk
        try:
            os.mkdir(apk_main_dir_apk)
        except:
            log_txt_update.write("[WARN]: Error Making APK Main Directory, likely already exists: " + apk_main_dir_apk + "\n")
            
        apk_source_directory = apk_main_dir_apk + "\\" + "_0_source"
        try:
            os.mkdir(apk_source_directory)
        except:
            log_txt_update.write("[WARN]: Error Making APK Source Directory, likely already exists: " + apk_source_directory + "\n")
            
        apk_decomp_directory = apk_main_dir_apk + "\\" + "_1_decomp"
        try:
            os.mkdir(apk_decomp_directory)
        except:
            log_txt_update.write("[WARN]: Error Making APK Decomp Directory, likely already exists: " + apk_decomp_directory + "\n")

        apk_results_directory = apk_main_dir_apk + "\\" + "_2_results"
        try:
            os.mkdir(apk_results_directory)
        except:
            log_txt_update.write("[WARN]: Error Making APK Results Directory, likely already exists: " + apk_results_directory + "\n")

        apk_extract_directory = apk_main_dir_apk + "\\" + "_3_extract"
        try:
            os.mkdir(apk_extract_directory)
        except:
            log_txt_update.write("[WARN]: Error Making APK Extract Directory, likely already exists: " + apk_extract_directory + "\n")
        
        var_information_true_filename = apk_with_extension[9:]
        hashes_file_dump_txt = apk_results_directory + "\\" + apk + "_info.txt"
        hashes_file_dump_csv = apk_results_directory + "\\" + apk + "_info.csv"
        jadx_ip_extract_txt = apk_results_directory + "\\" + apk + "_regex_IPs.txt"
        jadx_ip_extract_csv = apk_results_directory + "\\" + apk + "_regex_IPs.csv"

        var_information_filename_write = ("[INFO]: True APK Filename is: " + var_information_true_filename + "\n")
        log_txt_update.write("[INFO]: True APK Filename is: " + var_information_true_filename + "\n")
        file_txt_update = open(hashes_file_dump_txt, "a")
        file_txt_update.write(var_information_filename_write)

        md5_hash = hashlib.md5()
        with open(apk_full_path,"rb") as f:
            for byte_block in iter(lambda: f.read(4096),b""):
                md5_hash.update(byte_block)
            apk_md5_hash = md5_hash.hexdigest()
            var_information_md5hash_write = ("[RESULTS]: MD5 Hash for: " + apk + " is: " + apk_md5_hash + "\n")
            file_txt_update.write(var_information_md5hash_write)

        sha1_hash = hashlib.sha1()
        with open(apk_full_path,"rb") as f:
            for byte_block in iter(lambda: f.read(4096),b""):
                sha1_hash.update(byte_block)
            apk_sha1_hash = sha1_hash.hexdigest()
            var_information_sha1hash_write = ("[RESULTS]: SHA1 Hash for: " + apk + " is: " + apk_sha1_hash + "\n")
            file_txt_update.write(var_information_sha1hash_write)

        sha256_hash = hashlib.sha256()
        with open(apk_full_path,"rb") as f:
            for byte_block in iter(lambda: f.read(4096),b""):
                sha256_hash.update(byte_block)
            apk_sha256_hash = sha256_hash.hexdigest()
            var_information_sha256hash_write = ("[RESULTS]: SHA256 Hash for: " + apk + " is: " + apk_sha256_hash + "\n")
            file_txt_update.write(var_information_sha256hash_write)

        sha512_hash = hashlib.sha512()
        with open(apk_full_path,"rb") as f:
            for byte_block in iter(lambda: f.read(4096),b""):
                sha512_hash.update(byte_block)
            apk_sha512_hash = sha512_hash.hexdigest()
            var_information_sha512hash_write = ("[RESULTS]: SHA512 Hash for: " + apk + " is: " + apk_sha512_hash + "\n")
            file_txt_update.write(var_information_sha512hash_write)

        try:        
            os.system(".\\win\\bin\\jadx.bat -d " + apk_decomp_directory + "\\" + apk + "_source " + apk_full_path)
        except:
            log_txt_update.write("[WARN]: Error Decompiling: " + apk_full_path + " with JADX \n")            
        
        var_ip_list_unscrubbed = []
        var_proto_list_unscrubbed = []

        try:
            with ZipFile(apk_full_path,"r") as var_apk_unzip:
                var_apk_unzip.extractall(apk_extract_directory + "\\")
        except:
            log_txt_update.write("[WARN]: Error Extracting: " + apk_full_path + "\n")
        
        var_path_to_android_xml = apk_extract_directory + "\\AndroidManifest.xml"
        var_cert_RSA_location = apk_extract_directory + "\\META-INF\\CERT.RSA"
        var_android_buildinfo_location = apk_extract_directory + "\\SEC-INF\\buildinfo.xml"
        
        ### Cleanup (Per APK) ###
        apk_move_cleanup_loc = apk_source_directory + "\\" + apk_with_extension
        try:
            shutil.move(apk_full_path, apk_move_cleanup_loc)
        except:
            log_txt_update.write("[WARN]: Error Moving APK: " + apk_full_path + " to: " + apk_move_cleanup_loc + "\n")
        file_txt_update.close()
    ### Final Cleanup ###
    log_txt_update.close()
        
if __name__ == "__main__":
   main(sys.argv[1:])
   
