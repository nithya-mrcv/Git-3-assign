import argparse
import os
import sys
import pwd
import json
import hashlib
from argparse import RawDescriptionHelpFormatter
from datetime import datetime
import grp

mode = 'initialization'
start_time = datetime.now()
files_parsed = 0
directories_parsed = 0
warnings_issued = 0
directiories_data = {}
files_data = {}
stored_data = []
warnings = ''


def getComputedMessageDigest(item, hash_function):
    hash_object = hashlib.sha1()
    if (hash_function == 'md5'):
        hash_object = hashlib.md5()

    with open(item.path, 'rb') as file_content:
        hash_object.update(file_content.read())
    return str(hash_object.digest())


def verifyStoredItems(item, size_of_file, name_of_user,
                      name_of_group, access_rights, last_modified_date, report_path, message_digest):
    global warnings_issued, warnings

    stored_data_item = stored_data[2]['files']
    if (item.is_dir()):
        stored_data_item = stored_data[1]['directories']

    items = {size_of_file: "size_of_file", name_of_user: "name_of_user", name_of_group: "name_of_group",
             access_rights: "access_rights", last_modified_date: "last_modified_date", message_digest: "computed_message_digest"}

    if item.path in stored_data_item:
        for key, value in items.items():
            if (value != 'computed_message_digest' or item.is_file()) and key != stored_data_item[item.path][value]:
                warnings_issued += 1
                warnings += item.path + " has different "+value+"\n"
    else:
        warnings += item.path + " is added\n"
        warnings_issued += 1


def getItemPathDetails(item, hash_function, verification_path, report_path):
    global directiories_data, files_data
    stat_info = os.stat(item.path)
    size_of_file = stat_info.st_size
    name_of_user = pwd.getpwuid(stat_info.st_uid)[0]
    name_of_group = grp.getgrgid(stat_info.st_gid)[0]
    access_rights = oct(stat_info.st_mode & 0o777)
    last_modified_date = str(datetime.fromtimestamp(stat_info.st_mtime))
    message_digest = ''

    if item.is_file():
        message_digest = getComputedMessageDigest(item, hash_function)

    if mode == 'verification':
        verifyStoredItems(item, size_of_file, name_of_user,
                          name_of_group, access_rights, last_modified_date, report_path, message_digest)
    else:
        if item.is_dir():
            directiories_data[item.path] = {
                "size_of_file": size_of_file, "name_of_user": name_of_user, "name_of_group": name_of_group, "access_rights": access_rights, "last_modified_date": last_modified_date
            }
        else:
            files_data[item.path] = {"size_of_file": size_of_file, "name_of_user": name_of_user, "name_of_group": name_of_group,
                                     "access_rights": access_rights, "last_modified_date": last_modified_date, "computed_message_digest": message_digest}


def getDirectoryContents(directory_path, verification_path, report_path, hash_function):
    global directories_parsed, files_parsed

    for item in os.scandir(directory_path):
        if item.is_dir():
            directories_parsed += 1
            getItemPathDetails(item, hash_function,
                               verification_path, report_path)
            getDirectoryContents(
                item.path, verification_path, report_path, hash_function)
        else:
            files_parsed += 1
            getItemPathDetails(item, hash_function,
                               verification_path, report_path)


def commonReportData(directory_path, verification_path, report_path):
    data = ""
    data += "\n\nFull pathname of monitored directory = " + directory_path + \
        "\nFull pathname of verification file =" + verification_path +\
        "\nNumber of directories parsed =" + str(directories_parsed) +\
        "\nNumber of files parsed = " + str(files_parsed)
    return data


def getWarnings():
    return "\n\nWarnings:\n"+warnings if warnings != '' else ''
    # if warnings == '':
    #     return "No"
    # else:
    #     return '\n'+warnings


def generateVerificationFile(verification_path, hash_function):
    result = [{"hash_function": hash_function}, {
        "directories": directiories_data}, {"files": files_data}]
    with open(verification_path, "w") as verification_file:
        verification_file.write(json.dumps(result, indent=1))
    print('Verification file is updated\n')


def generateReportFileForInitializationMode(directory_path, verification_path, report_path):
    with open(report_path, "w") as report:
        report.write(
            "Initialization mode started on "+str(start_time) +
            commonReportData(directory_path, verification_path, report_path) +
            "\n\nTime taken to complete the initialization mode = " + str(datetime.now() - start_time))

    print('Report file is updated\n')


def generateReportFileforVerificationMode(directory_path, verification_path, report_path):
    with open(report_path, "w") as report:
        report.write(
            "Verification mode started on " + str(start_time) +
            "\n\nFull pathname of report file =" + report_path +
            commonReportData(directory_path, verification_path, report_path) +
            "\nNumber of warnings issued = " + str(warnings_issued) +
            getWarnings() +
            "\n\nTime taken to complete the verification mode = " + str(datetime.now() - start_time))

    print('Report file is updated\n')


def validatePaths(directory_path, verification_path, report_path, mode):
    does_directory_exist = os.path.isdir(directory_path)
    if not does_directory_exist:
        sys.exit("Directory path doesn't exist\n")

    paths = [directory_path, verification_path]
    if (os.path.commonprefix(paths) == directory_path):
        sys.exit("Verification file path is not outside the monitored directory\n")

    paths = [directory_path, report_path]
    if (os.path.commonprefix(paths) == directory_path):
        sys.exit("Report file path is not outside the monitored directory\n")

def initialize(directory_path, verification_path, report_path, hash_function):
    print("\nInitialization mode started on " + str(start_time)+"\n")
    validatePaths(directory_path, verification_path, report_path)

    if not (hash_function == 'sha1' or hash_function == 'md5'):
        sys.exit("Hash function is not valid. It should be sha1 or md5\n")

    is_verification_file_exists = os.path.isfile(verification_path)
    is_report_file_exists = os.path.isfile(report_path)

    os.umask(0)
    if not is_verification_file_exists:
        os.open(verification_path, os.O_CREAT, mode=0o777)
    if not is_report_file_exists:
        os.open(report_path, os.O_CREAT, mode=0o777)
    
    getDirectoryContents(directory_path, verification_path,
                         report_path, hash_function)
    generateVerificationFile(verification_path, hash_function)
    generateReportFileForInitializationMode(
        directory_path, verification_path, report_path)


def verify(directory_path, verification_path, report_path):
    global mode, warnings_issued, stored_data, warnings
    mode = 'verification'
    print("\nVerification mode started on "+str(start_time)+"\n")
    validatePaths(directory_path, verification_path, report_path)

    is_verification_file_exists = os.path.isfile(verification_path)
    is_report_file_exists = os.path.isfile(report_path)
    if not is_verification_file_exists:
        sys.exit("Verification file path doesn't exist")
    if not is_report_file_exists:
        os.umask(0)
        os.open(report_path, os.O_CREAT, mode=0o777)

    with open(verification_path) as verification_file:
        stored_data = json.load(verification_file)
        hash_function = stored_data[0]['hash_function']

        getDirectoryContents(directory_path, verification_path,
                             report_path, hash_function)

    for item_path in stored_data[1]['directories']:
        if os.path.isdir(item_path) == 0:
            warnings += item_path + " has been deleted\n"
            warnings_issued += 1
    for item_path in stored_data[2]['files']:
        if os.path.isfile(item_path) == 0:
            warnings += item_path + " has been deleted\n"
            warnings_issued += 1

    generateReportFileforVerificationMode(
        directory_path, verification_path, report_path)


arg_parser = argparse.ArgumentParser(description='''
 System Integrity Verifier\n
 Initialization mode- siv.py -i -D 'important directory' -V 'verification file' -R 'my report' -H 'hash funtion'
 Verification mode-  siv.py -v -D 'important directory' -V 'verification file' -R 'my report2' ''',
                                     formatter_class=RawDescriptionHelpFormatter)

mode = arg_parser.add_mutually_exclusive_group()
mode.add_argument('-i', '--initialization_mode',
                  action='store_true', help='initialization mode')
mode.add_argument('-v', '--verification_mode',
                  action='store_true', help='verification mode')

arg_parser.add_argument('-D', '--important_directory_path',
                        type=str, help='Enter the path for monitored directory')
arg_parser.add_argument('-V', '--verification_file_path',  type=str,
                        help='Enter the path for verification file')
arg_parser.add_argument("-R", "--my_report_file_path", type=str,
                        help="Enter the path for report file")
arg_parser.add_argument("-H", "--hash_function", type=str,
                        help="Enter the hash function(Suppported options: 'sha1' and 'md5')")


siv_args = arg_parser.parse_args()

if siv_args.initialization_mode:
    initialize(siv_args.important_directory_path, siv_args.verification_file_path,
               siv_args.my_report_file_path, siv_args.hash_function)
elif siv_args.verification_mode:
    verify(siv_args.important_directory_path, siv_args.verification_file_path,
           siv_args.my_report_file_path)

