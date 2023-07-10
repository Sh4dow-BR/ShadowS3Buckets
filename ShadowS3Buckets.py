#!/usr/bin/env python

"""
This script is to help you get an understanding of what possible risks you are facing with your S3 buckets.
ShadowS3Buckets was used as a side project to learn how Boto3 works, learn to program in Python for the first time and also S3 buckets.
It was built in a modular way, which means that there are functions that need to be run and will break the script if commented and others that are optional.
ShadowS3Buckets has the capability to check multiple features of every bucket in an account and also assume roles in as many other accounts that you need.
Be aware that I'm not a professional programmer, so I imagine a lot of refactoring can be done in the code to improve it and any help is greatly appreciated!
****** Most of the configuration or ajustments that you will need to check/do/define inside the script will be in the 'main' & 'assume_role' function ******
Thanks!
- Fernando (Sh4dow-BR)
"""


#####################################################################
#                              IMPORTS                              #
#####################################################################

import argparse
import json
import time
import inspect
import boto3
from botocore.exceptions import ClientError, ProfileNotFound


#####################################################################
#                   CONSTANTS & GLOBAL VARIABLES                    #
#####################################################################

## The profile that you initially use to make the first API calls, will be the account that will assume roles in the other accounts..
## Insert each 12-digit Account ID into the list of the accounts you want to check and assume roles in, with the following format:
# ACCOUNT_IDS = ['111111111111','222222222222','333333333333']

ACCOUNT_IDS = ['']

CRED = '\033[91m'
CGREEN = '\033[92m'
CBLUE = '\033[94m'
CEND = '\033[0m'
CBOLD = '\033[1m'
CITALIC = '\033[3m'
CUNDER = '\033[4m'

SEPERATE = '---------------'
SEPERATE2 = '+++++++++++++++++++++++++++++++++++++++++++++++++++++++++'
SEPERATE4 = SEPERATE2 + SEPERATE2

ENABLED = f"{CGREEN}Enabled{CEND}"
DISABLED = f"{CRED}Disabled{CEND}"
TRUE = f"{CGREEN}TRUE{CEND}"
FALSE = f"{CRED}False{CEND}"
WARNING = f"{CUNDER}{CBOLD}WARNING{CEND}"


#####################################################################
#                          ARGUMENT PARSER                          #
#####################################################################

# Help parser description.
intro = "Execute the script and show this help menu."

# Initialize parser
parser = argparse.ArgumentParser(prog='./ShadowS3Buckets.py', description=intro)

# Adding optional argument
parser.add_argument('-p', '--Profile', nargs='?', required=False,
                    help='Use a different AWS profile than the DEFAULT configured profile to make the API calls')


#####################################################################
#         FUNCTIONS THAT RUN BEFORE MAKING API CALLS TO AWS         #
#####################################################################

def banner():
    """
    Function that prints the main banner used in the script.
    """

    # DOS REBEL
    banner_script = """
  █████████  █████                    █████                              █████████   ████████     ███████████                      █████                █████           
 ███░░░░░███░░███                    ░░███                              ███░░░░░███ ███░░░░███   ░░███░░░░░███                    ░░███                ░░███            
░███    ░░░  ░███████    ██████    ███████   ██████  █████ ███ █████   ░███    ░░░ ░░░    ░███    ░███    ░███ █████ ████  ██████  ░███ █████  ██████  ███████    █████ 
░░█████████  ░███░░███  ░░░░░███  ███░░███  ███░░███░░███ ░███░░███    ░░█████████    ██████░     ░██████████ ░░███ ░███  ███░░███ ░███░░███  ███░░███░░░███░    ███░░  
 ░░░░░░░░███ ░███ ░███   ███████ ░███ ░███ ░███ ░███ ░███ ░███ ░███     ░░░░░░░░███  ░░░░░░███    ░███░░░░░███ ░███ ░███ ░███ ░░░  ░██████░  ░███████   ░███    ░░█████ 
 ███    ░███ ░███ ░███  ███░░███ ░███ ░███ ░███ ░███ ░░███████████      ███    ░███ ███   ░███    ░███    ░███ ░███ ░███ ░███  ███ ░███░░███ ░███░░░    ░███ ███ ░░░░███
░░█████████  ████ █████░░████████░░████████░░██████   ░░████░████      ░░█████████ ░░████████     ███████████  ░░████████░░██████  ████ █████░░██████   ░░█████  ██████ 
 ░░░░░░░░░  ░░░░ ░░░░░  ░░░░░░░░  ░░░░░░░░  ░░░░░░     ░░░░ ░░░░        ░░░░░░░░░   ░░░░░░░░     ░░░░░░░░░░░    ░░░░░░░░  ░░░░░░  ░░░░ ░░░░░  ░░░░░░     ░░░░░  ░░░░░░  
    
                                   Created by Fernando (Sh4dow-BR) | https://github.com/Sh4dow-BR | https://shadowsecurity.com.br
    """
    print("\033[31;1m" + banner_script + "\033[98m\033[00m")


def closing_banner(total_time_perf_formatted):
    """
    Function that prints the closing banner with the time that it took to execute the script.
    It uses the 'total_time_perf_formatted' parameter from the 'total_time_and_main' function to print the time.
    """

    print(' ______________________________________ ')
    print('|                                      |')
    print('|     The script finished executing    |')
    print(f'|         in {total_time_perf_formatted} seconds          |')
    print('|______________________________________|\n')
    

def profile_check():
    """
    Function checks if the -p argument was passed and if not, will use the 'default' AWS configured profile.
    It then returns the value stored in the 'Profile' parameter to create a session in AWS to make API calls.
    """

    args = parser.parse_args()

    if args.Profile is None:
        args = parser.parse_args(['--Profile', 'default'])
        return args.Profile
    else:
        return args.Profile


def validate_assume_role_in_main():
    """
    Function that checks all the functions called in the 'main' function.
    Then it then prints allf the functions and filters for only the 'assume_role' function.
    Finally, it returns 'True' or 'False' if it's being called or not in the 'main' function.
    """

    functions = [obj for name, obj in inspect.getmembers(inspect.getmodule(main))
                 if inspect.isfunction(obj) and obj.__module__ == __name__
                 and inspect.getmodule(obj) == inspect.getmodule(inspect.currentframe().f_back)]

    # Print the names of the functions called inside the main function
    for function in functions:
        if function.__name__ == "assume_role" in main.__code__.co_names:
            return True
        else:
            return False
    
    
def check_account_id_and_assume_role():
    """
    Function that checks if the 'assume_role' was called and if account IDs were passed to the 'ACCOUNT_IDS' const.
    It returns the result of the 'validate_assume_role_in_main' to check if it's being called and is 'True' or 'False'.
    Then, depending on the comparison of 'ACCOUNTS_IDS' and 'assume_role_result', it passes (continues the script) or throws an error.
    This function executes and checks before running any AWS service/client calls to catch and fix the error early on.
    """

    assume_role_result = validate_assume_role_in_main()

    if ACCOUNT_IDS != [''] and assume_role_result is True:
        pass
    elif ACCOUNT_IDS != [''] and assume_role_result is False:
        print(f"{CRED}{CBOLD}ERROR{CEND}: Assume role was not called but there are accounts to check")
        print("There are accounts in the 'ACCOUNT_IDS' constant but the 'assume_role' function in the 'main' function was not called")
        print("Uncomment the 'assume_role' function in the 'main' function")
        exit()
    elif ACCOUNT_IDS == [''] and assume_role_result is True:
        print(f'{CRED}{CBOLD}ERROR{CEND}: Assume role was called but there were no accounts to check')
        print("Insert account IDs in the 'ACCOUNT_IDS' constant or comment out the 'assume_role' function in the 'main' function")
        exit()
    else:
        pass


def create_session(profile_check):
    """
    Function that checks if the profile used in the 'profile_check' function is valid to create a boto3 session.
    If the profile is valid, it will create a testing session to validate that API calls can be made.
    If the profile isn't valid, it will return the profile not found error.
    """

    profile_name = profile_check()

    try:
        session = boto3.Session(profile_name=profile_name)
        print(f'             Using the {CRED}{profile_name}{CEND} AWS Profile')
        return session

    except ProfileNotFound:
        print(f'{CRED}{CBOLD}Profile not found{CEND}: The config profile ({CRED}{profile_name}{CEND}) could not be found.')
        print('--> Retry with a different profile or check the profile passed on the -p parameter')
        exit()


#####################################################################
#         FUNCTIONS THAT RUN AWS API SERVICE & CLIENT CALLS         #
#####################################################################


def get_caller_identity(session):
    """
    Function uses the profile provided in the 'create_session' function to call sts and get the Account ID used.
    This function helps when trying to debug or run the script with various accounts.
    It also helps when testing using different profiles using the '-p' argument.
    """

    sts = session.client('sts')

    account_id = sts.get_caller_identity()["Account"]
    arn = sts.get_caller_identity()['Arn']

    print('******************************************************')
    print(f'             Account ID: {account_id}               ')
    print(f'        {arn}      ')
    print('******************************************************')


def list_s3_buckets(list_buckets):
    """
    Function to list all S3 bucket names in the account.
    If there are no buckets, it will print out that there are no buckets in the account and continue the script.
    """

    profile_name = profile_check()

    print(f'\n{CRED}{CBOLD}[+][+] Checking to see if there buckets in this account [+][+]{CEND}')

    try:
        if list_buckets['Buckets'] == []:
            print('There are no S3 buckets in this account.')
        else:
            count = 0

            print(f'\n{CBLUE}{CBOLD}[+] Bucket names: [+]{CEND}\n')

            for bucket in list_buckets.get('Buckets', []):
                count += 1
                bucket_name = bucket["Name"]
                print(f'{count}) {bucket_name}')
    except ClientError as error:
        if error.response['Error']['Code'] == 'AccessDenied':
            print(f"{CRED}{CBOLD}Access Denied{CEND}: This profile doesn't have the permission to list S3 buckets")
            print('--> Check the permissions of the AWS profile used')
            print(f'--> Add the "s3:ListAllMyBuckets" permission to the {CRED}{profile_name}{CEND} user')
            exit()
        elif error.response['Error']['Code'] == 'InvalidAccessKeyId':
            print(f"{CRED}{CBOLD}Invalid Access Key ID{CEND}: The AWS Access Key ID you provided doesn't exist")
            print('--> Retry with a different profile or validate if the Access Key is valid')
            exit()
        else:
            print('An unexpected error occured :( Please open an issue on the GitHub repo to help add a custom error message!')
            print(f'{CRED}{CBOLD}Error Message{CEND}: {error}')
            exit()


def sse_status(s3, list_buckets):
    """ 
    Function that calls the bucket name and checks the server-side encryption (SSE) status of each bucket.
    It will either output, SSE-S3, KMS or that is not encrypted while also checking for the bucket key when KMS is enabled.
    If there are no buckets, it will print out that there are no buckets in the account and continue the script.
    """

    print(f'\n{CBLUE}{CBOLD}[+] Bucket name & Server-side encryption status: [+]{CEND}')
    print(SEPERATE4)
    print(f"Bucket encryption: {CUNDER}https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html{CEND}")
    print(f"Bucket key: {CUNDER}https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-key.html{CEND}")
    print(SEPERATE4 + '\n')

    if list_buckets['Buckets'] == []:
        print(f'{WARNING}: Skipping this check since there are no buckets on this account')
    else:
        count = len(list_buckets.get('Buckets'))

        for bucket in list_buckets.get('Buckets', []):
            bucket_name = bucket["Name"]
            count -= 1
            try:
                bucket_encryption = s3.get_bucket_encryption(Bucket=bucket['Name'])
                # Thanks ChatGPT for the filtering, I initially had no idea on how to do this :D
                sse_algorithm = bucket_encryption['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']
                bucket_key = str(bucket_encryption['ServerSideEncryptionConfiguration']['Rules'][0]['BucketKeyEnabled'])
                if 'AES256' in sse_algorithm:
                    print(f'  {CBOLD}{bucket_name}{CEND}: {ENABLED} -> Amazon S3 managed (SSE-S3)')
                    if 'True' in bucket_key:
                        print(f'  -- Bucket Key is: {CRED}Enabled{CEND} --> This should be turned off as it only applies for KMS')
                        if count > 0:
                            print('  ******')
                    else:
                        print(f'  -- Bucket Key is: {CGREEN}Disabled{CEND} --> This is configured correctly as it only applies for KMS')
                        if count > 0:
                            print('  ******')
                elif 'aws:kms' in sse_algorithm:
                    kms_masterkey = bucket_encryption['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']['KMSMasterKeyID']
                    print(f'  {CBOLD}{bucket_name}{CEND}: {ENABLED} -> Amazon S3 Managed Key (SSE-KMS)')
                    print(f'  -- KMS Master Key ID: {kms_masterkey}')
                    if 'True' in bucket_key:
                        print(f'  -- Bucket Key is: {ENABLED} --> Check the Docs if you want to learn more about this feature')
                        if count > 0:
                            print('  ******')
                    else:
                        print(f'  -- Bucket Key is: {DISABLED} --> Check the Docs to learn more and see if you can enable this feature')
                        if count > 0:
                            print('  ******')
                else:
                    print(f'  {CBOLD}{bucket_name}{CEND}: {DISABLED}')
            except ClientError as error:
                if error.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    print(f'  {CBOLD}{bucket_name}{CEND}: {CRED}SSE Configuration Not Found{CEND}')
                else:
                    print(f'{CRED}{CBOLD}Error Message{CEND}: {error}')
                    exit('An unexpected error occured :( Please open an issue on the GitHub repo to help add a custom error message!')


def versioning_status(s3, list_buckets):
    """ 
    Function that calls the bucket name and versioning status of each bucket.
    It will either output, if versioning is activated for the bucket or not and if MFA is activated.
    If there are no buckets, it will print out that there are no buckets in the account and continue the script.
    """

    print(f'\n{CBLUE}{CBOLD}[+] Bucket name & Bucket versioning status: [+]{CEND}')
    print(SEPERATE4)
    print(f"Versioning: {CUNDER}https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html{CEND}")
    print(f"MFA delete: {CUNDER}https://docs.aws.amazon.com/AmazonS3/latest/userguide/MultiFactorAuthenticationDelete.html{CEND}")
    print(SEPERATE4 + '\n')

    profile_name = profile_check()

    if list_buckets['Buckets'] == []:
        print(f'{WARNING}: Skipping this check since there are no buckets on this account')
    else:
        count = len(list_buckets.get('Buckets'))

        for bucket in list_buckets.get('Buckets', []):
            bucket_name = bucket["Name"]
            count -= 1
            try:
                get_bucket_versioning = s3.get_bucket_versioning(Bucket=bucket['Name'])
                if 'Status' in get_bucket_versioning:
                    print(f'  {CBOLD}{bucket_name}{CEND}: {ENABLED} -> Versioning is activated')
                else:
                    print(f'  {CBOLD}{bucket_name}{CEND}: {DISABLED} -> Versioning is off')
                if 'MFADelete' in get_bucket_versioning:
                    print(f'  {CBOLD}{bucket_name}{CEND}: {ENABLED} ->  MFA is activated')
                    if count > 0:
                        print('  ******')
                else:
                    print(f'  {CBOLD}{bucket_name}{CEND}: {DISABLED} -> MFA is off')
                    if count > 0:
                        print('  ******')
            except ClientError as error:
                if error.response['Error']['Code'] == 'AccessDenied':
                    print(f"{CRED}{CBOLD}Access Denied{CEND}: This profile doesn't have the permission to see the versioning S3 buckets")
                    print(f'---> Add the "s3:GetBucketVersioning" permission to the {CRED}{profile_name}{CEND} user.')
                    exit()
                else:
                    print('An unexpected error occured :( Please open an issue on the GitHub repo to help add a custom error message!')
                    print(f'{CRED}{CBOLD}Error Message{CEND}: {error}')
                    exit()


def public_access_block_status(s3, list_buckets):
    """ 
    Function that calls the bucket name and the public access block status of each bucket.
    It will check if the bucket or any aspect of the bucket is publicly accessible to the internet which is very dangerous.
    It checks 4 flags regarding the "Public Access Block" and will list if flag/configuration is enabled with the "False" result.
    If there are no buckets, it will print out that there are no buckets in the account and continue the script.
    """

    print(f'\n{CBLUE}{CBOLD}[+] Bucket name & Public access block status: [+]{CEND}')
    print(SEPERATE4)
    print('If you do not understand this part, read more here')
    print(f"Block public access: {CUNDER}https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html{CEND}")
    print(SEPERATE4 + '\n')

    profile_name = profile_check()

    if list_buckets['Buckets'] == []:
        print(f'{WARNING}: Skipping this check since there are no buckets on this account')
    else:
        count = len(list_buckets.get('Buckets'))

        for bucket in list_buckets.get('Buckets', []):
            bucket_name = bucket["Name"]
            count -= 1
            try:
                get_public_access_block = s3.get_public_access_block(Bucket=bucket['Name'])
                block_public_acl = str(get_public_access_block['PublicAccessBlockConfiguration']['BlockPublicAcls'])
                ignore_public_acl = str(get_public_access_block['PublicAccessBlockConfiguration']['IgnorePublicAcls'])
                block_public_policy = str(get_public_access_block['PublicAccessBlockConfiguration']['BlockPublicPolicy'])
                restrict_public_bucket = str(get_public_access_block['PublicAccessBlockConfiguration']['RestrictPublicBuckets'])

                if block_public_acl == 'True' and ignore_public_acl == 'True' and block_public_policy == 'True' and restrict_public_bucket  == 'True':
                    print(f'  {CBOLD}{bucket_name}{CEND}: {TRUE} -> The bucket has all the 4 blocks configured')
                    if count > 0:
                        print('  ******')
                else:
                    print(f'  {CBOLD}{bucket_name}{CEND}: {WARNING} At least 1 block is not configured which can mean that this bucket can be public')
                    if 'True' in block_public_acl:
                        print(f'  -- Block public ACL: {TRUE} --> The block is active')
                    else:
                        print(f'  -- Block public ACL: {FALSE} --> The block is not activated')
                    if 'True' in ignore_public_acl:
                        print(f'  -- Ignore public ACL: {TRUE} --> The block is active')
                    else:
                        print(f'  -- Ignore public ACL: {FALSE} --> The block is not activated')
                    if 'True' in block_public_policy:
                        print(f'  -- Block public policy: {TRUE} --> The block is active')
                    else:
                        print(f'  -- Block public policy: {FALSE} --> The block is not activated')
                    if 'True' in restrict_public_bucket:
                        print(f'  -- Restrict public bucket: {TRUE} --> The block is active')
                        if count > 0:
                            print('  ******')
                    else:
                        print(f'  -- Restrict public bucket: {FALSE} --> The block is not activated')
                        if count > 0:
                            print('  ******')
            except ClientError as error:
                if error.response['Error']['Code'] == 'AccessDenied':
                    print(f"{CRED}{CBOLD}Access Denied{CEND}: This profile doesn't have the permission to see the public access settings of S3 buckets")
                    print(f'--> Add the "s3:GetBucketPublicAccessBlock" permission to the {CRED}{profile_name}{CEND} user.')
                    exit()
                elif error.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    print(f'{CRED}{CBOLD}No Public Access Block Configured{CEND}: {CBOLD}{bucket_name}{CEND}')
                    print(f'--> {WARNING}: There are no public access blocks configured for this bucket')
                    print('--> By itself, this does not mean the bucket is public, but it is a warning sign in case it is a private bucket')
                    if count > 0:
                        print('  ******')
                    continue
                else:
                    print('An unexpected error occured :( Please open an issue on the GitHub repo to help add a custom error message!')
                    print(f'{CRED}{CBOLD}Error Message{CEND}: {error}')
                    exit()


def bucket_policy_status(s3, list_buckets):
    """ 
    Function that calls the bucket name and the public bucket policy status of each bucket.
    This is a further investigation to validate if a bucket is publicly accessible.
    For a bucket to be considered public, it needs "public_access_block_status" to be "public" and also the "bucket policy" allowing items inside the bucket to be public.
    This status check is only "dangerous" when the public is considered public, if it is not, there is nothing to worry about.
    If there are no buckets, it will print out that there are no buckets in the account and continue the script.
    """

    print(f'\n{CBLUE}{CBOLD}[+] Bucket name & Public Bucket policy status: [+]{CEND}')
    print(SEPERATE4)
    print('If you do not understand this part, read more here')
    print(f"Block public access: {CUNDER}https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html{CEND}")
    print(SEPERATE4 + '\n')

    profile_name = profile_check()

    if list_buckets['Buckets'] == []:
        print(f'{WARNING}: Skipping this check since there are no buckets on this account')
    else:
        count = len(list_buckets.get('Buckets'))

        for bucket in list_buckets.get('Buckets', []):
            bucket_name = bucket["Name"]
            count -= 1
            try:
                get_bucket_policy_status = s3.get_bucket_policy_status(
                    Bucket=bucket['Name'])
                is_public = str(get_bucket_policy_status['PolicyStatus']['IsPublic'])
                if is_public == 'True':
                    print(f'  {CBOLD}{bucket_name}{CEND} : {TRUE} -> {WARNING}: The configured bucket policy is considered public')
                    if count > 0:
                        print('  ******')
                else:
                    print(f'  {CBOLD}{bucket_name}{CEND} : {FALSE} -> There is a bucket policy configured but it is not considered public')
                    if count > 0:
                        print('  ******')
            except ClientError as error:
                if error.response['Error']['Code'] == 'AccessDenied':
                    print(f"{CRED}{CBOLD}Access Denied{CEND}: This profile doesn't have the permission to see the public access settings of S3 buckets")
                    print(f'---> Add the "s3:GetBucketPolicyStatus" permission to the {CRED}{profile_name}{CEND} user.')
                    exit()
                elif error.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    print(f'{CRED}{CBOLD}No Bucket policy configured{CEND}: {CBOLD}{bucket_name}{CEND}')
                    print('---> There is no bucket policy configured for this bucket')
                    if count > 0:
                        print('  ******')
                    continue
                else:
                    print('An unexpected error occured :( Please open an issue on the GitHub repo to help add a custom error message!')
                    print(f'{CRED}{CBOLD}Error Message{CEND}: {error}')
                    exit()


def bucket_policy(s3, list_buckets):
    """
    Function that calls the bucket name and the bucket policy attached to each bucket.
    It will output the policy in JSON format, the exact way that it is configured on the AWS Management Console.
    If there are no buckets, it will print out that there are no buckets in the account and continue the script.
    """

    print(f'\n{CBLUE}{CBOLD}[+] Bucket name & Configured Bucket policy: [+]{CEND}')
    print(SEPERATE4)
    print('If you do not understand this part, read more here')
    print(f"Block public access: {CUNDER}https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html{CEND}")
    print(SEPERATE4 + '\n')

    profile_name = profile_check()

    if list_buckets['Buckets'] == []:
        print(f'{WARNING}: Skipping this check since there are no buckets on this account')
    else:
        count = len(list_buckets.get('Buckets'))

        for bucket in list_buckets.get('Buckets', []):
            bucket_name = bucket["Name"]
            count -= 1
            try:
                get_bucket_policy = s3.get_bucket_policy(Bucket=bucket['Name'])
                policy = get_bucket_policy['Policy']

                data = json.loads(policy)
                policy_formatted = json.dumps(data, indent=4)

                print(f'{CBOLD}{CRED}{bucket_name}{CEND}')
                print(policy_formatted + '\n')
            except ClientError as error:
                if error.response['Error']['Code'] == 'AccessDenied':
                    print(f"{CRED}{CBOLD}Access Denied{CEND}: This profile doesn't have the permission to see the public access settings of S3 buckets")
                    print(f'---> Add the "s3:GetBucketPolicy" permission to the {CRED}{profile_name}{CEND} user.')
                    exit()
                elif error.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    print(f'{CRED}{CBOLD}No Bucket policy configured{CEND}: {CBOLD}{bucket_name}{CEND}')
                    print('---> There is no bucket policy configured for this bucket')
                    if count > 0:
                        print('  ******')
                    continue
                else:
                    print('An unexpected error occured :( Please open an issue on the GitHub repo to help add a custom error message!')
                    print(f'{CRED}{CBOLD}Error Message{CEND}: {error}')
                    exit()


def assume_role():
    """
    Function that will try to assume a role in another account or various other accounts and execute the same requests as if for a single account check.
    It will need a "role name" and a "role session name" along with the account ID of the other accounts.
    It will perform this function for each account in the "ACCOUNT_IDS" constant.
    Depending on what functions you want to call for the other accounts, you can comment out the functions that you do not want to execute.
    This function usually works well from the management/delegated account in a AWS Organization but you can also call assume roles from cross-accounts.
    If you want to call cross-accounts, you will need to create a role in "Account B" to permit "Account A" to assume a role in that account.
    If there are no other accounts to check, it will finish the script.
    """

    print(f'\n{CRED}{CBOLD}[+][+][+] Validating other accounts to assume a role: [+][+][+]{CEND}')
    print(SEPERATE4)
    print('If you do not understand this part, check out these User Guides')
    print(f"Assuming a role: {CUNDER}https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html{CEND}")
    print(f"Assuming a role: {CUNDER}https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access.html{CEND}")
    print(f"Assuming a cross-account role: {CUNDER}https://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_cross-account-with-roles.html{CEND}")    
    print(SEPERATE4 + '\n')

    ## Insert the default AWS Organizations role_name 'OrganizationAccountAccessRole' or a custom one that you have configured
    role_name = 'OrganizationAccountAccessRole'
    ## This role_session_name just helps with overall log auditing and tracing and you can put anything you want here
    role_session_name = 'S3BucketAssumeRoleSession'

    profile_name = profile_check()

    count = len(ACCOUNT_IDS)

    session = boto3.Session(profile_name=profile_name)
    sts = session.client('sts')

    arn = sts.get_caller_identity()['Arn']

    for account in ACCOUNT_IDS:
        count -= 1
        try:
            print(f'\n{CGREEN}{CBOLD}[+][+][+][+][+] Trying to assume a new role: [+][+][+][+][+]{CEND}')
            ## Dont touch this part!
            assumed_role_object = sts.assume_role(
                RoleArn=f"arn:aws:iam::{account}:role/{role_name}",
                RoleSessionName=f"{role_session_name}")
            temporary_credentials = assumed_role_object['Credentials']
            role_id = assumed_role_object['AssumedRoleUser']['AssumedRoleId']

            print('\n******************************************************')
            print(f'    Assuming a role in account ID: {account}')
            print(f'  {role_id}')
            print('******************************************************')

            ## Dont touch this part!
            session = boto3.Session(
                aws_access_key_id=temporary_credentials['AccessKeyId'],
                aws_secret_access_key=temporary_credentials['SecretAccessKey'],
                aws_session_token=temporary_credentials['SessionToken'],
            )

            ## Dont touch this part!
            s3 = session.client('s3')
            list_buckets = s3.list_buckets()

            ## Choose the functions that you want to call in each account and comment out the ones you do not need!

            list_s3_buckets(list_buckets) ## ACTION: Lists all bucket names
            #sse_status(s3, list_buckets) ## ACTION: Checks the status of every bucket to see if the Server Side Encryption was configured.
            #versioning_status(s3, list_buckets) ## ACTION: Checks the status of every bucket to see if Bucket Versioning is enabled.
            #public_access_block_status(s3, list_buckets) ## ACTION: Checks the status of every bucket to see the public access block flag status.
            #bucket_policy_status(s3, list_buckets) ## ACTION: Checks the status of every bucket to see if a bucket policy is configured and if it's considered public.
            #bucket_policy(s3, list_buckets) ## ACTION: Checks the bucket policy configured for every bucket and parses the json bucket policy.

        except ClientError as error:
            if error.response['Error']['Code'] == 'AccessDenied':
                print(f"{CRED}{CBOLD}Access Denied{CEND}: The user: {CUNDER}{arn}{CEND} isn't authorized to assume the role {CUNDER}{role_name}{CEND} in the account {CUNDER}{account}{CEND}")
                print("--> Validate if the user and account is declared with an 'sts:AssumeRole' action with the role name defined in the script in the second account")
                print('--> Check if there is a trust relationship built between the two accounts')
                print("--> By default, 'OrganizationAccountAccessRole' is a role name that is created for accounts created in a AWS organization")
                print('--> This role builds a trust relationshop with the AWS organization management account')
                print(SEPERATE2)
                print('Example trust relationship')
                print("{'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'AWS': 'arn:aws:iam::ACCOUNT_ID:root'}, 'Action': 'sts:AssumeRole'}]}")
                if count > 0:
                    continue
            else:
                print('An unexpected error occured :( Please open an issue on the GitHub repo to help add a custom error message!')
                print(f'{CRED}{CBOLD}Error Message{CEND}: {error}')
                exit()

#####################################################################
#              MAIN AND TOTAL EXECUTION TIME FUNCTIONS              #
#####################################################################


def main():
    """
    This is the main function that will determine and execute all the functions in a procedural way.
    This is the entire logic of the program and you can filter out the functions/blocks you dont want executed.
    """

    ## Required functions & Variables - DO NOT touch this part!

    banner()  ## ACTION: Shows the 'Shadow S3 Buckets' banner.
    check_account_id_and_assume_role() ## ACTION: Checks if account_id is configured and assume_role is
    session = create_session(profile_check) ## ACTION: Creates the 'session' variable to use in other functions.
    get_caller_identity(session) ## ACTION: Gets the caller identity of who will be making the API calls
    s3 = session.client('s3') ## ACTION: Creates the 's3' variable to do client API calls and to use the service in various functions.
    list_buckets = s3.list_buckets() ## ACTION: Creates the 'list_buckets' variable to use the service in various functions.

    ## Optional functions - Choose the functions/blocks you want to run

    list_s3_buckets(list_buckets)  ## ACTION: Lists all bucket names
    #sse_status(s3, list_buckets) ## ACTION: Checks the status of every bucket to see if the Server Side Encryption was configured.
    #versioning_status(s3, list_buckets) ## ACTION: Checks the status of every bucket to see if Bucket Versioning is enabled.
    #public_access_block_status(s3, list_buckets) ## ACTION: Checks the status of every bucket to see the public access block flag status.
    #bucket_policy_status(s3, list_buckets) ## ACTION: Checks the status of every bucket to see if a bucket policy is configured and if it's considered public.
    #bucket_policy(s3, list_buckets) ## ACTION: Checks the bucket policy configured for every bucket and parses the json bucket policy.
    #assume_role() ## ACTION: Executes the 'assume_role' function and inside the function, choose the blocks you want to run when you assume a role.

    ## Testing functions

    #print(validate_assume_role_in_main())
    #print(type(validate_assume_role_in_main()))

def total_time_and_main(main_function: str):
    """
    Function that calculates the total system time to run the script and uses the 'main' function as a parameter.
    It's not exactly only about the program itself but how long the computer takes to run it.
    It's used as a reference and can help with larger accounts with many resources.
    """

    start_time_perf = time.perf_counter()
    main_function()
    end_time_perf = time.perf_counter()

    total_time_perf = end_time_perf - start_time_perf
    total_time_perf_formatted = "{:f}".format(total_time_perf)
    closing_banner(total_time_perf_formatted)


#####################################################################
#                  IF NAME DUNDER IS EQUAL TO MAIN                  #
#####################################################################


if __name__ == '__main__':
    """
    The script "only" executes this function that has the 'main' function as it's parameter.
    The entire execution logic is in the 'main' function.
    """
    
    total_time_and_main(main)
