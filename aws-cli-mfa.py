#!/usr/bin/env python3
"""
Module Docstring


TODO: Update this to use all necessary env variables here:
https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html
"""

__author__ = "Bruno Cacheira"
__version__ = "0.1.0"
__license__ = "MIT"

import os
import json
import argparse
import subprocess
import configparser
import sys

# If logzero is available, use it, else, go standard
try:
    import logzero
    from logzero import logger
except ImportError:
    # If logzero is not available, we use standard logging
    import logging as logger 
    logger.basicConfig(filename='aws-cli-mfa.log',
                    filemode='w',
                    format='[%(asctime)s] : %(levelname)s : %(message)s',
                    #level=logger.DEBUG
                    )
else:
    # We configure logzero
    # Set a logfile (all future log messages are also saved there), but disable the default stderr logging
    logzero.logfile("aws-cli-mfa.log", disableStderrLogger=True)

 
CREDS_FILE = os.path.expanduser('~/.aws/credentials')
CONFIG_FILE = os.path.expanduser('~/.aws/config')
SESSION_DURATION = '43200' # The console default is 12 hours - https://aws.amazon.com/console/faqs/#session_expire





def trimProfileName(profile):
    # in case you have a section [profile name]
    if len(profile.split()) == 2:
        return profile.split()[1]
    ### end

def getDefaultProfile( awsConfig ):
    # It the ENV is set, it takes percedence
    default = os.getenv('AWS_DEFAULT_PROFILE')
    if default:
        logger.debug("Profile found in env(AWS_DEFAULT_PROFILE): " + default)
        return default
    # If not, let's see if there is a profile named "default"
    if awsConfig.has_section("default"):
        return "default"
    # else, let's use the first option in the config file
    if awsConfig.sections() == []:
        logger.warning('"~/aws/config" is empty or misformatted')
        return None 
    default = trimProfileName( awsConfig.sections()[0] )
    logger.debug('Profile found in "~/aws/config": ' + default)
    return( default )
    ### end

def getMfaArn( awsConfig, profile ):
    print ("")
    # to be implemented, replacing the profile concat hack
    ### end

def main():
    # First, let's make sure we have a config file
    if not os.path.exists(os.path.expanduser('~/.aws/config')):
        logger.error('You need to define an AWS CLI config file in "~/.aws/config" first')
        sys.exit(1)

    # Let's read the config - we could read credentials, but config always exists and has mfa arn
    awsConfig = configparser.ConfigParser()
    awsConfig.read( os.path.expanduser('~/.aws/config') )

    parser = argparse.ArgumentParser(description='Update your AWS CLI Token')
    parser.add_argument('token',
                        help='token from your MFA device'
                        )
    parser.add_argument('--profile',
                        help='AWS profile to store the session token.\
                        If unset, ENV(AWS_PROFILE) or first profile in "~/.aws/config" will be used.',
                        default = getDefaultProfile( awsConfig )
                        )
    parser.add_argument('--arn',
                        help='AWS ARN from the IAM console (Security credentials -> Assigned MFA device).\
                              This is saved to your .aws/credentials file'
                        )
    parser.add_argument('--credential-path',
                        help='path to the aws credentials file',
                        default=os.path.expanduser('~/.aws/credentials')
                        )
    parser.add_argument('--duration',
                        help='The  duration, in seconds, that the credentials should remain valid.',
                        default = SESSION_DURATION
                        )

    args = parser.parse_args()

    logger.info('Using profile "' + args.profile + '"')

    # we'll simplify for now
    if awsConfig.has_option( "profile " + args.profile , "mfa_serial" ):
        configArn = awsConfig.get( "profile " + args.profile , "mfa_serial")
    elif awsConfig.has_option( args.profile , "mfa_serial" ):
        configArn = awsConfig.get( args.profile , "mfa_serial")
    else:
        configArn = None

    if args.profile is None:
        parser.error('Expecting --profile or profile set in environment AWS_DEFAULT_PROFILE, or in config file. e.g. "stage"')
        logger.error('Expecting --profile or profile set in environment AWS__DEFAULT_PROFILE, or in config file. e.g. "stage"')
    if args.profile not in awsConfig.sections():
        if "profile " +  args.profile not in awsConfig.sections():
            parser.error('Invalid profile. Section not found in "~/.aws/config"')
            logger.error('Invalid profile. Section not found in "~/.aws/config"')
    
    # If the ARN is provided or in the config...
    if args.arn is None:
        if configArn is None:
            parser.error('ARN is not provided. Please specify via --arn')
            logger.error('ARN is not provided. Please specify via --arn')
        else:
            args.arn = configArn

    # Now let's look at the credentials file
    awsCreds = configparser.ConfigParser()
    # file path should come from somewhere else
    awsCreds.read( os.path.expanduser('~/.aws/credentials') )

    
    # Generate the session token from the default profile based on the environment. We do not want to overwrite these profiles as we wouldn't
    # be able to generate another token
    logger.info( 'executing: ' +
                'aws sts get-session-token --profile %s --duration-seconds %s  --serial-number %s --token-code %s', 
                args.profile, args.duration, args.arn, args.token)
    result = subprocess.run(['aws', 'sts', 'get-session-token',
                            '--profile', args.profile,
                            '--duration-seconds', args.duration,
                            '--serial-number', args.arn, '--token-code',
                            args.token], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        logger.error( result.stderr.decode('utf-8').strip('\n') )
        parser.error( result.stderr.decode('utf-8').strip('\n') )
    
    logger.debug( 'Got response: ' + result.stdout.decode('utf-8').strip('\n') ) 
    
    credentials = json.loads(result.stdout.decode('utf-8'))['Credentials']

    profileMFA = args.profile + "_mfa"
    # Lets eliminate old creds
    awsCreds.remove_section( profileMFA )
    # and set the new ones
    awsCreds.add_section( profileMFA )
    awsCreds[profileMFA]['aws_access_key_id'] = credentials['AccessKeyId']
    awsCreds[profileMFA]['aws_secret_access_key'] = credentials['SecretAccessKey']
    awsCreds[profileMFA]['aws_session_token'] = credentials['SessionToken']
    
    # Save the changes back to the file
    with open(CREDS_FILE, 'w') as configFile:
        awsCreds.write(configFile)
    
    print ("Credentials file setand valid until %s. If you want to use this profile, please use \
            \n \t\033[1m export AWS_DEFAULT_PROFILE = %s\033[0m",
            credentials['Expiration'],
            args.profile)
    logger.info("Credentials file set and valid until %s", credentials['Expiration'])

if __name__== "__main__":
  main()

""" 


if args.arn is None:
    if 'aws_arn_mfa' not in config[args.profile]:
        parser.error('ARN is not provided. Specify via --arn')

    args.arn = config[args.profile]['aws_arn_mfa']
else:
    # Update the arn with user supplied one
    config[args.profile]['aws_arn_mfa'] = args.arn



credentials = json.loads(result.stdout.decode('utf-8'))['Credentials']

config[args.profile]['aws_access_key_id'] = credentials['AccessKeyId']
config[args.profile]['aws_secret_access_key'] = credentials['SecretAccessKey']
config[args.profile]['aws_session_token'] = credentials['SessionToken']

# Save the changes back to the file
with open(args.credential_path, 'w') as configFile:
    config.write(configFile)

print('Saved {} credentials to {}'.format(args.profile, args.credential_path))
 """