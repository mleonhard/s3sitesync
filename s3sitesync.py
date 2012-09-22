#!/usr/bin/env python
"""S3 Site Sync is a tool upload a website to S3 and keep it
synchronized with a directory on your computer.

Usage: s3sitesync.py [-v] [-q] DIR
 -v  Verbose
 -q  Quick (compare local and remote files only by size and timestamp)
 Config is loaded from DIR/.s3sitesync
 Ignore files by adding names and patterns to DIR/.s3ignore
 Specify mimetypes in DIR/.s3mimetypes

Example:
    $ cat /home/leonhard/www.mysite.com/.s3sitesync
    awsAccessKeyId=AKIAIMDM47V6KXC6YFAA
    awsSecretAccessKey=et5EAWe6EBF7E/F/3St92B5/aghxwDy3UOpzP9mP
    bucketName=www.mysite.com
    awsRegion=us-east-1
    indexDocument=index.html
    errorDocument=
    $ cat /home/leonhard/www.mysite.com/.s3ignore
    *~
    $ cat /home/leonhard/www.mysite.com/.s3mimetypes
    text/html shtml
    text/plain app asc asm bat cpp csv data diff erl java py LICENSE README
    image/png png
    $ s3sitesync.py /home/leonhard/www.mysite.com
    Listing bucket www.mysite.com..
    Listing directory '/home/leonhard/www.mysite.com'..
    No new files
    No changed files
    No deleted files
    Configuring bucket website index_doc=u'index.html' error_doc=''
    Done"""

from __future__ import print_function
import calendar
import ConfigParser
import email.utils
import fnmatch
import hashlib
import io
import mimetypes
import os
import os.path
import Queue
import re
import sys
import threading
import time

import boto.s3.connection

import parallel

__version__ = '1.0'
__author__ = 'Mike Leonhard <mike@restbackup.com>'

DOT_S3SITESYNC=".s3sitesync"
DOT_S3IGNORE=".s3ignore"
DOT_S3MIMETYPES=".s3mimetypes"
WARNING_KEY_NAME="WARNING! Bucket is managed by s3sitesync. Files are deleted automatically."
API_ENDPOINTS = {
    'ap-northeast-1':'ap-northeast-1.amazonaws.com',
    'ap-southeast-1':'ap-southeast-1.amazonaws.com',
    'eu-west-1':'eu-west-1.amazonaws.com',
    'sa-east-1':'sa-east-1.amazonaws.com',
    'us-east-1':'s3.amazonaws.com', # US Standard
    'us-west-1':'us-west-1.amazonaws.com',
    'us-west-2':'us-west-2.amazonaws.com'
    }

def get_config(args):
    verbose = False
    quick = False
    if '-v' in args:
        args.remove('-v')
        verbose = True
    if '-q' in args:
        args.remove('-q')
        quick = True
    if(len(args) != 2):
        return None
    local_dir = unicode(args[1])
    if not os.path.isdir(local_dir):
        raise Exception("Not a directory: %s" % local_dir)
    return Config(local_dir, verbose, quick)

class Config:
    def __init__(self, local_dir, verbose, quick):
        self.local_dir = local_dir
        self.verbose = verbose
        self.quick = quick
        parser = ConfigParser.SafeConfigParser()
        config_file_name = os.path.join(local_dir, DOT_S3SITESYNC)
        with open(config_file_name) as f:
            config_file_contents = unicode("[s3sitesync]\n" + f.read())
        parser.readfp(io.StringIO(config_file_contents), config_file_name)
        self.keyid = parser.get('s3sitesync', 'awsAccessKeyId')
        self.key = parser.get('s3sitesync', 'awsSecretAccessKey')
        self.bucket_name = parser.get('s3sitesync', 'bucketName')
        self.region = parser.get('s3sitesync', 'awsRegion')
        if not self.region in API_ENDPOINTS:
            raise Exception("Invalid region '%s'" % self.region)
        self.api_endpoint = API_ENDPOINTS[self.region]
        self.index_doc = parser.get('s3sitesync', 'indexDocument')
        self.error_doc = parser.get('s3sitesync', 'errorDocument')
        ignore_file_name = os.path.join(local_dir, DOT_S3IGNORE)
        self.ignore_patterns = []
        if os.path.isfile(ignore_file_name):
            with open(ignore_file_name) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        pattern = os.path.join(local_dir, line)
                        self.ignore_patterns.append(pattern)
        self.ignore_patterns.append(os.path.join(local_dir, DOT_S3SITESYNC))
        self.ignore_patterns.append(os.path.join(local_dir, DOT_S3IGNORE))
        mimetypes.init()
        mimetypes.init([os.path.join(local_dir, DOT_S3MIMETYPES)])
    
    def __str__(self):
        return "Config{local_dir=%r,verbose=%r,quick=%r,keyid=%s,key=***,bucket=%s,region=%s,api_endpoint=%s,index_doc=%s,error_doc=%s,ignore_patterns=%r}" % (
            self.local_dir, self.verbose, self.quick, self.keyid, \
                self.bucket_name, self.region, self.api_endpoint, \
                self.index_doc, self.error_doc, self.ignore_patterns)

def list_remote_files(bucket, config):
    sys.stdout.write("Listing bucket %s" % bucket.name)
    if config.quick:
        print()
        remote_files = {}
        for key in bucket.list():
            remote_file = RemoteFileQuick(key)
            if config.verbose:
                print(remote_file)
            remote_files[key.name] = remote_file
        return remote_files
    else:
        if config.verbose:
            print()
        key_names = [key.name for key in bucket.list()]
        def get_remote_file(key_name):
            key = bucket.get_key(key_name)
            remote_file = RemoteFile(key)
            if config.verbose:
                parallel.t_print(remote_file)
            else:
                parallel.t_write(".")
            return remote_file
        remote_files_list = parallel.process(get_remote_file, key_names)
        print()
        return dict([(f.name,f) for f in remote_files_list])

def is_public_read_policy(policy):
    has_owner_full_control = False
    has_all_users_read = False
    for g in policy.acl.grants:
        if g.id == policy.owner.id and g.permission == 'FULL_CONTROL':
            has_owner_full_control = True
        elif g.type == 'Group' and \
                g.uri == 'http://acs.amazonaws.com/groups/global/AllUsers' and \
                g.permission == 'READ':
            has_all_users_read = True
        else:
            return False
    return has_owner_full_control and has_all_users_read

class RemoteFile:
    def __init__(self, key):
        self.name = key.name
        # Expects key returned by bucket.get_key()
        self.content_type = key.content_type
        if self.content_type == 'application/octet-stream':
            self.content_type = None
        self.content_encoding = key.content_encoding
        self.md5 = key.etag.strip('"')
        self.policy = key.get_acl() # network call
        if is_public_read_policy(self.policy):
            self.policy = 'public-read'
        self.size = key.size
        self.timestamp = -1
    
    def __str__(self):
        return "RemoteFile{%r,md5=%s,size=%s,type=%s,enc=%s,policy=%s}" % \
            (self.name, self.md5, self.size, self.content_type, \
                 self.content_encoding, self.policy)

class RemoteFileQuick:
    def __init__(self, key):
        self.name = key.name
        self.size = key.size
        self.content_type = None
        self.content_encoding = None
        self.md5 = None
        self.policy = None
        mtime = re.sub(r'^(.*)\.[0-9]{3}Z$',r'\1',key.last_modified)
        time_tuple = time.strptime(mtime, "%Y-%m-%dT%H:%M:%S")
        self.timestamp = calendar.timegm(time_tuple)
    
    def __str__(self):
        return "RemoteFile{%r,size=%s,timestamp=%d}" % \
            (self.name, self.size, self.timestamp)

def fn_multi_match(filename, patterns):
    for pattern in patterns:
        if fnmatch.fnmatch(filename, pattern):
            return True
    return False

def list_local_files(config):
    sys.stdout.write("Listing directory '%s'" % config.local_dir)
    if config.verbose:
        print()
    local_files = {}
    dirs = [('',config.local_dir)]
    while dirs:
        (dir_name, dir_path) = dirs.pop()
        for entry in os.listdir(dir_path):
            path = os.path.join(dir_path, entry)
            if fn_multi_match(path, config.ignore_patterns):
                if config.verbose:
                    print("Ignoring file %r" % path)
                continue
            name = dir_name + entry
            if os.path.isdir(path):
                dirs.append((name + "/", path))
            else:
                if config.quick:
                    local_file = LocalFileQuick(name, path)
                else:
                    local_file = LocalFile(name, path)
                if config.verbose:
                    print(local_file)
                else:
                    sys.stdout.write(".")
                    sys.stdout.flush()
                local_files[name] = local_file
    print()
    return local_files

def get_file_md5(path):
    m = hashlib.md5()
    with open(path,"rb") as f:
        while True:
            block = f.read(1024*1024)
            if not block:
                break
            m.update(block)
    return  m.hexdigest()

class LocalFile:
    def __init__(self, name, path):
        self.name = name
        self.path = path
        (self.content_type, self.content_encoding) = mimetypes.guess_type(path)
        if self.content_type == 'application/octet-stream':
            self.content_type = None
        self.md5 = get_file_md5(path)
        self.policy = 'public-read'
        self.size = os.stat(path).st_size
        self.timestamp = -1
    
    def __str__(self):
        return "LocalFile{%r,md5=%s,size=%s,type=%s,enc=%s}" % \
            (self.name, self.md5, self.size, self.content_type, \
                 self.content_encoding)

class LocalFileQuick:
    def __init__(self, name, path):
        self.name = name
        self.path = path
        self.content_encoding = None
        self.content_type = None
        self.md5 = None
        self.policy = None
        self.size = os.stat(path).st_size
        self.timestamp = os.stat(path).st_mtime
    
    def __str__(self):
        return "LocalFile{%r,size=%s,timestamp=%d}" % \
            (self.name, self.size, self.timestamp)

def are_files_same(local, remote):
    assert(local.name == remote.name)
    return True \
        and local.content_encoding == remote.content_encoding \
        and local.content_type == remote.content_type \
        and local.md5 == remote.md5 \
        and local.policy == remote.policy \
        and local.size == remote.size \
        and local.timestamp <= remote.timestamp

def upload_files(bucket, local_files, verbose):
    if verbose:
        print()
    def upload_file(local_file):
        key = bucket.new_key(local_file.name)
        filename = local_file.path
        headers = {}
        if local_file.content_type:
            headers['Content-Type'] = local_file.content_type
        if local_file.content_encoding:
            headers['Content-Encoding'] = local_file.content_encoding
        if local_file.md5:
            hex_md5 = local_file.md5
            b64_md5 = hex_md5.decode('hex').encode('base64').strip()
            md5 = (hex_md5, b64_md5)
        else:
            md5 = None
        policy = local_file.policy
        if verbose:
            parallel.t_print("Uploading %r %r" % (local_file.name, headers))
        key.set_contents_from_filename(filename,headers,md5=md5,policy=policy)
        if not verbose:
            parallel.t_write(".")
        return None
    parallel.process(upload_file, local_files)
    print()

def main(args):
    config = get_config(args)
    if not config:
        sys.stderr.write(__doc__)
        return 1
    if config.verbose:
        print(config)
    s3connection = boto.s3.connection.S3Connection(
        config.keyid, config.key, is_secure=True, host=config.api_endpoint)
    bucket = s3connection.get_bucket(config.bucket_name)
    remote_files = list_remote_files(bucket, config)
    local_files = list_local_files(config)
    
    new_files_names = local_files.viewkeys() - remote_files.viewkeys()
    new_files = [local_files[name] for name in new_files_names]
    if new_files:
        sys.stdout.write("Uploading %s new files" % len(new_files))
        upload_files(bucket, new_files, config.verbose)
    else:
        print("No new files")
    
    existing_files_names = local_files.viewkeys() & remote_files.viewkeys()
    changed_files_names = [name for name in existing_files_names if not 
                           are_files_same(local_files[name],remote_files[name])]
    changed_files = [local_files[name] for name in changed_files_names]
    if changed_files:
        sys.stdout.write("Uploading %s changed files" % len(changed_files))
        upload_files(bucket, changed_files, config.verbose)
    else:
        print("No changed files")
    
    deleted_files_names = remote_files.viewkeys() - local_files.viewkeys()
    always_delete = WARNING_KEY_NAME in remote_files
    deleted_files_names.discard(WARNING_KEY_NAME)
    if deleted_files_names:
        print("Deleted files:")
        for name in deleted_files_names:
            print(" %r" % name)
        if always_delete:
            print("Deleting")
            time.sleep(2.0)
            bucket.delete_keys(deleted_files_names)
        else:
            print("Delete these files from the bucket? y/N/a")
            response = sys.stdin.readline().strip().lower()
            if response == "y" or response == "a":
                print("Deleting")
                bucket.delete_keys(deleted_files_names)
            if response == "a":
                key = bucket.new_key(WARNING_KEY_NAME)
                print("Adding warning object to bucket: %r" % WARNING_KEY_NAME)
                key.set_contents_from_string("1")
    else:
        print("No deleted files")
    if not config.quick and config.index_doc:
        print("Configuring bucket website index_doc=%r error_doc=%r" %
              (config.index_doc, config.error_doc))
        bucket.configure_website(config.index_doc, config.error_doc)
    print("Done")
    return 0

if __name__ == '__main__':
    exit_status = main(sys.argv)
    sys.exit(int(exit_status))
