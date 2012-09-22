S3 Site Sync
====================================================

S3 Site Sync is a tool upload a website to S3 and keep it
synchronized with a directory on your computer.

Requires:

1. Python 2.7
1. Boto 2.3.0 https://github.com/boto/boto

Usage:

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
    Done
