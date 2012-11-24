from distutils.core import setup
import os
import os.path
import py2exe
import sys

def whole_directory(dirname):
    return (dirname, [os.path.join(dirname, f) for f in os.listdir(dirname)])

if __name__ == '__main__':
    # If run without args, build executables
    if len(sys.argv) == 1:
        sys.argv.append("py2exe")
        #sys.argv.append("-q")

setup(
    console = [
        {
            'script': "s3sitesync.py",
            'name': "s3sitesync",
            }
        ],
    options = {
        "py2exe": {
            # http://stackoverflow.com/questions/1979486/py2exe-win32api-pyc-importerror-dll-load-failed
            "dll_excludes": [
                #"mswsock.dll",
                #"powrprof.dll"
                ],
            "includes": [
                #'email',
                #'email.encoders',
                #'email.MIMEBase',
                #'email.MIMEMultipart',
                #'email.MIMEText',
                #'email.Utils'
                ]
            }
        },
    data_files = [
        whole_directory("Microsoft.VC90.CRT"),
        whole_directory("Microsoft.VC90.MFC"),
        ("", [
                "LICENSE.txt",
                "README.md"
                ]
         ),
        ]
    )
