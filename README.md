# otx2misp
V1.0: Import new OTX pulse to MISP

# setup
pip3 install git+https://github.com/guangamber/otx2misp.git

# run
otx2misp /path/misp.ini

# issues
1. if you are installing the package on a local misp server, which may have an older version, use the following to force upgrade
pip3 install --no-cache-dir --upgrade pymisp
