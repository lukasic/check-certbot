#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 
# Nagios/Icinga Plugin to check expiring/expired certbot certificates
# https://github.com/lukasic/check-certbot
#
# Version: 0.2
#

#
# Copyright (c) 2023 Lukáš Kasič <src@lksc.sk>
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

import argparse
import datetime
import os
import subprocess
import sys
import yaml

def get_certificates_info(certbot_path):
  out = subprocess.check_output("%s certificates 2>&1" % certbot_path, shell=True).decode()
  sep = "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
  return out.split(sep)[1]

def certbot_output_to_json(co):
  # 🐷 oink oink ... 
  lines = co.split("\n")
  yamlstr = []

  for line in lines:
    line = line.rstrip()
    if not line: continue
    try:
      key, val = line.split(": ", 1)
      line = '%s: "%s"' % (key, val)
    except ValueError:
      if line[-1] != ":":
          print("Certbot certificates output error.")
          sys.exit(3)

    yamlstr.append(line)

  yamlstr = '\n'.join(yamlstr)
  yamlstr = yamlstr.replace("Certificate Name:", "- Certificate Name:")

  y = yaml.safe_load(yamlstr)
  return y['Found the following certs']

def valid_days(s):
  d = s[:19]
  fmt = "%Y-%m-%d %H:%M:%S"
  dt = datetime.datetime.strptime(d, fmt)
  now = datetime.datetime.now()
  return (dt-now).days

parser = argparse.ArgumentParser(description="check certbot certificate expirations")
parser.add_argument('-c', '--critical', help="critical days", default=3)
parser.add_argument('-w', '--warning', help="warning days", default=7)
args = parser.parse_args()

cd = int(args.critical)
wd = int(args.warning)

if wd < cd:
  print("Warning value is less than Critical!")
  sys.exit(3)

warn = False
crit = False

certbot_search = [
  "/usr/bin/certbot",
  "/snap/bin/certbot",
  "/usr/local/bin/certbot-auto"
]

certbot_path = None

for i in certbot_search:
  if os.path.isfile(i):
    certbot_path = i
    break

if not certbot_path:
  print("Certbot not found.")
  sys.exit(3)

data = get_certificates_info(certbot_path)
c = certbot_output_to_json(data)

perfdata = {
  'Expired': 0,
  'InWarning': 0,
  'InCritical': 0,
  'OK': 0,
  'ALL': 0,
  'MinValidDays': 1000,
}

for cert in c:
  name = cert["Certificate Name"]
  v = valid_days(cert["Expiry Date"])
  perfdata['ALL'] += 1
  if v < perfdata['MinValidDays']:
    perfdata['MinValidDays'] = v
  if v < 0:
    print("CRITICAL: %s - expired" % name)
    perfdata['Expired'] += 1
    crit = True
  elif v < cd:
    print("CRITICAL: %s - expires in %d days" % (name, v))
    perfdata['InCritical'] += 1
    crit = True
  elif v < wd:
    print("WARNING: %s - expires in %d days" % (name, v))
    perfdata['InWarning'] += 1
    warn = True
  else:
    perfdata['OK'] += 1

if crit:
  retcode = 2
elif warn:
  retcode = 1
else:
  print("No certificate expired nor expiring soon.")
  retcode = 0

perfdata_format = "| Expired=%d;;;; InWarning=%d;;;; InCritical=%d;;;; OK=%d;;;; ALL=%d;;;; MinValidDays=%d;%d;%d;;" % (
    perfdata['Expired'],
    perfdata['InWarning'],
    perfdata['InCritical'],
    perfdata['OK'],
    perfdata['ALL'],
    perfdata['MinValidDays'],
    wd,
    cd
  )
print(perfdata_format)

sys.exit(retcode)
