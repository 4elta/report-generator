#!/usr/bin/env python3

'''
this script parses a Nessus export (i.e. `.nessus` file) and creates issue files (i.e. Markdown).

please be aware that the issue descriptions from Nessus aren't that good (most of the times).
so the generated issue files should only be used as a basis; you still have to verify each vulnerability, improve the description and add proper evidences/PoC.

please don't be one of those people that solely run Nessus, use its bad issue descriptions verbatim and call their work a pentest.
'''

import argparse
import json
import pathlib
import sys

VERBOSE = False
ISSUES_DIR = pathlib.Path('src', 'issues')

try:
  # https://github.com/tiran/defusedxml
  import defusedxml.ElementTree
except:
  sys.exit("this script requires the 'defusedxml' module.\nplease install it via 'pip3 install defusedxml'.")

def log(msg):
  if VERBOSE:
    print(msg)

def create_issue(issues_directory, vulnerability):
  issue_file = pathlib.Path(issues_directory, f"{vulnerability['id'][1]}.md")
  print(f"\ncreating issue '{issue_file}' ...")
  
  with open(issue_file, 'w') as f:
    f.write('# id\n\n')
    for id in vulnerability['id']:
      f.write(f"* {id}\n")

    f.write('\n# title\n\n')
    f.write(f"{vulnerability['title']}\n")

    f.write('\n# description\n\n')
    f.write(f"{vulnerability['description']}\n")

    f.write('\n# evidence\n')
    for evidence in vulnerability['evidence']:
      f.write(f"\n## {evidence['title']}\n\n")
      f.write(f"{evidence['description']}\n\n")
      if evidence['code']:
        f.write(f"```text\n{evidence['code']}\n```\n\n")
      f.write(f"**Severity: {evidence['severity']}**\n")

    f.write('\n# affected assets\n\n')
    for affected_asset in vulnerability['affected assets']:
      f.write(f'* `{affected_asset}`\n')

    f.write('\n# severity\n\n')
    f.write(f"{vulnerability['severity']['score']}\n")
    if vulnerability['severity']['cvss']:
      f.write(f"{vulnerability['severity']['cvss']}\n")

    f.write(f'\n# recommendations\n\n')
    f.write(f"{vulnerability['recommendations']}\n")

    f.write(f'\n# references\n\n')
    for reference in vulnerability['references']:
      f.write(f'* [{reference}]({reference})\n')

def parse_nessus_file(nessus_file):
  # https://static.tenable.com/documentation/nessus_v2_file_format.pdf

  # a 'vulnerability' is identified by the tuple (pluginFamily, pluginID)
  vulnerabilities = {}

  report = defusedxml.ElementTree.parse(nessus_file).getroot().find('Report')

  for report_host in report.iterfind('ReportHost'):
    host = report_host.get('name')
    log(f"\nhost: {host}")

    for report_item in report_host.iterfind('ReportItem'):
      vulnerability_class = report_item.get('pluginFamily').lower()
      vulnerability_subclass = report_item.get('pluginID')
      vulnerability_id = ( vulnerability_class, vulnerability_subclass )
      log(f"\nvulnerability ID: {vulnerability_id}")
      
      port = report_item.get('port')
      log(f"port: {port}")

      if vulnerability_id not in vulnerabilities:
        title = report_item.get('pluginName')
        log(f"title: {title}")
        
        description = report_item.find('description').text.strip()
        log(f"description: {description}")

        vulnerability = {
          'id': [
            vulnerability_class,
            vulnerability_subclass
          ],
          'title': title,
          'description': description,
          'evidence': [],
          'affected assets': [],
          'severity': {
            'score': 0.0,
            'cvss': None
          },
          'recommendations': None,
          'references': [],
        }

        vulnerabilities[vulnerability_id] = vulnerability

      vulnerability = vulnerabilities[vulnerability_id]

      if host not in vulnerability['affected assets']:
        vulnerability['affected assets'].append(host)

      severity = report_item.findtext('cvss3_base_score')
      if severity is None:
        severity = report_item.findtext('cvss_base_score')

      if severity:
        severity = float(severity)
      else:
        severity = 0.0

      log(f"severity: {severity}")

      cvss = report_item.findtext('cvss3_vector')
      if cvss is None:
        cvss = report_item.findtext('cvss_vector')
        if cvss:
          cvss = cvss.replace('CVSS2#', 'CVSS:2/')

      log(f"CVSS: {cvss}")

      # the highest severity of any evidence makes up the severity of the vulnerability
      if severity > vulnerability['severity']['score']:
        vulnerability['severity']['score'] = severity
        vulnerability['severity']['cvss'] = cvss

      synopsis = report_item.findtext('synopsis')
      if synopsis:
        synopsis = synopsis.strip()
      log(f"synopsis: {synopsis}")

      plugin_output = report_item.findtext('plugin_output')
      if plugin_output:
        plugin_output = plugin_output.strip()
      log(f"plugin output:\n{plugin_output}")

      evidence = {
        'title': f"{host}:{port}",
        'description': synopsis,
        'code': plugin_output,
        'severity': severity,
        'cvss': cvss,
      }

      vulnerability['evidence'].append(evidence)

      recommendations = report_item.findtext('solution')
      if recommendations:
        recommendations = recommendations.replace("Refer to the 'See also' section for guidance.", '').strip()

      if recommendations == 'n/a' or recommendations == '':
        recommendations = None
        
      vulnerability['recommendations'] = recommendations

      references = report_item.findtext('see_also')
      if references:
        for reference in references.split('\n'):
          if reference not in vulnerability['references']:
            vulnerability['references'].append(reference)
      
  return vulnerabilities

def process(args):
  global VERBOSE
  VERBOSE = args.verbose

  global ISSUES_DIR

  # extract vulnerabilities
  print(f"parsing nessus file '{args.input}' ...")
  vulnerabilities = parse_nessus_file(args.input)

  print(f"parsed {len(vulnerabilities)} vulnerabilities")

  if args.group:
    ISSUES_DIR = pathlib.Path(ISSUES_DIR, args.group)

  ISSUES_DIR.mkdir(parents=True, exist_ok=True)

  # create issue files
  for _, vulnerability in vulnerabilities.items():
    log(json.dumps(vulnerability, indent=2))
    create_issue(ISSUES_DIR, vulnerability)
      
  return

def main():
  parser = argparse.ArgumentParser()

  parser.add_argument('input', type=pathlib.Path)
  parser.add_argument('-g', '--group', help="specify the group the imported issues should belong to (e.g. '<order> - <name>')")
  parser.add_argument('-v', '--verbose', help='be very verbose', action='store_true')
  
  process(parser.parse_args())
  
if __name__ == '__main__':
  main()
