#!/usr/bin/env python3

import argparse
import itertools
import jinja2
import json
import pathlib
import re
import subprocess
import sys
import yaml

VERBOSE = False
CONFIG_PATH = pathlib.Path('project.yaml')
RESULTS_DIR = pathlib.Path('results')
TEMPLATES_DIR = pathlib.Path('templates')
REPORT_DIR = pathlib.Path('report')
VULNERABILITIES_DIR = pathlib.Path('report', 'vulnerabilities')
ISSUES_DIR = pathlib.Path('report', 'issues')

def log(msg):
  if VERBOSE:
    print(msg)

def read_file(path):
  with open(path) as f:
    content = f.read()
  return content.strip()

def parse_vulnerability(path):
  vulnerability = {}

  patterns = {
    'title': re.compile(r'^# (?P<title>.+)\s*'),
    'description': re.compile(r'^## description\s+(?P<description>.+?)\s+^## ', re.MULTILINE | re.DOTALL),
    'recommendations': re.compile(r'^## recommendations\s+(?P<recommendations>.+?)\s+^## ', re.MULTILINE | re.DOTALL),
    'references': re.compile(r'^## references\s+(?P<references>.+?)\s+^## ', re.MULTILINE | re.DOTALL),
    'id': re.compile(r'^## id\s+(?P<id>.+)\s*', re.MULTILINE)
  }

  with open(path) as f:
    content = f.read()

  for key, pattern in patterns.items():
    m = pattern.search(content)
    if m:
      vulnerability[key] = m.group(key).strip()
    else:
      vulnerability[key] = ''

  vulnerability['id'] = tuple(vulnerability['id'].split(';'))
        
  return vulnerability

def load_vulnerabilities(path):
  vulnerabilities = {}

  for vulnerability_file in path.glob('**/*.md'):
    vulnerability = parse_vulnerability(vulnerability_file)
    vulnerabilities[vulnerability['id']] = vulnerability

  return vulnerabilities

def load_issue(issue_file, group, vulnerabilities):
  issue = yaml.safe_load(open(issue_file))
  log(f"\nissue ({issue_file}):\n")
  log(json.dumps(issue, indent=2))

  issue['id'] = tuple(issue['id'])
  issue['class'] = issue['id'][0]
  issue['group'] = group

  if group['name']:
    issue['title'] = f"[{group['name']}] {issue['title']}"

  # the issue's label, used for referencing in LaTeX (`\lable{the_lable}`).
  # use the file's name (excl the extension), replace all non-word characters with an underscore.
  issue['label'] = re.sub(
    r'[^\w-]',
    '_',
    f"{group['order']}-{group['name']}-{issue_file.stem}"
  )

  # replace '!REF:IMG:<ID>!' with '!REF:IMG:<issue label>-<ID>!'
  for evidence in issue['evidence']:
    description = re.sub(
      r'!REF:IMG:([^!]+)!',
      f"!REF:IMG:{issue['label']}-\\1!",
      evidence['description']
    )
    evidence['description'] = description

  # parse CVSS vector
  if 'cvss' in issue['severity']:
    metrics = []
    for metric in issue['severity']['cvss'].split('/'):
      metrics.append(metric.split(':')[1])
    issue['severity']['cvss'] = metrics

  # parse DREAD vector
  if 'dread' in issue['severity']:
    metrics = []
    for metric in issue['severity']['dread'].split('/'):
      metrics.append(metric.split(':')[1])
    issue['severity']['dread'] = metrics
  
  # fill in 'description', 'recommendations', 'references' from vulnerability library
  if issue['id'] in vulnerabilities:
    vulnerability = vulnerabilities[issue['id']]
    for key, value in vulnerability.items():
      if key not in issue:
        issue[key] = vulnerability[key]

  log(json.dumps(issue, indent=2))

  return issue

def load_issue_group(path, group, vulnerabilities):
  issues = []

  for issue_file in path.glob('*.yaml'):
    issues.append(load_issue(issue_file, group, vulnerabilities))

  return issues
  
def load_issues(path, vulnerabilities):
  issues = []

  # each directory within the 'issues' directory is an issue group.
  # iterate over the children of the 'issues' directory:
  # * is it a directory? iterate over the directory ('<group order> - <group name>').
  # * is it a yaml file? add the issue to the default group

  for path in path.iterdir():
    if path.is_dir():
      group_order, group_name = path.name.split(' - ')
      group = {
        'order': group_order,
        'name': group_name,
        'graphics_path': str(path.relative_to('.'))
      }

      issues += load_issue_group(path, group, vulnerabilities)
    else: # add issues to the default group
      group = {
        'order': '0',
        'name': None,
        'graphics_path': str(path.parent.relative_to('.'))
      }
      
      if path.suffix == '.yaml':
        issues.append(load_issue(path, group, vulnerabilities))
  
  return issues

def markdown2latex(content):
  process = subprocess.run(
    [
      'pandoc',
      '--from', 'markdown',
      '--to', 'latex',
      '--listings', # nicer code listings
      '--wrap=preserve',
      '--output', '-'
    ],
    input = content,
    text = True,
    check = True,
    stdout = subprocess.PIPE
  )

  latex = process.stdout

  # replace '!REF:<type>:<ID>!' with '\ref{<type>:<ID>}'
  updated_latex = re.sub(
    r'!REF:([^:]+):([^!]+)!',
    r'\\ref{\1:\2}',
    latex
  )

  return updated_latex

def process(args):
  global VERBOSE
  VERBOSE = args.verbose

  project = yaml.safe_load(open(CONFIG_PATH))
  log(f"\nconfig ({CONFIG_PATH}):\n")
  log(json.dumps(project, indent=2))

  print(f"loading vulnerabilities from '{VULNERABILITIES_DIR}' ...")
  vulnerabilities = load_vulnerabilities(VULNERABILITIES_DIR)
  
  log(f"\nvulnerabilities:\n")
  for key, vulnerability in vulnerabilities.items():
    log(json.dumps(vulnerability, indent=2))

  print(f"loading issues from '{ISSUES_DIR}' ...")
  issues = load_issues(ISSUES_DIR, vulnerabilities)

  groups = []
  for key, items in itertools.groupby(issues, lambda issue: issue['group']):
    if key not in groups:
      groups.append(key)
    
  log("\ngroups:\n")
  log(json.dumps(groups, indent=2))

  sorted_issues = sorted(
    issues,
    key = lambda issue: issue['severity']['number']
  )

  severity_range = {
    'min': sorted_issues[0]['severity']['number'],
    'max': sorted_issues[-1]['severity']['number']
  }

  env = jinja2.Environment(
    loader = jinja2.FileSystemLoader(searchpath=TEMPLATES_DIR),
    block_start_string = '\BLOCK{', block_end_string = '}',
    variable_start_string = '\VAR{', variable_end_string = '}',
    comment_start_string = '\#{', comment_end_string = '}',
    line_statement_prefix = '%%',
    line_comment_prefix = '%#',
    trim_blocks = True,
    autoescape = False
  )

  # register custom filter
  env.filters['markdown2latex'] = markdown2latex
  
  template = env.get_template(f'{project["report"]["template"]}.tex')

  report = template.render(
    project = project,
    severity_range = severity_range,
    summary = read_file(pathlib.Path(REPORT_DIR, 'summary.md')),
    required_info = read_file(pathlib.Path(REPORT_DIR, 'required info.md')),
    provided_info = read_file(pathlib.Path(REPORT_DIR, 'provided info.md')),
    limitations = read_file(pathlib.Path(REPORT_DIR, 'limitations.md')),
    tools = read_file(pathlib.Path(REPORT_DIR, 'tools.md')),
    issues = issues,
    groups = groups
  )

  log(report)

  report_file = pathlib.Path(RESULTS_DIR, 'report.tex')

  # only overwrite existing LaTeX report document if the user wishes so
  if not report_file.exists() or args.overwrite:
    report_file.touch(exist_ok=True)
    
    with open(report_file, 'w') as f:
      f.write(report)

  print(f"compiling '{report_file}' ...")
  print("first run ...")

  try:
    subprocess.run(
      [
        'pdflatex',
        '-interaction', 'batchmode',
        '-jobname', 'report',
        '-output-directory', RESULTS_DIR,
        report_file
      ],
      check = True,
      capture_output = True
    )
  except:
    sys.exit(f"error typsetting LaTeX document: please check '{RESULTS_DIR}/report.log'.")
    
  print("second run ...")
  
  try:
    subprocess.run(
      [
        'pdflatex',
        '-interaction', 'errorstopmode',
        '-jobname', 'report',
        '-output-directory', RESULTS_DIR,
        report_file
      ],
      check = True,
      capture_output = True
    )
  except:
    sys.exit(f"error typsetting LaTeX document: please check '{RESULTS_DIR}/report.log'.")

  pdf_report = pathlib.Path(RESULTS_DIR, 'report.pdf')
  print(f"report created at '{pdf_report}'")
  
  return

def main():
  parser = argparse.ArgumentParser()
  
  parser.add_argument('-o', '--overwrite', help='overwrite the LaTeX document', action='store_true', default=False)
  parser.add_argument('-v', '--verbose', help='be very verbose', action='store_true')
  
  process(parser.parse_args())
  
if __name__ == '__main__':
  main()
