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

def parse_severity(content):
  match = re.search(r'(?P<number>\d(\.\d+))\s+(\((?P<class>[^)]+)\))?\s+(((?P<cvss>CVSS:[^/]+(/\w+:.)+))|((?P<dread>D:./R:./E:./A:./D:.)))?\s*', content, flags=re.MULTILINE)

  if match:
    return {
      'number': match.group('number'),
      'class': match.group('class'),
      'cvss': match.group('cvss'),
      'dread': match.group('dread')
    }

def parse_images(image_strings):
  images = []
  
  for image in image_strings:
    match = re.search(r'!\[(?P<caption>[^\]]+)\]\((?P<file>[^\)]+)\)', image)
    
    if not match:
      continue
      
    images.append(
      {
        'caption': match.group('caption'),
        'file': match.group('file')
      }
    )

  return images
  
def parse_unordered_list(content):
  array = []

  for item in content.split('\n'):
    if item.strip():
      array.append(
        re.sub(
          r'^(\*|-)\s+(.+?)\s*$',
          r'\2',
          item,
        )
      )

  return array

def parse_content(content, section_level):
  sections = {}

  patterns = {
    1: r'^# ',
    2: r'^## '
  }
  
  for section in re.split(patterns[section_level], content, flags=re.MULTILINE):
    if not section:
      continue

    match = re.search(r'^(?P<name>.+?)$\s+(?P<content>.+)\s+', section, flags=re.MULTILINE|re.DOTALL)
    if match:
      section_name = match.group('name')
      section_content = match.group('content')

      sections[section_name] = section_content

      if section_level == 1:
        if section_name == 'id':
          sections[section_name] = parse_unordered_list(section_content)

        if section_name == 'evidence':
          sections[section_name] = parse_content(section_content, 2)
          
        if section_name == 'severity':
          sections[section_name] = parse_severity(section_content)

        if section_name == 'images':
          sections[section_name] = parse_images(parse_unordered_list(section_content))
      
  return sections

def load_file(path):
  with open(path) as f:
    content = f.read()

  return parse_content(content, 1)
  
def load_issue(issue_file, group, vulnerabilities):
  #issue = yaml.safe_load(open(issue_file))
  issue = load_file(issue_file)
  
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

  # replace '!REF:<type>:<ID>!' with '!REF:<type>:<issue label>-<ID>!'
  for id, evidence in issue['evidence'].items():
    issue['evidence'][id] = re.sub(
      r'!REF:([^:]+):([^!]+)!',
      f"!REF:\\1:{issue['label']}-\\2!",
      evidence
    )

  # parse CVSS vector
  if issue['severity']['cvss']:
    metrics = []
    for metric in issue['severity']['cvss'].split('/'):
      metrics.append(metric.split(':')[1])
    issue['severity']['cvss'] = metrics

  # parse DREAD vector
  if issue['severity']['dread']:
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

  for issue_file in path.glob('*.md'):
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
      
      if path.suffix == '.md':
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
  return re.sub(
    r'!REF:([^:]+):([^!]+)!',
    r'\\ref{\1:\2}',
    latex
  )

def load_vulnerabilities(path):
  vulnerabilities = {}

  for vulnerability_file in path.glob('**/*.md'):
    vulnerability = load_file(vulnerability_file)
    vulnerabilities[tuple(vulnerability['id'])] = vulnerability

  return vulnerabilities

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
