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
ISSUES_DIR = pathlib.Path('report', 'issues')

def log(msg):
  if VERBOSE:
    print(msg)

def read_file(path):
  with open(path) as f:
    content = f.read()
  return content.strip()

def parse_severity_vector(vector_string):
  '''
  parse severity vector (e.g. CVSS, DREAD):

    CVSS:3.1/AV:x/...

  return:

    [ 3.1, x, ... ]
  '''

  if vector_string is None:
    return

  metrics = []
  for metric in vector_string.split('/'):
    metrics.append(metric.split(':')[1])

  return metrics

def parse_severity(content):
  '''
  parse the severity section:

    <number> (<class>)?
    (<CVSS>|<DREAD>)?

  return:

    {
      "number": "x.y",
      "class": "(none|low|medium|...)",
      "cvss": [3.1, x, ...],
      "dread": [x, y, z, ...]
    }
  '''
  
  match = re.search(r'(?P<number>\d+(\.\d+)?)\s*(\((?P<class>[^)]+)\))?\s*(((?P<cvss>CVSS:[^/]+(/\w+:.)+))|((?P<dread>D:./R:./E:./A:./D:.)))?\s*', content, flags=re.MULTILINE)

  if match:
    return {
      'number': match.group('number'),
      'class': match.group('class'),
      'cvss': parse_severity_vector(match.group('cvss')),
      'dread': parse_severity_vector(match.group('dread'))
    }

def parse_images(image_strings):
  '''
  parse an array of Markdown image includes:

    [
      "![Image Caption.](image.png)",
      "![Another Caption.](another_image.png)"
    ]

  return:

    [
      {
        "caption": "Image Caption.",
        "file": "image.png"
      },
      {
        "caption": "Another Caption.",
        "file": "another_image.png"
      }
    ]
  '''
  
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
  '''
  parse the content as an unordered list:

    * list item one
    - list item two

  return:

    [
      "list item one",
      "list item two"
    ]
  '''
  
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
  '''
  parse the issue (template) document:

    # section one

    section content

    # section two

    more content

  return:

    {
      "section one": "section content",
      "section two": "more content"
    }
  '''
  
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

      sections[section_name] = section_content.strip()

      if section_level == 1:
        if section_name == 'id':
          sections[section_name] = parse_unordered_list(section_content)

        if section_name == 'evidence':
          sections[section_name] = parse_content(section_content, 2)
          
        if section_name == 'severity':
          sections[section_name] = parse_severity(section_content)

        # images are included in a separate section (i.e. `# images`) at the end of the issue document.
        # make sure to include the images in an unordered list (e.g. `* ![caption](image.png)`)
        if section_name == 'images':
          sections[section_name] = parse_images(parse_unordered_list(section_content))
      
  return sections

def load_file(path):
  with open(path) as f:
    content = f.read()

  return parse_content(content, 1)
  
def load_issue(issue_file, group, issue_templates):
  issue = load_file(issue_file)
  
  log(f"\nissue ({issue_file}):\n")
  log(json.dumps(issue, indent=2))

  issue['id'] = tuple(issue['id'])
  issue['class'] = issue['id'][0]
  issue['group'] = group

  # fill in 'description', 'recommendations', 'references' from issue templates
  if issue['id'] in issue_templates:
    issue_template = issue_templates[issue['id']]
    for key, value in issue_template.items():
      if key not in issue:
        issue[key] = issue_template[key]

  if group['name']:
    issue['title'] = f"[{group['name']}] {issue['title']}"

  # the issue's label, used for referencing in LaTeX (`\lable{the_lable}`).
  # use the file's name, replace all non-word characters with an underscore.
  issue['label'] = re.sub(
    r'[^\w:.-]',
    '_',
    f"{group['order']}:{group['name']}:{issue_file.name}" if group['name'] else issue_file.name
  )

  print(f"{issue['title']}")

  log(json.dumps(issue, indent=2))

  return issue

def load_issue_group(path, group, issue_templates):
  issues = []

  for issue_file in path.glob('*.md'):
    issues.append(load_issue(issue_file, group, issue_templates))

  return issues
  
def load_issues(path, issue_templates):
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
        'graphics_path': str(path.relative_to('.')) + '/'
      }

      issues += load_issue_group(path, group, issue_templates)
    else: # add issues to the default group
      group = {
        'order': '0',
        'name': None,
        'graphics_path': str(path.parent.relative_to('.')) + '/'
      }
      
      if path.suffix == '.md':
        issues.append(load_issue(path, group, issue_templates))
  
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

  # replace '!REF:<ID>!' with '\ref{<ID>}'
  return re.sub(
    r'!REF:([^!]+)!',
    r'\\ref{\1}',
    latex
  )

def load_issue_templates(path):
  issue_templates = {}

  for issue_template_file in path.glob('**/*.md'):
    issue_template = load_file(issue_template_file)
    issue_templates[tuple(issue_template['id'])] = issue_template

  return issue_templates

def process(args):
  global VERBOSE
  VERBOSE = args.verbose

  project = yaml.safe_load(open(CONFIG_PATH))
  log(f"\nconfig ({CONFIG_PATH}):\n")
  log(json.dumps(project, indent=2))

  issue_templates_dir = pathlib.Path(TEMPLATES_DIR, 'issues')

  print(f"loading issue templates from '{issue_templates_dir}' ...")
  issue_templates = load_issue_templates(issue_templates_dir)
  
  log(f"\nissue templates:\n")
  for key, issue_template in issue_templates.items():
    log(json.dumps(issue_template, indent=2))

  print(f"loading issues from '{ISSUES_DIR}' ...")
  issues = load_issues(ISSUES_DIR, issue_templates)

  groups = []
  for key, items in itertools.groupby(issues, lambda issue: issue['group']):
    if key not in groups:
      groups.append(key)
    
  log("\ngroups:\n")
  log(json.dumps(groups, indent=2))

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
    summary = read_file(pathlib.Path(REPORT_DIR, 'summary.md')),
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

  for i in range(1,3):
    print(f"run #{i} ...")

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
    
  pdf_report = pathlib.Path(RESULTS_DIR, 'report.pdf')
  print(f"report created at '{pdf_report}'")
  
  return

def main():
  parser = argparse.ArgumentParser()
  
  parser.add_argument(
    '-o', '--overwrite',
    help='overwrite the LaTeX document',
    action='store_true',
    default=False
  )

  parser.add_argument(
    '-v', '--verbose',
    help='be very verbose',
    action='store_true'
  )
  
  process(parser.parse_args())
  
if __name__ == '__main__':
  main()
