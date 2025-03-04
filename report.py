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
import zlib

VERBOSE = False
CONFIG_PATH = pathlib.Path('project.yaml')
OUT_DIR = pathlib.Path('out')
RESOURCES_DIR = pathlib.Path('res')
#TEMPLATES_DIR = pathlib.Path('templates')
SRC_DIR = pathlib.Path('src')

# replace some UTF-8 sequences with plain LaTeX.
UTF8_REPLACEMENTS = {
  'Ä': r'{\\"A}',
  'ä': r'{\\"a}',
  'Ö': r'{\\"O}',
  'ö': r'{\\"o}',
  'Ü': r'{\\"U}',
  'ü': r'{\\"u}',
  'ß': r'{\\ss}',
  ' ': '~', # non-breaking space
  '…': r'\\ldots',
  '–': '--', # en dash
  '—': '---', # em dash
  '„': '``', # german starting quotation mark
  '“': "''", # german ending quotation mark
}

def log(msg):
  if VERBOSE:
    print(msg)

def read_file(path):
  if not path.exists():
    return None

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

  if 'id' not in issue:
    sys.exit(f"issue ID not specified: '{issue_file}'")

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

  if not ('title' in issue and 'description' in issue and 'evidence' in issue and 'affected assets' in issue and 'severity' in issue):
    sys.exit(f"required information (e.g. title, description, evidence, affected assets, severity) not provided: '{issue_file}'")

  log(json.dumps(issue, indent=2))
  log(f"{issue['title']}")

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
  if content is None:
    return ""

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

def compile_document(input_file, output_directory):
  subprocess.run(
    [
      'pdflatex',
      '-interaction=batchmode',
      '-jobname=report',
      f'-output-directory={output_directory}',
      input_file
    ],
    check = True,
    capture_output = True
  )

  # return the Adler-32 checksum of the 'report.aux' file.
  # when the checksum stays constant (from one run to the next) no additional compilation is needed.
  with open(pathlib.Path(output_directory, 'report.aux')) as f:
    return zlib.adler32(f.read().encode())

def render_document():
  project = yaml.safe_load(open(CONFIG_PATH))
  log(f"\nconfig ({CONFIG_PATH}):\n")
  log(json.dumps(project, indent=2))

  issue_templates_dir = pathlib.Path(RESOURCES_DIR, 'issues', project["report"]["language"])

  print(f"loading issue templates from '{issue_templates_dir}' ...")
  issue_templates = load_issue_templates(issue_templates_dir)

  log(f"\nissue templates:\n")
  for key, issue_template in issue_templates.items():
    log(json.dumps(issue_template, indent=2))

  issues_dir = pathlib.Path(SRC_DIR, 'issues')

  print(f"loading issues from '{issues_dir}' ...")
  issues = load_issues(issues_dir, issue_templates)

  groups = []
  for key, items in itertools.groupby(issues, lambda issue: issue['group']):
    if key not in groups:
      groups.append(key)

  log("\ngroups:\n")
  log(json.dumps(groups, indent=2))

  env = jinja2.Environment(
    loader = jinja2.FileSystemLoader(searchpath=pathlib.Path(RESOURCES_DIR, 'tex')),
    block_start_string = r'\BLOCK{', block_end_string = '}',
    variable_start_string = r'\VAR{', variable_end_string = '}',
    comment_start_string = r'\#{', comment_end_string = '}',
    line_statement_prefix = '%%',
    line_comment_prefix = '%#',
    trim_blocks = True,
    autoescape = False
  )

  # register custom filter
  env.filters['markdown2latex'] = markdown2latex

  template_file = f'{project["report"]["language"]}.tex'
  template = env.get_template(template_file)

  print(f"rendering '{template_file}' ...")
  rendered_document = template.render(
    project = project,
    summary = read_file(pathlib.Path(SRC_DIR, 'summary.md')),
    limitations = read_file(pathlib.Path(SRC_DIR, 'limitations.md')),
    tools = read_file(pathlib.Path(SRC_DIR, f'tools-{project["report"]["language"]}.md')),
    test_procedure = read_file(pathlib.Path(SRC_DIR, 'test_procedure.md')),
    issues = issues,
    groups = groups
  )

  log(rendered_document)

  return rendered_document

def process(args):
  global VERBOSE
  VERBOSE = args.verbose

  report_file = pathlib.Path(OUT_DIR, 'report.tex')

  # only overwrite existing LaTeX report document if the user wishes so
  if not report_file.exists() or args.overwrite:
    print(f"clearing '{OUT_DIR}' ...")
    for artifact in OUT_DIR.iterdir():
      artifact.unlink()

    rendered_document = render_document()

    print("fixing Markdown/LaTeX quirks ...")

    # instruct LaTeX to display the figure right where it is defined (i.e. `[h]`)
    rendered_document = re.sub(
      r'begin{figure}$',
      r'begin{figure}[h]',
      rendered_document,
      flags = re.MULTILINE
    )

    # scale graphics to the width of the text
    rendered_document = re.sub(
      r'includegraphics{',
      r'includegraphics[width=\\textwidth]{',
      rendered_document,
      flags = re.MULTILINE
    )

    print("replacing UTF-8 sequences (e.g. umlaut, esszet, etc) with plain LaTeX ...")
    for search_string, replacement in UTF8_REPLACEMENTS.items():
      rendered_document = re.sub(
        search_string,
        replacement,
        rendered_document,
        flags = re.MULTILINE
      )

    report_file.touch(exist_ok=True)

    print(f"writing '{report_file}' ...")
    with open(report_file, 'w') as f:
      f.write(rendered_document)

  print(f"compiling '{report_file}' ...")

  try:
    run = 1
    checksum = None

    # when the checksum stays constant (from one run to the next) no additional compilation is needed.
    while True:
      print(f"run #{run} ...")
      cs = compile_document(report_file, OUT_DIR)
      if cs == checksum:
        break

      checksum = cs
      run += 1
  except subprocess.CalledProcessError as e:
    sys.exit(f"error compiling LaTeX document: please check '{pathlib.Path(OUT_DIR, 'report.log')}'.")

  pdf_report = pathlib.Path(OUT_DIR, 'report.pdf')
  print(f"report created at '{pdf_report}'")

  return

def main():
  parser = argparse.ArgumentParser()
  
  parser.add_argument(
    '-o', '--overwrite',
    help="overwrite the LaTeX document. WARNING: providing this flag causes the output directory ('out/') to be cleared",
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
