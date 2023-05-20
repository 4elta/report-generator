# report generator

Create beautiful pentest reports from Markdown documents.

<a href="results/report.pdf"><img src="results/report.png" width="80%"></a>

## motivation

> I really don't like writing reports.
>
> --generic pentester

Have you ever wondered why so many pentesters agree with this?

When a tool constantly gets in the way instead of helping you, even fun tasks can become dreadful.
I'm not saying that writing documentation is everyone's favorite pastime.
But I've noticed that when I have to use this one particular word processor (I don't think I need to name it), my stress level increases with the amount of time I spend using it.
On the other hand, when I use a text editor (there is a difference between "text editor" and "word processor") and Markdown (or some other lightweight markup language), I can happily write for hours.

Using plain text (e.g. Markdown, LaTeX, etc.) as the basis for the final output (i.e. PDF) allows us to use Git itself for collaboration.
Most Git services (e.g. [Gitea](https://gitea.io/en-us/), [GitLab](https://about.gitlab.com/), etc.) provide all the necessary tools for this (e.g. groups, access permissions, comments, etc.).

## requirements

Install Jinja2, TeX Live (full) and Pandoc:

```text
$ sudo apt install python3-jinja2 texlive-full pandoc
```

## usage

1. modify [`project.yaml`](project.yaml)
2. conduct pentest
3. document findings in `report/issues/<issue title>.md`
   * put screenshots right next to the issue file
   * you can structure a pentest into groups: put the issues into folders (e.g. `report/issues/1 - EXAMPLE/`)
4. add issue templates to [`templates/issues/`](templates/issues/)
5. adapt [`tools.md`](tools.md), [`limitations.md`](limitations.md) and [`summary.md`](summary.md)
6. create the PDF report

```text
$ ./report.py -h
usage: report.py [-h] [-o] [-v]

options:
  -h, --help       show this help message and exit
  -o, --overwrite  overwrite the LaTeX document
  -v, --verbose    be very verbose
```

## credits

* [image for the title page](https://www.oldbookillustrations.com/illustrations/microscope/)
