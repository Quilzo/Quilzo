# Evidence in

How files become evidence in the security register: sealed by their hash,
read as hostile, graded by how they came in, and checkable after the file
itself has gone.

## What happens to a file

1. **It is sealed first.** The file is kept in the raw evidence store beside
   the store (`evidence/` under the store's directory), under its SHA-256,
   before anything parses it. On an encrypted store it is sealed with the
   store's own keyring. What is read is the file that was sealed. A file
   sealed for the first time is recorded in the audit log (`evidence.seal`)
   as whoever brought it, whether or not it can be read and whether or not
   a preview of it is ever confirmed; nothing is sealed while the audit log
   cannot take that entry.
2. **It is read as hostile.** Each format's reader holds the file to a size
   (64 MB), a nesting depth (64) and a number of records (200,000). A JSON
   document that gives a key twice in one object is refused, because two
   readers would read two different documents; where a format is decoded
   into structures (SARIF, a DSSE envelope), two keys that differ only in
   case count as the same key, because that is how the decoder reads them.
   Two keys of a JSON table's row that become one column heading are
   refused too. A workbook is read with the standard library's zip and XML
   readers alone: a zip bomb, an XML bomb, a document type declaration and
   a part nested past any real workbook are refused, and so are a workbook
   of more than four million cells, merged ranges and answer lists that
   would stand for more than two million, and defined names over more than
   256 wide ranges; no formula is worked out; no link is followed. Of a
   table, only the columns its map reads are kept in memory.
3. **Every fact says where it came from.** Each Observation and Evidence
   record carries its grade, the digest of the file, the place it was read
   from (a cell such as `Devices!B4`, a row, or a JSON pointer such as
   `/1/status_code`) and, when that place is one a person opening the file
   would not see, a taint: a hidden sheet, row or column (a row given no
   height and a column given no width count as hidden), a comment, a
   formula's cached result or a CSV cell a spreadsheet would run as one, a
   cell a defined name points at, a link to another workbook.
4. **What was read is kept beside the seal.** A list of every record the
   file yielded, each with the hash of its fields, is kept for good, and its
   digest is in the file's `RawFile` record. When the raw file's time to be
   kept is up (thirteen months after it was last received) its bytes are
   erased, and every fact it yielded still checks against the seal and the
   list.
5. **It is written once.** The records go through `register.Put`, as the
   person or service who brought the file, in one commit, recorded in the
   audit log. A second import of the same file writes nothing.

What a file says about how the organisation's controls relate to a
framework (Prowler's compliance table, a Compliance Finding's standards) is
somebody else's mapping. It is never written: it waits on the register's
proposals ref, under the name `evidence-clerk`, for a person to decide.

## Grades

The grade is how the file came in, and nothing in the file changes it. A
signed file is verified against the keys pinned in the register, and never
against a key that came with the file or with the request.

| Grade | When |
|---|---|
| signed | A DSSE envelope whose signature checks against a key a person pinned |
| imported | A table read through a column map that names the tool whose export it is, or any file a service brought |
| uploaded | Any other file a person brought: a scanner's output, a bill of materials, a table of their own |

The connector and CI grades are given by the modules that pull and push
facts, never by an import. No importer here gives the screenshot grade: a
picture is a person's statement, and is recorded as one.

## Formats

| Format | Reads |
|---|---|
| `csv`, `xlsx`, `json` | A table, through a column map a person confirmed: into observations, or any kind a table can make |
| `ocsf` | OCSF 1.1 to 1.5 findings (classes 2001, 2003 and 2004), a JSON list or JSON Lines |
| `cyclonedx` | CycloneDX 1.2 to 1.6 in JSON, with the VEX statements a bill carries |
| `spdx` | SPDX 2.2 and 2.3 in JSON |
| `sarif` | SARIF 2.1.0: open findings by rule, by severity and by kind, and what was suppressed in the source |
| `csaf` | CSAF 2.0 security advisories and VEX documents |
| `openvex` | OpenVEX |
| `dsse` | A DSSE envelope verified against a pinned key, holding an in-toto statement, or a bill of materials or a VEX document |
| `osquery` | osquery result logs, differential and snapshot, and Fleet query reports |

A table is read only through a column map in the register. `quilzo evidence
draft-map` and the Import screen draft one from the table's headings, with
the first rows it would read; a person changes what is wrong and confirms
it, once. The grade, the raw digest and the place are the importer's to
write, and a map that reads them from a column is refused. So is who
stated a piece of evidence: a statement read from a table is the person's
who brings the file, named by the pseudonym the surface knows for them,
and is refused where the surface knows none (no surface passes a
pseudonym yet, so statements come in only as test runs' evidence for now).
A table is never read into a Decision, an Acknowledgement or a
MetricValue: each is never changed once written and is made by what it
records, so a table read into one would name a decider or a reader who
never acted, or a figure nothing computed, for good.

## On every surface

- `quilzo ingest FORMAT FILE [--source NAME] [--map NAME] [--preview]`
- `quilzo evidence list | show FILE | verify [FILE] | expire | maps | keys |
  draft-map | confirm-map | pin`
- The admin's **Evidence** screens: the files, one file with whether it
  checks, the import with a preview of every record before anything is
  written, column maps and pinned keys. Confirming an import writes what
  the preview showed or nothing: if the file reads otherwise by then (a
  column map changed in between), it says to look again.
- The agent interface: `evidence_files`, `evidence_verify`,
  `evidence_expire` and `evidence_ingest`; the last two write, and a model is
  refused them as every write to the register refuses one.
- The content API reads: `/api/v1/evidence/formats`, `/files`,
  `/files/{id}` and `/verify`.

## What is and is not verified here

- Each reader is tested against fixtures in `internal/evidence/testdata`,
  written from each format's published specification and the documented
  output of the tools named. They have not been checked against exports
  from live accounts. Report a file that reads wrongly.
- A file is brought in through the content API by no route yet: the API
  reads. Import on the command line, on the Import screen or through the
  agent interface.
- CycloneDX in XML, SPDX 3 (JSON-LD) and Sigstore's keyless signatures are
  not read, and are refused rather than misread.
- Importers for particular GRC tools' exports are not built: their formats
  cannot be checked here. A GRC tool's CSV, workbook or JSON export comes in
  through a column map that names the tool.
- The SARIF reader came, with its tests, from a security team's own tools;
  a digest of its shared fixture is held in its tests. A severity is the
  tool's `security-severity` on the published bands (9.0 critical, 7.0 high,
  4.0 medium) and, only where a result has none, its level, which the notes
  say. That source's conversion of results into its own alerts, and its
  SARIF writer, were not carried over, with their tests: Quilzo reads SARIF
  and writes none.
