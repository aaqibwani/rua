# Report fixtures

**These are synthetic.** They are modelled on the shapes real receivers emit -
Google, Microsoft and Yahoo each format aggregate reports slightly differently -
but none of them came off a real mailbox.

CONTRIBUTING.md is right that this is the weakest kind of test data: a parser
tested only against documents its author wrote will pass on exactly the inputs
its author imagined. **Redacted real reports are the most valuable thing anyone
can add here**, especially from a receiver that produced something the parser
choked on.

The adversarial fixtures are a different matter and are legitimately synthetic -
a decompression bomb has no "real" version worth capturing.

| File | What it is |
|---|---|
| aggregate_google.xml | Common shape: full metadata, several records, mixed alignment, IPv6 |
| aggregate_microsoft.xml | Different element ordering, extra_contact_info, no pct |
| aggregate_no_report_id.xml | Missing report_id; the parser must synthesise one deterministically |
| aggregate_odd_records.xml | Records that must be skipped individually, not fatally |
| tlsrpt_google.json | RFC 8460 report with a success summary and two failure causes |
| tlsrpt_unexplained_failures.json | Summary claims more failures than the breakdown explains |
| malformed_not_xml.xml | Plain text where XML is expected |
| malformed_wrong_root.xml | Well-formed XML that is not a DMARC report |
| billion_laughs.xml | Entity-expansion bomb; must be refused, not expanded |
