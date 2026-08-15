# Northwind Instruments

A whole site, so the tool can be judged on something other than a page called
"index" with the body "hello".

Five pages, one content type every page is bound to, a template that uses the
filters, and a stylesheet. It publishes with the accessibility gate passing,
the scanner clean, and a Content-Security-Policy that names nothing external
because the content references nothing external.

```bash
scrivet init
cp page.html site.css templates/
scrivet type add product.json
scrivet add index=index.json instruments=instruments.json \
             calibration=calibration.json about=about.json contact=contact.json
for p in index instruments calibration about contact; do
  scrivet type bind $p product
done
scrivet publish
scrivet site --addr 127.0.0.1:8080
```

## What it demonstrates

**The filters**, which are how this does the job other systems use a scripting
language for. In `page.html`:

| In the template | On the page |
|---|---|
| `{{ page.eyebrow \| upper }}` | MODEL NW-400 |
| `{{ page.updated \| date:"2 January 2006" }}` | Updated 14 July 2026 |
| `{{ page.author \| title }}` | Sam Whitfield |
| `{{ page.title \| slug }}` | the-bench-calibrator |

Each is a name from a fixed list taking one literal argument. There is no way
to call a method, reach anything the template was not given, or write a new
filter from a template — which is the difference between this and the
server-side template injection advisories every scripting engine carries.

**The content type.** `product.json` is eleven flat fields with lengths and
kinds. No nesting, no references, no regular expressions. Every page is bound
to it, so a page missing a required field is refused at write time rather than
discovered when somebody looks at the site.

**`hero_alt` is declared `alt_for: hero`**, which is what lets the
accessibility gate know an image has a description without inferring it from a
naming convention.

## What it is not

It has no images, because a repository is a bad place to keep them and a
made-up photograph would not show anything the field types do not already say.
Add one with `scrivet media add photo.jpg --alt "..."` and the pipeline will
strip its metadata and resize it.
