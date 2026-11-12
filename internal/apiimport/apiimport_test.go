// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package apiimport

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
)

const invoices = `{
  "openapi": "3.1.0",
  "info": {"title": "Billing API", "description": "Invoices and customers.\nMore text."},
  "servers": [{"url": "https://api.billing.example/v1"}],
  "components": {
    "securitySchemes": {"token": {"type": "http", "scheme": "bearer"}},
    "parameters": {"Id": {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}},
    "schemas": {"Invoice": {"type": "object", "properties": {"amount": {"type": "number"}, "customer": {"$ref": "#/components/schemas/Customer"}}},
                "Customer": {"type": "object", "properties": {"email": {"type": "string"}}}}
  },
  "security": [{"token": []}],
  "paths": {
    "/invoices": {
      "get": {"operationId": "listInvoices", "summary": "List invoices",
              "parameters": [{"name": "limit", "in": "query", "schema": {"type": "integer"}},
                             {"name": "X-Tenant", "in": "header", "schema": {"type": "string"}}]},
      "post": {"operationId": "createInvoice", "summary": "Raise an invoice",
               "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Invoice"}}}}}
    },
    "/invoices/{id}": {
      "parameters": [{"$ref": "#/components/parameters/Id"}],
      "get": {"operationId": "getInvoice", "summary": "One invoice"},
      "delete": {"summary": "Cancel an invoice"},
      "patch": {"operationId": "notes", "parameters": [{"$ref": "https://evil.example/params.json#/X"}],
                "requestBody": {"content": {"application/json": {"schema": {"$ref": "https://evil.example/schema.json"}}}}}
    }
  }
}`

func TestAnOpenAPIDocumentListsWhatItOffersAndDeclaresNothingUnasked(t *testing.T) {
	imp, err := OpenAPI([]byte(invoices), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(imp.Integration.Operations) != 0 || len(imp.Integration.Uses) != 0 {
		t.Fatal("operations were declared that nobody named")
	}
	var names []string
	for _, o := range imp.Available {
		names = append(names, o.Method+" "+o.Name)
	}
	got := strings.Join(names, ", ")
	for _, want := range []string{"GET listInvoices", "POST createInvoice", "GET getInvoice", "DELETE delete_invoices_id", "PATCH notes"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q is not on offer: %s", want, got)
		}
	}
}

func TestOnlyTheNamedOperationsAreDeclaredSwitchedOff(t *testing.T) {
	imp, err := OpenAPI([]byte(invoices), Options{Uses: []string{"listInvoices", "getInvoice", "createInvoice"}, Secret: "billing-token"})
	if err != nil {
		t.Fatal(err)
	}
	in := imp.Integration
	if in.Enabled {
		t.Error("an imported integration arrived switched on")
	}
	if in.Name != "billing-api" || in.Endpoint != "api.billing.example" || in.Path != "/v1" || in.Auth != "" || !in.Writes {
		t.Errorf("declared %+v", in)
	}
	if !strings.HasPrefix(in.Purpose, "Billing API: Invoices and customers.") || strings.Contains(in.Purpose, "More text") {
		t.Errorf("purpose %q", in.Purpose)
	}
	ops := map[string]agent.Operation{}
	for _, o := range in.Operations {
		ops[o.Name] = o
	}
	if len(ops) != 3 {
		t.Fatalf("%d operations declared", len(ops))
	}
	if p := ops["getInvoice"].Params; len(p) != 1 || p[0].Name != "id" || p[0].In != "path" {
		t.Errorf("getInvoice params %+v", p)
	}
	for _, p := range ops["listInvoices"].Params {
		if p.In == "header" {
			t.Error("a header parameter was imported")
		}
	}
	if b := string(ops["createInvoice"].Body); !strings.Contains(b, `"email"`) || strings.Contains(b, "$ref") {
		t.Errorf("the body schema was not followed locally: %s", b)
	}
	notes := strings.Join(imp.Notes, "\n")
	if !strings.Contains(notes, "X-Tenant") || !strings.Contains(notes, "2 other operations") {
		t.Errorf("notes:\n%s", notes)
	}
}

func TestNothingOutsideTheDocumentIsFollowed(t *testing.T) {
	imp, err := OpenAPI([]byte(invoices), Options{Uses: []string{"notes", "getInvoice"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range imp.Integration.Operations {
		if o.Name == "notes" && string(o.Body) != `{"type":"object"}` {
			t.Errorf("an external schema was used: %s", o.Body)
		}
	}
	if notes := strings.Join(imp.Notes, "\n"); !strings.Contains(notes, "evil.example/params.json") ||
		!strings.Contains(notes, "not fetched") {
		t.Errorf("the external references were not named:\n%s", notes)
	}
}

func TestADocumentThatCannotBeReachedSafelyIsRefused(t *testing.T) {
	for name, doc := range map[string]string{
		"swagger 2":       `{"swagger": "2.0", "paths": {}}`,
		"plain http":      strings.Replace(invoices, "https://api.billing.example", "http://api.billing.example", 1),
		"server template": strings.Replace(invoices, "https://api.billing.example/v1", "https://{region}.billing.example", 1),
		"no operations":   `{"openapi": "3.0.3", "info": {"title": "x"}, "servers": [{"url": "https://x.example"}], "paths": {}}`,
	} {
		if _, err := OpenAPI([]byte(doc), Options{Uses: []string{"getInvoice"}}); err == nil {
			t.Errorf("%s was imported", name)
		}
	}
	if _, err := OpenAPI([]byte(invoices), Options{Uses: []string{"nope"}}); err == nil {
		t.Error("an operation the document lacks was declared")
	}
	// An API key in a query string is not imported.
	q := strings.Replace(invoices, `{"type": "http", "scheme": "bearer"}`, `{"type": "apiKey", "in": "query", "name": "key"}`, 1)
	imp, err := OpenAPI([]byte(q), Options{Uses: []string{"getInvoice"}})
	if err != nil || imp.Integration.Auth != "" || !strings.Contains(strings.Join(imp.Notes, " "), "logs") {
		t.Errorf("a query key: %v %+v", err, imp)
	}
	h := strings.Replace(invoices, `{"type": "http", "scheme": "bearer"}`, `{"type": "apiKey", "in": "header", "name": "X-API-Key"}`, 1)
	if imp, err := OpenAPI([]byte(h), Options{Uses: []string{"getInvoice"}}); err != nil || imp.Integration.Auth != "header:X-API-Key" {
		t.Errorf("a header key: %v", err)
	}
}

func TestAnMCPRegistryEntryBecomesAServerDeclaration(t *testing.T) {
	doc := `{"name": "io.github.acme/tracker", "description": "Issues in the Acme tracker",
	  "remotes": [{"type": "sse", "url": "https://old.acme.example/sse"}, {"type": "streamable-http", "url": "https://mcp.acme.example/mcp"}],
	  "packages": [{"registryType": "npm", "identifier": "@acme/tracker-mcp"}]}`
	if !IsServerJSON([]byte(doc)) || IsServerJSON([]byte(invoices)) {
		t.Fatal("the two kinds of document are not told apart")
	}
	imp, err := MCPServer([]byte(doc), Options{Uses: []string{"list_issues"}})
	if err != nil {
		t.Fatal(err)
	}
	in := imp.Integration
	if in.Kind != agent.IntegrationMCP || in.Name != "tracker" || in.Endpoint != "mcp.acme.example" || in.Path != "/mcp" || in.Enabled {
		t.Errorf("declared %+v", in)
	}
	if !strings.Contains(strings.Join(imp.Notes, " "), "@acme/tracker-mcp") {
		t.Error("the package was not mentioned")
	}
	if _, err := MCPServer([]byte(`{"name": "x", "packages": [{"registryType": "npm", "identifier": "y"}]}`), Options{}); err == nil {
		t.Error("a package-only server was declared with nowhere to reach")
	}
}

// A request body that names itself, or names one that names it back, is an
// open object and a note. It was followed until the stack ran out, which is
// a fatal error no recover catches: a 263-byte document, or an agent file
// carrying one, ended the whole server.
func TestARequestBodyThatNamesItselfIsAnOpenObject(t *testing.T) {
	for name, bodies := range map[string]string{
		"itself":     `"A": {"$ref": "#/components/requestBodies/A"}`,
		"each other": `"A": {"$ref": "#/components/requestBodies/B"}, "B": {"$ref": "#/components/requestBodies/A"}`,
	} {
		doc := `{"openapi": "3.0.3", "info": {"title": "Loop"}, "servers": [{"url": "https://loop.example"}],
		  "components": {"requestBodies": {` + bodies + `}},
		  "paths": {"/a": {"post": {"operationId": "send", "requestBody": {"$ref": "#/components/requestBodies/A"}}}}}`
		imp, err := OpenAPI([]byte(doc), Options{Uses: []string{"send"}})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if b := string(imp.Integration.Operations[0].Body); b != `{"type":"object"}` {
			t.Errorf("%s: the body is %s", name, b)
		}
		if notes := strings.Join(imp.Notes, "\n"); !strings.Contains(notes, "send: its body refers to itself") {
			t.Errorf("%s: the loop was not named:\n%s", name, notes)
		}
	}
	// A body named through a few others is still followed to its schema.
	doc := `{"openapi": "3.0.3", "info": {"title": "Chain"}, "servers": [{"url": "https://chain.example"}],
	  "components": {"requestBodies": {"A": {"$ref": "#/components/requestBodies/B"}, "B": {"$ref": "#/components/requestBodies/C"},
	    "C": {"content": {"application/json": {"schema": {"type": "object", "properties": {"to": {"type": "string"}}}}}}}},
	  "paths": {"/a": {"post": {"operationId": "send", "requestBody": {"$ref": "#/components/requestBodies/A"}}}}}`
	imp, err := OpenAPI([]byte(doc), Options{Uses: []string{"send"}})
	if err != nil {
		t.Fatal(err)
	}
	if b := string(imp.Integration.Operations[0].Body); !strings.Contains(b, `"to"`) {
		t.Errorf("a chain of bodies was not followed: %s", b)
	}
}

// allocated is how many bytes f allocated.
func allocated(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// A schema whose properties each name another, whose properties each name
// another, grows as the power of its fan-out when every reference is
// expanded where it is used, as the billion laughs do with entities. Only
// the result's size was bounded, after it was made: 8.6 KB of document
// reached 1.6 GB of memory and ten seconds first. It is refused as it
// grows instead.
func TestAReferenceFanOutIsRefusedBeforeItGrows(t *testing.T) {
	doc := fanOut(5, 40)
	var imp *Imported
	var err error
	start := time.Now()
	n := allocated(func() { imp, err = OpenAPI([]byte(doc), Options{Uses: []string{"send"}}) })
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 5*time.Second || n > 64<<20 {
		t.Errorf("reading %d bytes took %v and %d MB", len(doc), took, n>>20)
	}
	if b := string(imp.Integration.Operations[0].Body); b != `{"type":"object"}` {
		t.Errorf("the body is %.200s", b)
	}
	if notes := strings.Join(imp.Notes, "\n"); !strings.Contains(notes, "over 32 KiB") {
		t.Errorf("the size was not named:\n%s", notes)
	}
	// One that stays within the limit is followed as before.
	imp, err = OpenAPI([]byte(fanOut(2, 10)), Options{Uses: []string{"send"}})
	if err != nil {
		t.Fatal(err)
	}
	if b := string(imp.Integration.Operations[0].Body); strings.Count(b, `{"type":"string"}`) != 100 || strings.Contains(b, "$ref") {
		t.Errorf("a schema within the limit was not followed: %.300s", b)
	}
}

// fanOut is a document whose body schema has n properties that each name a
// schema with n properties, levels deep.
func fanOut(levels, n int) string {
	var schemas []string
	for level := 0; level < levels; level++ {
		var props []string
		for i := 0; i < n; i++ {
			props = append(props, fmt.Sprintf(`"p%d": {"$ref": "#/components/schemas/S%d"}`, i, level+1))
		}
		schemas = append(schemas, fmt.Sprintf(`"S%d": {"type": "object", "properties": {%s}}`, level, strings.Join(props, ", ")))
	}
	schemas = append(schemas, fmt.Sprintf(`"S%d": {"type": "string"}`, levels))
	return `{"openapi": "3.0.3", "info": {"title": "Fan"}, "servers": [{"url": "https://fan.example"}],
	  "components": {"schemas": {` + strings.Join(schemas, ", ") + `}},
	  "paths": {"/a": {"post": {"operationId": "send",
	    "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/S0"}}}}}}}}`
}

// A component named from many places is read once, not once for each
// place. Read at every reference, a 2 MB schema named by two hundred
// properties cost twenty seconds and 2.9 GB, and a parameter or a request
// body named by every operation was read again for each of them.
func TestAComponentNamedFromManyPlacesIsReadOnce(t *testing.T) {
	pad := strings.Repeat("x", 2<<20)
	var props, params, paths []string
	for i := 0; i < 200; i++ {
		props = append(props, fmt.Sprintf(`"p%d": {"$ref": "#/components/schemas/S"}`, i))
		params = append(params, `{"$ref": "#/components/parameters/P"}`)
		paths = append(paths, fmt.Sprintf(`"/b%d": {"post": {"operationId": "b%d", "requestBody": {"$ref": "#/components/requestBodies/R"}}}`, i, i))
	}
	doc := `{"openapi": "3.0.3", "info": {"title": "Many"}, "servers": [{"url": "https://many.example"}],
	  "components": {
	    "schemas": {"S": {"type": "string", "description": "` + pad + `"}},
	    "parameters": {"P": {"name": "id", "in": "query", "description": "` + pad + `"}},
	    "requestBodies": {"R": {"content": {"application/json": {"schema": {"type": "object", "description": "` + pad + `"}}}}}},
	  "paths": {"/a": {"parameters": [` + strings.Join(params, ", ") + `],
	    "get": {"operationId": "list"},
	    "post": {"operationId": "send", "requestBody": {"content": {"application/json": {"schema": {"type": "object",
	      "properties": {` + strings.Join(props, ", ") + `}}}}}}}, ` + strings.Join(paths, ", ") + `}}`
	var imp *Imported
	var err error
	start := time.Now()
	n := allocated(func() { imp, err = OpenAPI([]byte(doc), Options{Uses: []string{"list", "send", "b0", "b199"}}) })
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 10*time.Second || n > 96<<20 {
		t.Errorf("reading %d bytes took %v and %d MB", len(doc), took, n>>20)
	}
	ops := map[string]agent.Operation{}
	for _, o := range imp.Integration.Operations {
		ops[o.Name] = o
	}
	if p := ops["list"].Params; len(p) != 1 || p[0].Name != "id" {
		t.Errorf("the parameter named many times is %+v", p)
	}
	for _, name := range []string{"send", "b0", "b199"} {
		if b := string(ops[name].Body); b != `{"type":"object"}` {
			t.Errorf("%s: the body over 32 KiB is %.100s", name, b)
		}
	}
}

// Each body schema is bounded, but a reference lets a few bytes of operation
// name a large one, so the bodies one document makes are bounded together
// too. 1.1 MB of operations that each named the same 20 KiB schema took
// nineteen seconds and kept 380 MB; 8 MiB would have kept three gigabytes.
func TestTheBodiesOfOneDocumentAreBoundedTogether(t *testing.T) {
	var paths []string
	for i := 0; i < 1200; i++ {
		paths = append(paths, fmt.Sprintf(`"/a%04d": {"post": {"operationId": "a%04d",
		  "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Big"}}}}}}`, i, i))
	}
	doc := `{"openapi": "3.0.3", "info": {"title": "Wide"}, "servers": [{"url": "https://wide.example"}],
	  "components": {"schemas": {"Big": {"type": "object", "description": "` + strings.Repeat("x", 16<<10) + `"}}},
	  "paths": {` + strings.Join(paths, ", ") + `}}`
	imp, err := OpenAPI([]byte(doc), Options{Uses: []string{"a0000", "a1199"}})
	if err != nil {
		t.Fatal(err)
	}
	ops := imp.Integration.Operations
	if b := string(ops[0].Body); len(b) < 16<<10 {
		t.Errorf("the first body is %.100s", b)
	}
	if b := string(ops[1].Body); b != `{"type":"object"}` {
		t.Errorf("the last body is %d bytes", len(b))
	}
	if notes := strings.Join(imp.Notes, "\n"); !strings.Contains(notes, "a1199: the document's body schemas are over 16 MiB together") {
		t.Errorf("the bound was not named:\n%.500s", notes)
	}
}

// A wide component, a long list or many properties, named by many
// operations, is copied at each only as far as a body may grow. Room for
// all of it was made at every reference, however little was then copied: a
// list of a million named by six hundred operations, 3.2 MB of document,
// made 8 GB, and 150,000 properties made 5 GB.
func TestAWideComponentIsCopiedOnlyAsFarAsABodyMayGrow(t *testing.T) {
	var keys, paths []string
	for i := 0; i < 150000; i++ {
		keys = append(keys, fmt.Sprintf(`"k%x": 0`, i))
	}
	for i := 0; i < 600; i++ {
		paths = append(paths, fmt.Sprintf(`"/a%03d": {"post": {"operationId": "a%03d",
		  "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Wide"}}}}}}`, i, i))
	}
	for name, wide := range map[string]string{
		"a long list":     `{"enum": [` + strings.Repeat("0, ", 1<<20) + `0]}`,
		"many properties": `{"type": "object", "properties": {` + strings.Join(keys, ", ") + `}}`,
	} {
		doc := `{"openapi": "3.0.3", "info": {"title": "Wide"}, "servers": [{"url": "https://wide.example"}],
		  "components": {"schemas": {"Wide": ` + wide + `}}, "paths": {` + strings.Join(paths, ", ") + `}}`
		var imp *Imported
		var err error
		n := allocated(func() { imp, err = OpenAPI([]byte(doc), Options{Uses: []string{"a000"}}) })
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if n > 1<<30 {
			t.Errorf("%s: reading %d bytes made %d MB", name, len(doc), n>>20)
		}
		if b := string(imp.Integration.Operations[0].Body); b != `{"type":"object"}` {
			t.Errorf("%s: the body over 32 KiB is %.100s", name, b)
		}
	}
}

// Operations that share a name are numbered in time in proportion to how
// many there are. Each counted up from 2 again past all those before it:
// 4,000 operations with one operationId, 160 KB of document, took four
// and a half seconds, and the 8 MiB a document may be would have taken
// hours.
func TestOperationsThatShareANameAreNumberedInTimeInProportion(t *testing.T) {
	// The numbers are as they were: the least free, past one taken by
	// another operation's own name.
	doc := `{"openapi": "3.0.3", "info": {"title": "Same"}, "servers": [{"url": "https://same.example"}],
	  "paths": {"/a": {"get": {"operationId": "send"}}, "/b": {"get": {"operationId": "send_3"}},
	    "/c": {"get": {"operationId": "send"}}, "/d": {"get": {"operationId": "send"}}, "/e": {"get": {"operationId": "send"}}}}`
	imp, err := OpenAPI([]byte(doc), Options{})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, o := range imp.Available {
		got = append(got, o.Name)
	}
	if strings.Join(got, " ") != "send send_3 send_2 send_4 send_5" {
		t.Errorf("the names are %v", got)
	}
	var paths []string
	for i := 0; i < 20000; i++ {
		paths = append(paths, fmt.Sprintf(`"/a%05d": {"get": {"operationId": "send"}}`, i))
	}
	doc = `{"openapi": "3.0.3", "info": {"title": "Same"}, "servers": [{"url": "https://same.example"}],
	  "paths": {` + strings.Join(paths, ", ") + `}}`
	read := make(chan *Imported, 1)
	start := time.Now()
	go func() {
		imp, _ := OpenAPI([]byte(doc), Options{})
		read <- imp
	}()
	select {
	case imp := <-read:
		if n := len(imp.Available); n != 20000 || imp.Available[n-1].Name != "send_20000" {
			t.Errorf("the last of %d is %s", n, imp.Available[n-1].Name)
		}
	case <-time.After(8 * time.Second):
		t.Errorf("%d bytes of operations with one name were not read in %v", len(doc), time.Since(start))
	}
}

// What an integration and its operations are for is cut where a character
// starts. Both are the document's own words, in whatever language its
// authors wrote, and both are what a person reads to decide what to turn on.
func TestALongPurposeAndDescriptionAreCutBetweenCharacters(t *testing.T) {
	purpose, description := strings.Repeat("a", 299), strings.Repeat("a", 199)
	doc := fmt.Sprintf(`{"openapi": "3.1.0", "info": {"title": %q},
  "servers": [{"url": "https://api.billing.example/v1"}],
  "paths": {"/notes": {"get": {"operationId": "notes", "summary": %q}}}}`,
		purpose+"中文", description+"中文")
	imp, err := OpenAPI([]byte(doc), Options{Name: "notes"})
	if err != nil {
		t.Fatal(err)
	}
	if got := imp.Integration.Purpose; got != purpose {
		t.Errorf("purpose ends %q", got[len(got)-3:])
	}
	if len(imp.Available) != 1 {
		t.Fatalf("%d operations", len(imp.Available))
	}
	if got := imp.Available[0].Summary; got != description {
		t.Errorf("description ends %q", got[len(got)-3:])
	}
}
