// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package sheet

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/schema"
)

// event is the ready-made event type's shape, as cmd/quilzo declares it.
func event() *schema.Type {
	f := func(name string, kind schema.Kind, label string, required bool) schema.Field {
		return schema.Field{Name: name, Kind: kind, Label: label, Required: required}
	}
	return &schema.Type{Name: "event", Fields: []schema.Field{
		f("title", schema.Text, "Title", true), f("slug", schema.Slug, "Page link", true),
		f("date", schema.Date, "Date", true), f("time", schema.Time, "Starts at", false),
		f("end_date", schema.Date, "Last day", false), f("until", schema.Time, "Finishes at", false),
		f("venue", schema.Text, "Venue", false), f("location", schema.Text, "Location", false),
		f("online", schema.URL, "Online at", false), f("summary", schema.LongText, "About it", false),
		f("image", schema.Text, "Picture", false), {Name: "alt", Kind: schema.Text, AltFor: "image"},
		f("price", schema.Text, "Price", false), f("tickets", schema.URL, "Tickets", false),
		{Name: "status", Kind: schema.Choice, Choices: []string{"cancelled", "postponed", "moved online"}},
	}}
}

func product() *schema.Type {
	return &schema.Type{Name: "product", Fields: []schema.Field{
		{Name: "name", Kind: schema.Text, Required: true}, {Name: "sku", Kind: schema.Text},
		{Name: "price", Kind: schema.Number}, {Name: "in_stock", Kind: schema.Boolean, Label: "In stock"},
		{Name: "tags", Kind: schema.List}, {Name: "added", Kind: schema.Date},
	}}
}

func check(t *schema.Type) func(map[string]any) error {
	return func(f map[string]any) error {
		if p := schema.Validate(*t, f); len(p) > 0 {
			return &schema.Invalid{Where: t.Name, Problems: p}
		}
		return nil
	}
}

func read(t *testing.T, body string, opts Options) *Sheet {
	t.Helper()
	sh, err := Read([]byte(body), opts)
	if err != nil {
		t.Fatal(err)
	}
	return sh
}

func TestASheetIsReadAsItsFieldsSay(t *testing.T) {
	sh := read(t, "Title,Page link,Date,Starts at,Finishes,Place,Online at,Notes,status\r\n"+
		"Rye night,,14/11/2026,7.30pm,21:00,The bakery,meet.example.com/rye,x,Cancelled\r\n"+
		"\"Market, with stalls\",market,25/12/2026,noon,,,,,\r\n", Options{Type: event()})
	var got []string
	for _, c := range sh.Columns {
		got = append(got, c.Header+"→"+c.Field)
	}
	want := "Title→title Page link→slug Date→date Starts at→time Finishes→until Place→venue Online at→online " +
		"Notes→ status→status"
	if strings.Join(got, " ") != want {
		t.Errorf("columns\n got %s\nwant %s", strings.Join(got, " "), want)
	}
	if !strings.Contains(sh.Columns[7].Note, "no field of event") {
		t.Errorf("a column left out did not say why: %q", sh.Columns[7].Note)
	}
	r := sh.Rows[0]
	for k, v := range map[string]any{"title": "Rye night", "date": "2026-11-14", "time": "19:30", "until": "21:00",
		"venue": "The bakery", "online": "https://meet.example.com/rye", "status": "cancelled"} {
		if r.Fields[k] != v {
			t.Errorf("%s = %#v, want %#v", k, r.Fields[k], v)
		}
	}
	if r.Line != 2 || sh.Rows[1].Line != 3 || !reflect.DeepEqual(r.Clear, []string{"slug"}) {
		t.Errorf("lines %d, %d; cleared %v", r.Line, sh.Rows[1].Line, r.Clear)
	}
	if sh.Rows[1].Fields["title"] != "Market, with stalls" || sh.Rows[1].Fields["time"] != "12:00" {
		t.Errorf("second row %v", sh.Rows[1].Fields)
	}
}

func TestEverySpreadsheetsWayOfSavingIsRead(t *testing.T) {
	utf16le := func(s string) string {
		var b []byte
		b = append(b, 0xFF, 0xFE)
		for _, u := range utf16.Encode([]rune(s)) {
			b = append(b, byte(u), byte(u>>8))
		}
		return string(b)
	}
	for name, body := range map[string]string{
		"UTF-8 with its mark":        "\ufeffname,price\nCafé crème,\"1,250.50\"\n",
		"semicolons, decimal commas": "name;price\nCafé crème;1.250,50\n",
		"Excel's sep= line":          "sep=;\nname;price\nCafé crème;1250,5\n",
		"tabs, UTF-16":               utf16le("name\tprice\r\nCafé crème\t1250.5\r\n"),
		"Windows-1252":               "name,price\nCaf\xe9 cr\xe8me,\xa31250.50\n",
	} {
		t.Run(name, func(t *testing.T) {
			sh := read(t, body, Options{Type: product()})
			if r := sh.Rows[0]; r.Fields["name"] != "Café crème" || r.Fields["price"] != 1250.5 {
				t.Errorf("%#v (notes %v)", r.Fields, sh.Notes)
			}
		})
	}
}

func TestValuesAreReadAsPeopleWriteThem(t *testing.T) {
	for _, tc := range []struct {
		kind schema.Kind
		in   string
		want any
	}{
		{schema.Number, "£1,250.00", 1250.0}, {schema.Number, "-3.5", -3.5}, {schema.Number, "1 000", 1000.0},
		{schema.Boolean, "Yes", true}, {schema.Boolean, "FALSE", false}, {schema.Boolean, "✓", true},
		{schema.Date, "2026-11-14T19:30:00Z", "2026-11-14"}, {schema.Date, "14 November 2026", "2026-11-14"},
		{schema.Date, "Nov 14th, 2026", "2026-11-14"}, {schema.Date, "Saturday 14 Nov 2026", "2026-11-14"},
		{schema.Date, "14.11.2026", "2026-11-14"}, {schema.Date, "2026/11/14", "2026-11-14"},
		{schema.Time, "7:30 PM", "19:30"}, {schema.Time, "7pm", "19:00"}, {schema.Time, "12am", "00:00"},
		{schema.Time, "19h30", "19:30"}, {schema.Time, "19:30:00", "19:30"}, {schema.Time, "7.30 p.m.", "19:30"},
		{schema.Time, "2026-11-14 19:30:00", "19:30"}, {schema.Time, "11/14/2026 7:30 PM", "19:30"},
		{schema.List, "rye; spelt", []any{"rye", "spelt"}}, {schema.List, "rye, spelt", []any{"rye", "spelt"}},
		{schema.List, `["a; b","c"]`, []any{"a; b", "c"}},
		{schema.Slug, "Summer Fair '26", "summer-fair-26"}, {schema.Email, "mailto:hi@x.org", "hi@x.org"},
		{schema.URL, "www.x.org/a", "https://www.x.org/a"}, {schema.Text, "two\nlines", "two lines"},
	} {
		got, problem := value(schema.Field{Name: "f", Kind: tc.kind}, tc.in, DayFirst, false)
		if problem != "" || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s %q = %#v (%s), want %#v", tc.kind, tc.in, got, problem, tc.want)
		}
	}
	for _, tc := range []struct {
		kind schema.Kind
		in   string
	}{
		{schema.Number, "twelve"}, {schema.Number, "12%"}, {schema.Boolean, "maybe"}, {schema.Date, "31/02/2026"},
		{schema.Date, "soon"}, {schema.Time, "25:00"}, {schema.Time, "13pm"}, {schema.Time, "7:5"},
	} {
		if _, problem := value(schema.Field{Name: "f", Kind: tc.kind}, tc.in, DayFirst, false); problem == "" {
			t.Errorf("%s %q was read", tc.kind, tc.in)
		}
	}
}

func TestADateThatCouldBeEitherWayIsAskedAbout(t *testing.T) {
	_, err := Read([]byte("name,added\nA,03/04/2026\nB,05/06/2026\n"), Options{Type: product()})
	var amb *AmbiguousDates
	if !errors.As(err, &amb) || amb.Example != "03/04/2026" {
		t.Fatalf("err %v", err)
	}
	sh := read(t, "name,added\nA,03/04/2026\n", Options{Type: product(), Dates: MonthFirst})
	if sh.Rows[0].Fields["added"] != "2026-03-04" {
		t.Errorf("month first: %v", sh.Rows[0].Fields["added"])
	}
	// One date past the 12th settles the column.
	sh = read(t, "name,added\nA,03/04/2026\nB,25/04/2026\n", Options{Type: product()})
	if sh.Rows[0].Fields["added"] != "2026-04-03" {
		t.Errorf("worked out day first: %v", sh.Rows[0].Fields["added"])
	}
	if _, err := Read([]byte("name,added\nA,13/04/2026\nB,04/13/2026\n"), Options{Type: product()}); err == nil {
		t.Error("a column written both ways was read")
	}
}

func TestAColumnCanBeMatchedByHandOrLeftOut(t *testing.T) {
	sh := read(t, "Product,Code,Price,Weight\nRye,R1,4,800\n",
		Options{Type: product(), Map: map[string]string{"Product": "name", "code": "sku", "Price": ""}})
	f := sh.Rows[0].Fields
	if f["name"] != "Rye" || f["sku"] != "R1" || f["price"] != nil {
		t.Errorf("%v", f)
	}
	if _, err := Read([]byte("Colour,Weight\nred,1\n"), Options{Type: product()}); err == nil ||
		!strings.Contains(err.Error(), `"Colour"`) {
		t.Errorf("a sheet with no field of the type: %v", err)
	}
}

func TestACollectionWithNoTypeTakesItsColumnsAsTheyAre(t *testing.T) {
	sh := read(t, "Host Name,Port,Encrypted,Postcode,Notes\nlaptop-14,443,TRUE,02134,\"a, b\"\n", Options{})
	want := map[string]any{"host_name": "laptop-14", "port": 443.0, "encrypted": true, "postcode": "02134",
		"notes": "a, b"}
	if !reflect.DeepEqual(sh.Rows[0].Fields, want) {
		t.Errorf("%#v", sh.Rows[0].Fields)
	}
}

func TestAProblemIsReportedWithItsLine(t *testing.T) {
	sh := read(t, "name,price\nRye,4\nSpelt,lots\nWheat,3,extra\n", Options{Type: product()})
	m := Merge{Collection: "products", Check: check(product())}
	plan := m.Plan(sh.Rows)
	if !plan.Refused() || len(plan.Problems) != 2 {
		t.Fatalf("%+v", plan)
	}
	s := plan.Summary()
	if !strings.Contains(s, `line 3: price: "lots" is not a number`) || !strings.Contains(s, "line 4: it has more cells") {
		t.Errorf("%s", s)
	}
	m.SkipBad = true
	if plan := m.Plan(sh.Rows); len(plan.Records) != 1 || plan.New != 1 || len(plan.Problems) != 2 {
		t.Errorf("skipping the bad rows: %+v", plan)
	}
}

func TestBroughtInTwiceIsTheSameRecords(t *testing.T) {
	body := "name,sku,price\nRye,R1,4\nSpelt,S1,5\n"
	sh := read(t, body, Options{Type: product()})
	m := Merge{Collection: "products", Key: "sku", Check: check(product())}
	first := m.Plan(sh.Rows)
	if first.New != 2 || first.Updated != 0 {
		t.Fatalf("%+v", first)
	}
	// Brought again into what the first made, with a price changed and a
	// field the sheet does not have kept.
	m.Existing = first.Records
	m.Existing[0].Fields["in_stock"] = true
	sh = read(t, "name,sku,price\nRye,R1,4.5\nSpelt,S1,\n", Options{Type: product()})
	again := m.Plan(sh.Rows)
	if again.New != 0 || again.Updated != 2 || again.Records[0].ID != first.Records[0].ID {
		t.Fatalf("%+v", again)
	}
	if f := again.Records[0].Fields; f["price"] != 4.5 || f["in_stock"] != true {
		t.Errorf("the update lost a field or kept the old price: %v", f)
	}
	if _, has := again.Records[1].Fields["price"]; has {
		t.Errorf("an emptied cell did not clear its field: %v", again.Records[1].Fields)
	}
	// With no key, the id column says which.
	csv := string(Write(product(), again.Records, WriteOptions{}))
	m.Key = ""
	m.Existing = again.Records
	back := m.Plan(read(t, csv, Options{Type: product()}).Rows)
	if back.Updated != 2 || back.New != 0 {
		t.Errorf("a sheet written here did not come back as the same records: %+v\n%s", back, csv)
	}
}

func TestAPageLinkIsMadeFromTheTitleAndKeptApart(t *testing.T) {
	existing := []collection.Record{{ID: strings.Repeat("a", 32), Fields: map[string]any{"title": "Rye night",
		"slug": "rye-night", "date": "2026-01-01"}}}
	sh := read(t, "title,date\nRye night,2026-11-14\nRye night,2026-12-12\nOpen day,2026-12-01\n", Options{Type: event()})
	m := Merge{Collection: "events", Existing: existing, Check: check(event()), Slug: "slug", Title: "title"}
	plan := m.Plan(sh.Rows)
	var got []string
	for _, r := range plan.Records {
		got = append(got, r.Fields["slug"].(string))
	}
	if strings.Join(got, " ") != "rye-night-2 rye-night-3 open-day" {
		t.Errorf("page links %v; problems %v", got, plan.Problems)
	}
	// Matched by page link, a row is the record with it.
	m.Key = "slug"
	plan = m.Plan(read(t, "title,date\nRye night,2026-11-14\n", Options{Type: event()}).Rows)
	if plan.Updated != 1 || plan.Records[0].ID != existing[0].ID {
		t.Errorf("%+v", plan)
	}
	// One written twice is a problem, not a page that shows one of them.
	plan = Merge{Collection: "events", Check: check(event()), Slug: "slug", Title: "title"}.Plan(
		read(t, "title,slug,date\nA,same,2026-11-14\nB,same,2026-11-15\n", Options{Type: event()}).Rows)
	if !plan.Refused() || !strings.Contains(plan.Summary(), "line 3: its slug, same, is line 2's too") {
		t.Errorf("%s", plan.Summary())
	}
}

func TestASheetIsWrittenSoNothingInItRuns(t *testing.T) {
	recs := []collection.Record{
		{ID: "b", Created: 2, Fields: map[string]any{"name": "=HYPERLINK(\"http://evil\")", "price": -4.0,
			"tags": []any{"rye", "dark; heavy"}, "in_stock": true}},
		{ID: "a", Created: 1, Fields: map[string]any{"name": "@SUM(A1)", "colour": "red", "tags": []any{"rye"}}},
	}
	out := string(Write(product(), recs, WriteOptions{BOM: true}))
	want := "\ufeffid,name,sku,price,in_stock,tags,added,colour\r\n" +
		"a,'@SUM(A1),,,,rye,,red\r\n" +
		"b,\"'=HYPERLINK(\"\"http://evil\"\")\",,-4,true,\"[\"\"rye\"\",\"\"dark; heavy\"\"]\",,\r\n"
	if out != want {
		t.Errorf("got\n%q\nwant\n%q", out, want)
	}
	sh := read(t, out, Options{Type: product(), Map: map[string]string{"colour": ""}})
	if f := sh.Rows[1].Fields; f["name"] != "=HYPERLINK(\"http://evil\")" ||
		!reflect.DeepEqual(f["tags"], []any{"rye", "dark; heavy"}) || f["price"] != -4.0 {
		t.Errorf("read back as %#v", f)
	}
}

func TestPicturesAreWrittenWhereTheyCanBeFetched(t *testing.T) {
	id := strings.Repeat("ab", 32)
	out := string(Write(event(), []collection.Record{{ID: "x", Fields: map[string]any{"title": "A", "image": id,
		"alt": "A loaf"}}}, WriteOptions{Picture: func(id string) string { return "https://crumb.example/media/" + id }}))
	if !strings.Contains(out, "https://crumb.example/media/"+id+",A loaf") {
		t.Errorf("%s", out)
	}
	plan := &Plan{Records: []collection.Record{{Fields: map[string]any{"image": "https://x.example/a.jpg", "alt": "A"}},
		{Fields: map[string]any{"image": id}}, {Fields: map[string]any{"image": "nowhere", "alt": "B"}}}, Lines: []int{2, 3, 4}}
	notes := plan.Fetch(Pictures(event()), func(raw, alt string) (string, error) {
		if raw == "nowhere" {
			return "", errors.New("not an address")
		}
		return strings.Repeat("c", 64), nil
	})
	if plan.Records[0].Fields["image"] != strings.Repeat("c", 64) || plan.Records[1].Fields["image"] != id ||
		plan.Records[2].Fields["image"] != nil || len(notes) != 1 || notes[0].Line != 4 {
		t.Errorf("%v %v", plan.Records, notes)
	}
}

func TestACalendarBecomesEvents(t *testing.T) {
	london, _ := time.LoadLocation("Europe/London")
	ics := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\n" +
		"BEGIN:VEVENT\r\nUID:rye@x\r\nSUMMARY:Rye night\r\nDTSTART:20261114T193000Z\r\nDTEND:20261115T000000Z\r\n" +
		"LOCATION:https://zoom.us/j/1\r\nURL:https://tickets.example/rye\r\nDESCRIPTION:<p>Bring <b>a loaf</b></p><p>Or two</p>\r\nEND:VEVENT\r\n" +
		"BEGIN:VEVENT\r\nUID:fair@x\r\nSUMMARY:Fair\r\nDTSTART;VALUE=DATE:20261205\r\nDTEND;VALUE=DATE:20261207\r\n" +
		"LOCATION:Market Square\\, Town\r\nSTATUS:CANCELLED\r\nEND:VEVENT\r\n" +
		"BEGIN:VEVENT\r\nUID:me@x\r\nSUMMARY:Dentist\r\nCLASS:PRIVATE\r\nDTSTART:20261116T090000Z\r\nEND:VEVENT\r\n" +
		"BEGIN:VEVENT\r\nUID:class@x\r\nSUMMARY:Yoga\r\nDTSTART;TZID=Europe/London:20261102T180000\r\n" +
		"DTEND;TZID=Europe/London:20261102T190000\r\nRRULE:FREQ=WEEKLY;COUNT=2\r\nEND:VEVENT\r\n" +
		"END:VCALENDAR\r\n"
	opts := CalendarOptions{Collection: "events", Type: event(), Zone: london,
		Now: time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)}
	rows, notes, err := FromCalendar([]byte(ics), opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 || !strings.Contains(strings.Join(notes, " "), "1 event(s) the calendar marks private") {
		t.Fatalf("%d rows, notes %v", len(rows), notes)
	}
	rye := rows[0].Fields
	for k, v := range map[string]any{"title": "Rye night", "date": "2026-11-14", "time": "19:30", "until": "00:00",
		"online": "https://zoom.us/j/1", "tickets": "https://tickets.example/rye", "summary": "Bring a loaf\nOr two"} {
		if rye[k] != v {
			t.Errorf("rye %s = %#v, want %#v", k, rye[k], v)
		}
	}
	if _, has := rye["end_date"]; has {
		t.Errorf("an evening ending at midnight was given a last day: %v", rye)
	}
	fair := rows[1].Fields
	if fair["date"] != "2026-12-05" || fair["end_date"] != "2026-12-06" || fair["status"] != "cancelled" ||
		fair["location"] != "Market Square, Town" || fair["time"] != nil {
		t.Errorf("fair %v", fair)
	}
	if rows[2].Suggest["slug"] != "yoga-2026-11-02" || rows[3].Fields["date"] != "2026-11-09" ||
		rows[3].Fields["time"] != "18:00" {
		t.Errorf("yoga %v %v %v", rows[2].Suggest, rows[3].Fields, rows[3].Suggest)
	}
	m := Merge{Collection: "events", Check: check(event()), Slug: "slug", Title: "title"}
	plan := m.Plan(rows)
	if plan.Refused() || plan.New != 4 {
		t.Fatalf("%s", plan.Summary())
	}
	if plan.Records[0].Fields["slug"] != "rye-night" || plan.Records[3].Fields["slug"] != "yoga-2026-11-09" {
		t.Errorf("slugs %v %v", plan.Records[0].Fields["slug"], plan.Records[3].Fields["slug"])
	}
	// Brought again, after someone gave the first a picture and changed
	// its page link: the same records, with those kept.
	m.Existing = plan.Records
	m.Existing[0].Fields["slug"], m.Existing[0].Fields["image"] = "rye", "pic"
	again := m.Plan(rows)
	if again.New != 0 || again.Updated != 4 || again.Records[0].Fields["slug"] != "rye" ||
		again.Records[0].Fields["image"] != "pic" {
		t.Errorf("%+v %v", again, again.Records[0].Fields)
	}
}

func FuzzRead(f *testing.F) {
	f.Add("name,price,added,tags\nRye,\"£1,250\",14/11/2026,a;b\n")
	f.Add("sep=;\nname;price\n\"x\"\"y\";1.250,5\n")
	f.Fuzz(func(t *testing.T, s string) {
		for _, typ := range []*schema.Type{product(), nil} {
			sh, err := Read([]byte(s), Options{Type: typ, Dates: DayFirst})
			if err != nil {
				continue
			}
			plan := Merge{Collection: "c", Key: "name", Slug: "", Check: nil}.Plan(sh.Rows)
			_ = Write(typ, plan.Records, WriteOptions{})
		}
	})
}
