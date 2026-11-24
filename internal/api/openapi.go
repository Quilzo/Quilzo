// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
)

// The API's own description, as OpenAPI 3.1, at /api/v1/openapi.json: what
// a client generator, an integration platform or an agent reads to call
// this API without reading this source. The same for every server of a
// kind, and nothing in it about the content behind it, so it is served to
// anybody; every route it describes still needs a token. A test walks the
// routes registered below and fails on one this leaves out.
//
// And of the routes this server was started with (described), not of every
// route there is. The site serves no records and the admin no vector index,
// and both served the one description of everything, so half of what each
// described answered 404 "this server does not serve records" or "no vector
// index".

func schemaRef(name string) map[string]any {
	return map[string]any{"$ref": "#/components/schemas/" + name}
}

func jsonBody(schema map[string]any) map[string]any {
	return map[string]any{"content": map[string]any{"application/json": map[string]any{"schema": schema}}}
}

func answer(desc string, schema map[string]any) map[string]any {
	a := map[string]any{"description": desc}
	if schema != nil {
		a["content"] = map[string]any{"application/json": map[string]any{"schema": schema}}
	}
	return a
}

func param(name, in, desc string, required bool, schema map[string]any) map[string]any {
	return map[string]any{"name": name, "in": in, "description": desc, "required": required, "schema": schema}
}

var (
	str    = map[string]any{"type": "string"}
	posInt = map[string]any{"type": "integer", "minimum": 1}
	nonNeg = map[string]any{"type": "integer", "minimum": 0}
)

// errors are the answers every operation may give besides its own.
func errorsFor(codes ...string) map[string]any {
	out := map[string]any{}
	words := map[string]string{
		"400": "The request was malformed; the answer says what to fix.",
		"401": "No token, or one that is not valid.",
		"403": "The token's holder may not do this here.",
		"404": "There is no such thing, or the caller may not know it exists.",
		"405": "This server takes no writes here, and the answer says where they are taken; Allow names what it does take.",
		"409": "It changed since it was read: read it again, then write with its new ETag.",
		"412": "If-Match did not match the current ETag.",
		"413": "The body, or the query, is larger than this server reads.",
		"422": "The content does not satisfy its type; the answer says what it lacks and where the type is read.",
		"428": "A write without If-Match is refused.",
		"429": "Too many requests; Retry-After says when to try again.",
		"503": "Nothing is published yet, or the API is turned off for a while; Retry-After, when it is sent, says until when.",
	}
	for _, c := range codes {
		out[c] = answer(words[c], schemaRef("Error"))
	}
	return out
}

func op(summary, id string, params []any, body map[string]any, ok map[string]any, errs ...string) map[string]any {
	// 503 with the three every operation can meet, because the shield turns
	// the whole API off at once.
	o := map[string]any{"summary": summary, "operationId": id, "responses": errorsFor(append([]string{"401", "403", "429", "503"}, errs...)...)}
	if len(params) > 0 {
		o["parameters"] = params
	}
	if body != nil {
		o["requestBody"] = body
	}
	for code, a := range ok {
		o["responses"].(map[string]any)[code] = a
	}
	return o
}

// OpenAPI is the API's description.
func OpenAPI() map[string]any {
	paging := []any{
		param("limit", "query", "how many to return", false, posInt),
		param("offset", "query", "how many to skip", false, nonNeg),
	}
	name := param("name", "path", "the page's name, which may contain slashes", true, str)
	coll := param("collection", "path", "the collection's name", true, str)
	id := param("id", "path", "the record's id", true, str)
	ifMatch := param("If-Match", "header", "the ETag the write is based on", true, str)
	ifNone := param("If-None-Match", "header", "an ETag already held: answered 304 when it is still current", false, str)
	return map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":   "Quilzo API",
			"version": "1",
			"description": "Pages and records as published, and written where the server allows it. Every " +
				"answer carries an ETag, the content's hash; every write needs If-Match with the ETag it is based on, " +
				"so two writers never overwrite each other unseen. What a token may read or write is its holder's " +
				"permissions, the same as in the admin and on the command line.",
		},
		"servers":  []any{map[string]any{"url": "/"}},
		"security": []any{map[string]any{"bearer": []any{}}},
		"paths": map[string]any{
			"/api/v1/pages": map[string]any{
				"get": op("List pages", "listPages", append([]any{ifNone}, paging...), nil,
					map[string]any{"200": answer("A page of pages, and where the next is.", schemaRef("Listing")),
						"304": answer("Not modified.", nil)}, "400"),
			},
			"/api/v1/pages/{name}": map[string]any{
				"get": op("Read a page", "getPage", []any{name, ifNone}, nil,
					map[string]any{"200": answer("The page.", schemaRef("Page")), "304": answer("Not modified.", nil)}, "404"),
				"put": op("Write a page to the draft", "putPage", []any{name, ifMatch},
					jsonBody(map[string]any{"type": "object", "description": "the page's fields"}),
					map[string]any{"200": answer("Written; the new ETag is in the answer.", schemaRef("Page"))},
					"400", "404", "405", "409", "412", "413", "422", "428"),
			},
			"/api/v1/collections": map[string]any{
				"get": op("List collections", "listCollections", nil, nil,
					map[string]any{"200": answer("The collections the caller may read, with their sizes.", map[string]any{"type": "object"})}),
			},
			"/api/v1/records/{collection}": map[string]any{
				"get": op("List records", "listRecords", append([]any{coll,
					param("where", "query", "field:value, repeatable: records whose field equals the value", false, str),
					param("contains", "query", "field:text, repeatable: records whose field contains the text", false, str),
					param("sort", "query", "the field to sort by", false, str),
					param("order", "query", "asc or desc", false, map[string]any{"type": "string", "enum": []any{"asc", "desc"}}),
				}, paging...), nil, map[string]any{"200": answer("A page of records.", map[string]any{"type": "object"})}, "400", "404"),
				"post": op("Add a record", "addRecord", []any{coll}, jsonBody(map[string]any{"type": "object"}),
					map[string]any{"201": answer("Added, with its id and ETag.", map[string]any{"type": "object"})}, "400", "404", "405", "413", "422"),
			},
			"/api/v1/records/{collection}/{id}": map[string]any{
				"get": op("Read a record", "getRecord", []any{coll, id, ifNone}, nil,
					map[string]any{"200": answer("The record.", map[string]any{"type": "object"}), "304": answer("Not modified.", nil)}, "404"),
				"put": op("Replace a record", "putRecord", []any{coll, id, ifMatch}, jsonBody(map[string]any{"type": "object"}),
					map[string]any{"200": answer("Replaced.", map[string]any{"type": "object"})}, "400", "404", "405", "409", "412", "413", "422", "428"),
				"delete": op("Delete a record", "deleteRecord", []any{coll, id, ifMatch}, nil,
					map[string]any{"204": answer("Deleted.", nil)}, "404", "405", "409", "412", "428"),
			},
			"/api/v1/similar/{name}": map[string]any{
				"get": op("Pages like a page", "similarPages", []any{name, param("limit", "query", "how many", false, posInt)}, nil,
					map[string]any{"200": answer("The nearest published pages, nearest first.", map[string]any{"type": "object"})}, "400", "404"),
			},
			"/api/v1/search/vector": map[string]any{
				"get": op("Pages by meaning", "searchByMeaning", []any{param("q", "query", "what to look for, in plain words", true, str),
					param("limit", "query", "how many", false, posInt)}, nil,
					map[string]any{"200": answer("The nearest published pages, nearest first.", map[string]any{"type": "object"})}, "400", "404", "413"),
			},
			"/api/v1/replica/ref/{ref}": map[string]any{
				"get": op("A ref, for a replica", "replicaRef", []any{param("ref", "path", "live or draft", true, str)}, nil,
					map[string]any{"200": answer("The commit the ref names.", map[string]any{"type": "object"})}, "404"),
			},
			"/api/v1/replica/object/{id}": map[string]any{
				"get": op("An object, for a replica", "replicaObject", []any{param("id", "path", "the object's id", true, str)}, nil,
					// JSON, with the bytes in base64 beside the kind they
					// hash with (objectResponse). Described as the raw
					// bytes, which a client written from this could not
					// read.
					map[string]any{"200": answer("The object, whose kind and bytes hash to its id.", schemaRef("Object"))}, "404"),
			},
		},
		"components": map[string]any{
			"securitySchemes": map[string]any{"bearer": map[string]any{"type": "http", "scheme": "bearer",
				"description": "a token from quilzo token issue, or the admin session for a same-origin request in the admin"}},
			"schemas": map[string]any{
				"Error": map[string]any{"type": "object", "required": []any{"error"}, "properties": map[string]any{
					"error": str, "detail": str, "fix": map[string]any{"type": "string", "description": "what would resolve it"}}},
				"Page": map[string]any{"type": "object", "required": []any{"name", "fields", "etag"}, "properties": map[string]any{
					"name": str, "fields": map[string]any{"type": "object"}, "etag": str, "type": str}},
				"Object": map[string]any{"type": "object", "required": []any{"id", "kind", "payload"}, "properties": map[string]any{
					"id": str, "kind": map[string]any{"type": "string", "description": "blob, tree or commit"},
					"payload": map[string]any{"type": "string", "contentEncoding": "base64",
						"description": "the object's bytes, in standard base64"}}},
				"Listing": map[string]any{"type": "object", "required": []any{"pages", "total", "offset", "limit", "commit"},
					"properties": map[string]any{"pages": map[string]any{"type": "array", "items": schemaRef("Page")},
						"total": nonNeg, "offset": nonNeg, "limit": posInt, "next": str, "commit": str}},
			},
		},
	}
}

// described is the description of what this server serves: OpenAPI less the
// routes it was started without, which answer 404 here.
func (s *Server) described() map[string]any {
	doc := OpenAPI()
	paths := doc["paths"].(map[string]any)
	if s.Records == nil || s.Records.Tree == nil {
		delete(paths, "/api/v1/collections")
		delete(paths, "/api/v1/records/{collection}")
		delete(paths, "/api/v1/records/{collection}/{id}")
	}
	if s.Vectors == nil || s.Tokenise == nil {
		delete(paths, "/api/v1/similar/{name}")
		delete(paths, "/api/v1/search/vector")
	}
	return doc
}

func (s *Server) openAPI(w http.ResponseWriter, r *http.Request) {
	if !readMethod(r) {
		s.notAllowed(w, r, Error{Error: "GET only"})
		return
	}
	b, _ := json.MarshalIndent(s.described(), "", "  ")
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(b)
}
