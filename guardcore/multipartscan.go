package guardcore

// Line-based multipart scanner mirroring the extracted-value semantics of
// Python's email feedparser for multipart/form-data bodies
// (guard_core/_utils/body_form_scan._multipart_text_parts):
//
//   - preamble lines before the opening boundary are discarded, epilogue
//     after the final boundary is discarded;
//   - part headers keep their raw name case and wire order; a folded
//     continuation line is appended to the previous value with its original
//     line break preserved (compat32 keeps the raw fold);
//   - the first colonless line inside a part ends the header block and that
//     line and everything after it up to the next boundary is the payload
//     (MissingHeaderBodySeparatorDefect);
//   - the line terminator preceding a boundary line belongs to the delimiter,
//     everything else (including bare newlines) stays in the payload;
//   - a part whose Content-Type is multipart with a boundary parameter is a
//     container: its leaf parts are walked in place (message.walk), the
//     container itself produces no entries; a container without a boundary is
//     an ordinary leaf.
//
// No closing boundary is tolerated: the part parsed so far is kept, matching
// the email parser's CloseBoundaryNotFoundDefect behavior. The scanner is
// line-based over the already-capped body string and allocates part payloads
// as byte slices of it.

import "strings"

type mimeHeaderEntry struct {
	name  string
	value string
}

type multipartPart struct {
	headers []mimeHeaderEntry
	payload []byte
}

// parseMultipartParts splits a multipart body into its leaf parts (nested
// multipart containers expanded in place). An empty boundary yields no parts,
// which routes the caller to the whole-body blob fallback like the Python
// is_multipart() == False path.
func parseMultipartParts(body, boundary string) []multipartPart {
	if boundary == "" {
		return nil
	}
	return parseMultipartLevel(body, boundary)
}

func parseMultipartLevel(body, boundary string) []multipartPart {
	delim := "--" + boundary
	finalMark := delim + "--"
	pos := 0

	// Preamble: skip lines until the opening boundary (or the final
	// boundary, which means zero parts).
	for pos <= len(body) {
		lineStart, lineEnd, next := nextLine(body, pos)
		bare := trimCRAndPadding(body[lineStart:lineEnd])
		if bare == delim {
			pos = next
			break
		}
		if strings.HasPrefix(bare, finalMark) {
			return nil
		}
		pos = next
	}

	var parts []multipartPart
	for pos <= len(body) {
		headers, payload, next, closed, wasFinal := readPart(body, pos, delim, finalMark)
		parts = appendMultipartLeafOrContainer(parts, headers, payload)
		if !closed || wasFinal {
			// Missing closing boundary (payload ran to the end of the
			// input, CloseBoundaryNotFoundDefect) or the multipart body
			// was closed: any epilogue is discarded.
			return parts
		}
		pos = next
	}
	return parts
}

// readPart reads one part (headers plus payload) starting at pos. It reports
// whether a boundary line terminated the part (closed) and whether that
// boundary was the final one; a missing closing boundary ends the multipart
// body with the payload running to the end of the input.
func readPart(body string, pos int, delim, finalMark string) (headers []mimeHeaderEntry, payload []byte, next int, closed bool, wasFinal bool) {
	inHeaders := true
	payloadStart := -1
	for pos <= len(body) {
		lineStart, lineEnd, lineNext := nextLine(body, pos)
		raw := body[lineStart:lineEnd]
		content := trimCRAndPadding(raw)
		if inHeaders {
			switch {
			case content == "":
				// Blank line: headers end, payload starts after it.
				inHeaders = false
				payloadStart = lineNext
			case len(headers) > 0 && (content[0] == ' ' || content[0] == '\t'):
				// Folded continuation: keep the raw break and the line.
				br := "\n"
				if strings.HasSuffix(raw, "\r") {
					br = "\r\n"
				}
				prev := &headers[len(headers)-1]
				prev.value += br + content
			default:
				idx := strings.IndexByte(content, ':')
				if idx < 0 {
					// Colonless line: the header block ends and the line
					// itself opens the payload (compat32 defect behavior).
					inHeaders = false
					payloadStart = lineStart
					break
				}
				headers = append(headers, mimeHeaderEntry{
					name:  content[:idx],
					value: strings.TrimLeft(content[idx+1:], " \t"),
				})
			}
			pos = lineNext
			continue
		}
		if content == delim || strings.HasPrefix(content, finalMark) {
			return headers, payloadSlice(body, payloadStart, lineStart), lineNext, true, strings.HasPrefix(content, finalMark)
		}
		pos = lineNext
	}
	// No closing boundary: the payload runs to the end of the body.
	if payloadStart < 0 {
		payloadStart = len(body)
	}
	return headers, []byte(body[payloadStart:]), len(body) + 1, false, false
}

// payloadSlice extracts the payload bytes between payloadStart and the start
// of the boundary line; the terminator immediately before the boundary line
// belongs to the delimiter, not the payload.
func payloadSlice(body string, payloadStart, boundaryLineStart int) []byte {
	if payloadStart < 0 {
		payloadStart = boundaryLineStart
	}
	if boundaryLineStart <= payloadStart {
		return []byte{}
	}
	end := boundaryLineStart
	if end > payloadStart && body[end-1] == '\n' {
		end--
		if end > payloadStart && body[end-1] == '\r' {
			end--
		}
	}
	if end < payloadStart {
		end = payloadStart
	}
	return []byte(body[payloadStart:end])
}

// trimCRAndPadding strips the trailing CR and transport padding (trailing
// spaces and tabs) the boundary comparison ignores.
func trimCRAndPadding(line string) string {
	line = strings.TrimSuffix(line, "\r")
	return strings.TrimRight(line, " \t")
}

func nextLine(body string, pos int) (lineStart, lineEnd, next int) {
	lineStart = pos
	idx := strings.IndexByte(body[pos:], '\n')
	if idx < 0 {
		return lineStart, len(body), len(body) + 1
	}
	return lineStart, pos + idx, pos + idx + 1
}

// appendMultipartLeafOrContainer either expands a nested multipart container
// (message.walk descends; the container itself produces no entries) or
// appends the part as a leaf.
func appendMultipartLeafOrContainer(parts []multipartPart, headers []mimeHeaderEntry, payload []byte) []multipartPart {
	mainType, params := parseMediaTypeParams(firstHeaderValueOrEmpty(headers, "content-type"))
	if maintypeIsMultipart(mainType) && params["boundary"] != "" {
		return append(parts, parseMultipartLevel(string(payload), params["boundary"])...)
	}
	return append(parts, multipartPart{headers: headers, payload: payload})
}

// maintypeIsMultipart mirrors get_content_maintype() == "multipart": the part
// of the content type before the "/".
func maintypeIsMultipart(contentType string) bool {
	mainType, _, _ := strings.Cut(contentType, "/")
	return mainType == "multipart"
}

func firstHeaderValueOrEmpty(headers []mimeHeaderEntry, lowerName string) string {
	v, _ := firstHeaderValue(headers, lowerName)
	return v
}
