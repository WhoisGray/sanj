package main

import (
	"archive/zip"
	"fmt"
	"os"
	"strings"
)

func writeXLSX(path string, cols []string, rows []map[string]string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	files := map[string]string{
		"[Content_Types].xml": `<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>`,
		"_rels/.rels": `<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>`,
		"xl/workbook.xml": `<?xml version="1.0" encoding="UTF-8"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="results" sheetId="1" r:id="rId1"/></sheets></workbook>`,
		"xl/_rels/workbook.xml.rels": `<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>`,
		"xl/worksheets/sheet1.xml": sheetXML(cols, rows),
	}
	order := []string{
		"[Content_Types].xml",
		"_rels/.rels",
		"xl/workbook.xml",
		"xl/_rels/workbook.xml.rels",
		"xl/worksheets/sheet1.xml",
	}
	for _, name := range order {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		if _, err := w.Write([]byte(files[name])); err != nil {
			return err
		}
	}
	return zw.Close()
}

func sheetXML(cols []string, rows []map[string]string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`)
	writeRow(&b, 1, cols)
	for i, row := range rows {
		vals := make([]string, len(cols))
		for c, col := range cols {
			vals[c] = row[col]
		}
		writeRow(&b, i+2, vals)
	}
	b.WriteString(`</sheetData></worksheet>`)
	return b.String()
}

func writeRow(b *strings.Builder, index int, vals []string) {
	fmt.Fprintf(b, `<row r="%d">`, index)
	for i, val := range vals {
		cell := fmt.Sprintf("%s%d", colName(i), index)
		fmt.Fprintf(b, `<c r="%s" t="inlineStr"><is><t>%s</t></is></c>`, cell, xmlEscape(val))
	}
	b.WriteString(`</row>`)
}

func colName(i int) string {
	n := i + 1
	var s string
	for n > 0 {
		n--
		s = string(rune('A'+n%26)) + s
		n /= 26
	}
	return s
}

func xmlEscape(s string) string {
	amp := "&" + "amp;"
	lt := "&" + "lt;"
	gt := "&" + "gt;"
	quot := "&" + "quot;"
	s = strings.ReplaceAll(s, "&", amp)
	s = strings.ReplaceAll(s, "<", lt)
	s = strings.ReplaceAll(s, ">", gt)
	return strings.ReplaceAll(s, "\"", quot)
}
