package report

import (
	"fmt"
	"os"
	"time"

	"github.com/xuri/excelize/v2"

	"github.com/wsearles/cyber_news_monitor/go/internal/models"
)

var xlsxHeaders = []string{"Title", "Categories", "CVEs", "Source Feed", "Published (UTC)", "Link", "First Seen (UTC)"}
var xlsxColumnWidths = []float64{70, 30, 22, 24, 18, 70, 18}

const sheetName = "Cyber News"

// PrependXLSX adds new items as rows just below the header, pushing
// previously saved rows down -- so the file always reads newest-first.
// Mirrors prepend_to_xlsx() in the Python script.
func PrependXLSX(items []models.Item, path string) error {
	if len(items) == 0 {
		return nil
	}

	var f *excelize.File
	if _, err := os.Stat(path); err == nil {
		f, err = excelize.OpenFile(path)
		if err != nil {
			return err
		}
	} else {
		f = excelize.NewFile()
		f.SetSheetName("Sheet1", sheetName)
		if err := f.SetSheetRow(sheetName, "A1", &xlsxHeaders); err != nil {
			return err
		}
		boldFont, err := f.NewStyle(&excelize.Style{Font: &excelize.Font{Family: "Arial", Bold: true}})
		if err != nil {
			return err
		}
		if err := f.SetRowStyle(sheetName, 1, 1, boldFont); err != nil {
			return err
		}
		if err := f.SetPanes(sheetName, &excelize.Panes{Freeze: true, Split: false, XSplit: 0, YSplit: 1,
			TopLeftCell: "A2", ActivePane: "bottomLeft"}); err != nil {
			return err
		}
		for i, width := range xlsxColumnWidths {
			col, _ := excelize.ColumnNumberToName(i + 1)
			if err := f.SetColWidth(sheetName, col, col, width); err != nil {
				return err
			}
		}
	}
	defer f.Close()

	if err := f.InsertRows(sheetName, 2, len(items)); err != nil {
		return err
	}

	plainFont, err := f.NewStyle(&excelize.Style{Font: &excelize.Font{Family: "Arial"}})
	if err != nil {
		return err
	}
	linkFont, err := f.NewStyle(&excelize.Style{Font: &excelize.Font{Family: "Arial", Color: "0563C1", Underline: "single"}})
	if err != nil {
		return err
	}

	nowStr := time.Now().UTC().Format("2006-01-02 15:04")
	for offset, it := range items {
		row := 2 + offset
		published := ""
		if it.Published != nil {
			published = it.Published.Format("2006-01-02 15:04")
		}
		categories := "Uncategorized"
		if len(it.Categories) > 0 {
			categories = joinComma(it.Categories)
		}
		values := []interface{}{it.Title, categories, joinComma(it.CVEs), it.Feed, published, it.Link, nowStr}
		cell, _ := excelize.CoordinatesToCellName(1, row)
		if err := f.SetSheetRow(sheetName, cell, &values); err != nil {
			return err
		}
		if err := f.SetRowStyle(sheetName, row, row, plainFont); err != nil {
			return err
		}
		linkCell, _ := excelize.CoordinatesToCellName(6, row)
		if err := f.SetCellHyperLink(sheetName, linkCell, it.Link, "External"); err != nil {
			return err
		}
		if err := f.SetCellStyle(sheetName, linkCell, linkCell, linkFont); err != nil {
			return err
		}
	}

	if err := f.SaveAs(path); err != nil {
		return fmt.Errorf("saving %s: %w", path, err)
	}
	return nil
}
