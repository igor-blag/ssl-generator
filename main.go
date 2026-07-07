package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"golang.org/x/net/idna"
)

var (
	oidINN  = asn1.ObjectIdentifier{1, 2, 643, 100, 4}
	oidOGRN = asn1.ObjectIdentifier{1, 2, 643, 100, 1}
)

var numericRegex = regexp.MustCompile(`^\d+$`)

func main() {
	a := app.New()
	w := a.NewWindow("Генератор CSR / RSA-ключа")
	w.Resize(fyne.NewSize(640, 720))

	defaultCN := "sch123.ru"
	defaultOrg := "ГБОУ СОШ № 123 Курортного района Санкт-Петербурга"

	cnEntry := widget.NewEntry()
	cnEntry.SetText(defaultCN)

	oEntry := widget.NewEntry()
	oEntry.SetText(defaultOrg)

	cEntry := widget.NewEntry()
	cEntry.SetText("RU")

	stEntry := widget.NewEntry()
	stEntry.SetText("г. Санкт-Петербург")

	lEntry := widget.NewEntry()
	lEntry.SetText("г. Сестрорецк")

	streetEntry := widget.NewEntry()
	streetEntry.SetText("ул. Примерная, д. 1")

	innEntry := widget.NewEntry()
	innEntry.PlaceHolder = "10 цифр, опционально"

	ogrnEntry := widget.NewEntry()
	ogrnEntry.PlaceHolder = "13 цифр, опционально"

	keySizeSelect := widget.NewSelect([]string{"2048", "4096"}, nil)
	keySizeSelect.SetSelected("2048")

	sanFields := []*widget.Entry{}
	sanBox := container.NewVBox()

	addSanField := func(value string) *widget.Entry {
		entry := widget.NewEntry()
		entry.PlaceHolder = "domain.ru"
		if value != "" {
			entry.SetText(value)
		}
		sanBox.Add(entry)
		return entry
	}

	sanFields = append(sanFields, addSanField(defaultCN))
	sanFields = append(sanFields, addSanField("www."+defaultCN))

	addSanBtn := widget.NewButton("+ Добавить ещё", func() {
		sanFields = append(sanFields, addSanField(""))
	})

	sanScroll := container.NewVBox(
		sanBox,
		addSanBtn,
	)

	baseNameEntry := widget.NewEntry()
	baseNameEntry.SetText(domainToFilename(defaultCN))

	cnEntry.OnChanged = func(s string) {
		if baseNameEntry.Text == domainToFilename(defaultCN) || baseNameEntry.Text == "" {
			baseNameEntry.SetText(domainToFilename(s))
		}
	}

	dirEntry := widget.NewEntry()
	homeDir, _ := os.UserHomeDir()
	dirEntry.SetText(filepath.Join(homeDir, "Desktop"))

	browseBtn := widget.NewButton("Обзор...", func() {
		dialog.ShowFolderOpen(func(uri fyne.ListableURI, err error) {
			if err == nil && uri != nil {
				dirEntry.SetText(uri.Path())
			}
		}, w)
	})

	cnfCheck := widget.NewCheck("Создать .cnf файл (необязательно)", nil)

	var generateBtn *widget.Button
	generateBtn = widget.NewButton("Сгенерировать CSR", func() {
		cn := strings.TrimSpace(cnEntry.Text)
		org := strings.TrimSpace(oEntry.Text)
		country := strings.TrimSpace(cEntry.Text)
		province := strings.TrimSpace(stEntry.Text)
		locality := strings.TrimSpace(lEntry.Text)
		street := strings.TrimSpace(streetEntry.Text)
		inn := strings.TrimSpace(innEntry.Text)
		ogrn := strings.TrimSpace(ogrnEntry.Text)
		baseName := strings.TrimSpace(baseNameEntry.Text)
		dir := strings.TrimSpace(dirEntry.Text)

		var errs []string
		if cn == "" {
			errs = append(errs, "CN (домен) обязателен для заполнения")
		}
		if inn != "" && (len(inn) != 10 || !numericRegex.MatchString(inn)) {
			errs = append(errs, "ИНН должен содержать ровно 10 цифр (или оставьте поле пустым)")
		}
		if ogrn != "" && (len(ogrn) != 13 || !numericRegex.MatchString(ogrn)) {
			errs = append(errs, "ОГРН должен содержать ровно 13 цифр (или оставьте поле пустым)")
		}
		if baseName == "" {
			errs = append(errs, "Имя файла обязательно")
		}
		if dir == "" {
			errs = append(errs, "Выберите папку для сохранения")
		}
		if len(errs) > 0 {
			dialog.ShowError(fmt.Errorf("Ошибки:\n%s", strings.Join(errs, "\n")), w)
			return
		}

		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			dialog.ShowError(fmt.Errorf("Папка '%s' не найдена", dir), w)
			return
		}

		var dnsNames []string
		for _, entry := range sanFields {
			v := strings.TrimSpace(entry.Text)
			if v != "" {
				dnsNames = append(dnsNames, v)
			}
		}
		if len(dnsNames) == 0 {
			dialog.ShowError(fmt.Errorf("Добавьте хотя бы одно DNS-имя в SAN"), w)
			return
		}

		keyPath := filepath.Join(dir, baseName+".key")
		csrPath := filepath.Join(dir, baseName+".csr")
		cnfPath := filepath.Join(dir, baseName+".cnf")

		keySize := 2048
		if keySizeSelect.Selected == "4096" {
			keySize = 4096
		}

		var existingFiles []string
		for _, p := range []string{keyPath, csrPath} {
			if _, err := os.Stat(p); err == nil {
				existingFiles = append(existingFiles, filepath.Base(p))
			}
		}
		if cnfCheck.Checked {
			if _, err := os.Stat(cnfPath); err == nil {
				existingFiles = append(existingFiles, filepath.Base(cnfPath))
			}
		}

		runGeneration := func() {
			generateBtn.Disable()
			generateBtn.SetText("Генерация...")

			subject := pkix.Name{
				CommonName:    cn,
				Organization:  []string{org},
				Country:       []string{country},
				Province:      []string{province},
				Locality:      []string{locality},
				StreetAddress: []string{street},
			}
			if inn != "" || ogrn != "" {
				var extra []pkix.AttributeTypeAndValue
				if inn != "" {
					extra = append(extra, pkix.AttributeTypeAndValue{Type: oidINN, Value: inn})
				}
				if ogrn != "" {
					extra = append(extra, pkix.AttributeTypeAndValue{Type: oidOGRN, Value: ogrn})
				}
				subject.ExtraNames = extra
			}

			key, err := rsa.GenerateKey(rand.Reader, keySize)
			if err != nil {
				dialog.ShowError(fmt.Errorf("Ошибка генерации ключа: %v", err), w)
				generateBtn.Enable()
				generateBtn.SetText("Сгенерировать CSR")
				return
			}

			csrDER, err := createCSR(key, subject, dnsNames)
			if err != nil {
				dialog.ShowError(fmt.Errorf("Ошибка создания CSR: %v", err), w)
				generateBtn.Enable()
				generateBtn.SetText("Сгенерировать CSR")
				return
			}

			if err := savePEMFile(keyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key)); err != nil {
				dialog.ShowError(fmt.Errorf("Ошибка сохранения ключа: %v", err), w)
				generateBtn.Enable()
				generateBtn.SetText("Сгенерировать CSR")
				return
			}

			if err := savePEMFile(csrPath, "CERTIFICATE REQUEST", csrDER); err != nil {
				dialog.ShowError(fmt.Errorf("Ошибка сохранения CSR: %v", err), w)
				generateBtn.Enable()
				generateBtn.SetText("Сгенерировать CSR")
				return
			}

			if cnfCheck.Checked {
				cnfContent := generateCNF(cn, org, country, province, locality, street, inn, ogrn, dnsNames)
				if err := os.WriteFile(cnfPath, []byte(cnfContent), 0644); err != nil {
					dialog.ShowError(fmt.Errorf("Ошибка сохранения CNF: %v", err), w)
					generateBtn.Enable()
					generateBtn.SetText("Сгенерировать CSR")
					return
				}
			}

			generateBtn.Enable()
			generateBtn.SetText("Сгенерировать CSR")

			msg := fmt.Sprintf("Ключ: %s\nCSR: %s", filepath.Base(keyPath), filepath.Base(csrPath))
			if cnfCheck.Checked {
				msg += "\nCNF: " + filepath.Base(cnfPath)
			}
			dialog.ShowInformation("Готово", msg, w)

			openFolder(dir)
		}

		if len(existingFiles) > 0 {
			dialog.ShowConfirm("Файлы уже существуют",
				fmt.Sprintf("Будут перезаписаны:\n%s\n\nПродолжить?", strings.Join(existingFiles, "\n")),
				func(ok bool) {
					if ok {
						runGeneration()
					}
				}, w)
		} else {
			runGeneration()
		}
	})

	form := widget.NewForm(
		widget.NewFormItem("CN (домен)", cnEntry),
		widget.NewFormItem("Организация (O)", oEntry),
		widget.NewFormItem("Страна (C)", cEntry),
		widget.NewFormItem("Регион (ST)", stEntry),
		widget.NewFormItem("Город (L)", lEntry),
		widget.NewFormItem("Улица (Street)", streetEntry),
		widget.NewFormItem("ИНН", innEntry),
		widget.NewFormItem("ОГРН", ogrnEntry),
		widget.NewFormItem("Размер ключа", keySizeSelect),
		widget.NewFormItem("DNS-имена (SANs)", sanScroll),
		widget.NewFormItem("Имя файла", baseNameEntry),
	)

	dirLabel := widget.NewLabelWithStyle("Папка для сохранения:",
		fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	dirRow := container.NewBorder(nil, nil, nil, browseBtn, dirEntry)

	content := container.NewVBox(
		form,
		dirLabel,
		dirRow,
		cnfCheck,
		widget.NewSeparator(),
		container.NewHBox(
			layout.NewSpacer(),
			generateBtn,
			layout.NewSpacer(),
		),
	)

	w.SetContent(container.NewScroll(content))
	w.ShowAndRun()
}

func createCSR(key *rsa.PrivateKey, subject pkix.Name, dnsNames []string) ([]byte, error) {
	var exts []pkix.Extension

	kuBits := asn1.BitString{Bytes: []byte{0x80 | 0x20 | 0x08}, BitLength: 5}
	kuValue, err := asn1.Marshal(kuBits)
	if err != nil {
		return nil, fmt.Errorf("keyUsage: %v", err)
	}
	exts = append(exts, pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 15},
		Critical: true,
		Value:    kuValue,
	})

	ekuOIDs := []asn1.ObjectIdentifier{
		{1, 3, 6, 1, 5, 5, 7, 3, 1},
		{1, 3, 6, 1, 5, 5, 7, 3, 2},
	}
	ekuValue, err := asn1.Marshal(ekuOIDs)
	if err != nil {
		return nil, fmt.Errorf("extKeyUsage: %v", err)
	}
	exts = append(exts, pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 37},
		Critical: false,
		Value:    ekuValue,
	})

	template := &x509.CertificateRequest{
		Subject:            subject,
		DNSNames:           dnsNames,
		ExtraExtensions:    exts,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	return x509.CreateCertificateRequest(rand.Reader, template, key)
}

func savePEMFile(path, blockType string, derBytes []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return pem.Encode(f, &pem.Block{
		Type:  blockType,
		Bytes: derBytes,
	})
}

func domainToFilename(s string) string {
	ascii, err := idna.ToASCII(s)
	if err == nil {
		s = ascii
	}
	s = strings.NewReplacer(
		".", "-",
		"/", "-", "\\", "-", ":", "-", "*", "-",
		"?", "-", "\"", "-", "<", "-", ">", "-", "|", "-",
	).Replace(s)
	s = strings.TrimSuffix(s, "-")
	return s
}

func generateCNF(cn, org, country, province, locality, street, inn, ogrn string, dnsNames []string) string {
	var b strings.Builder

	b.WriteString("openssl_conf = openssl_init\n\n")
	b.WriteString("[openssl_init]\n")
	b.WriteString("oid_section = new_oids\n\n")
	b.WriteString("[new_oids]\n")
	b.WriteString("INNLE = 1.2.643.100.4\n")
	b.WriteString("OGRN = 1.2.643.100.1\n\n")
	b.WriteString("[req]\n")
	b.WriteString("distinguished_name = req_distinguished_name\n")
	b.WriteString("req_extensions = v3_req\n")
	b.WriteString("x509_extensions = v3_req\n")
	b.WriteString("prompt = no\n")
	b.WriteString("string_mask = utf8only\n")
	b.WriteString("utf8 = yes\n\n")
	b.WriteString("[req_distinguished_name]\n")
	fmt.Fprintf(&b, "CN = %s\n", cn)
	if org != "" {
		fmt.Fprintf(&b, "O = %s\n", org)
	}
	fmt.Fprintf(&b, "C = %s\n", country)
	if province != "" {
		fmt.Fprintf(&b, "ST = %s\n", province)
	}
	if locality != "" {
		fmt.Fprintf(&b, "L = %s\n", locality)
	}
	if street != "" {
		fmt.Fprintf(&b, "streetAddress = %s\n", street)
	}
	if inn != "" {
		fmt.Fprintf(&b, "INNLE = %s\n", inn)
	}
	if ogrn != "" {
		fmt.Fprintf(&b, "OGRN = %s\n", ogrn)
	}
	b.WriteString("\n[v3_req]\n")
	b.WriteString("keyUsage = digitalSignature, keyEncipherment, keyAgreement\n")
	b.WriteString("extendedKeyUsage = serverAuth, clientAuth\n")
	if len(dnsNames) > 0 {
		sans := make([]string, len(dnsNames))
		for i, d := range dnsNames {
			sans[i] = "DNS:" + d
		}
		fmt.Fprintf(&b, "subjectAltName = %s\n", strings.Join(sans, ", "))
	}

	return b.String()
}

func openFolder(path string) {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
		args = []string{path}
	case "windows":
		cmd = "explorer"
		args = []string{path}
	default:
		cmd = "xdg-open"
		args = []string{path}
	}
	exec.Command(cmd, args...).Start()
}
