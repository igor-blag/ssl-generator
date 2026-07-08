package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
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

const (
	appVersion = "1.0"
	repoURL    = "https://github.com/igor-blag/ssl-generator"
)

var (
	oidINN  = asn1.ObjectIdentifier{1, 2, 643, 100, 4}
	oidOGRN = asn1.ObjectIdentifier{1, 2, 643, 100, 1}
)

var numericRegex = regexp.MustCompile(`^\d+$`)

type CertType string

const (
	CertOV CertType = "OV"
	CertDV CertType = "DV"
)

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
	stEntry.SetText("78 г. Санкт-Петербург")

	lEntry := widget.NewEntry()
	lEntry.SetText("г. Сестрорецк")

	streetEntry := widget.NewEntry()
	streetEntry.SetText("ул. Примерная, д. 1")

	innEntry := widget.NewEntry()
	innEntry.PlaceHolder = "10 цифр (обязательно для OV)"

	ogrnEntry := widget.NewEntry()
	ogrnEntry.PlaceHolder = "13 цифр (обязательно для OV)"

	oEntry.Hide()
	stEntry.Hide()
	lEntry.Hide()
	streetEntry.Hide()
	innEntry.Hide()
	ogrnEntry.Hide()

	ovFieldsWidgets := []fyne.CanvasObject{oEntry, stEntry, lEntry, streetEntry, innEntry, ogrnEntry}

	certType := CertOV
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
		var row fyne.CanvasObject
		delBtn := widget.NewButton("✕", func() {
			if row != nil {
				sanBox.Remove(row)
			}
			for i, sf := range sanFields {
				if sf == entry {
					sanFields = append(sanFields[:i], sanFields[i+1:]...)
					break
				}
			}
		})
		row = container.NewBorder(nil, nil, nil, delBtn, entry)
		sanBox.Add(row)
		return entry
	}

	addSanBtn := widget.NewButton("+ Добавить ещё", func() {
		sanFields = append(sanFields, addSanField(""))
	})

	setSANDefaults := func(ct CertType) {
		sanBox.RemoveAll()
		sanFields = nil
		c := cnEntry.Text
		if c == "" {
			c = "domain.ru"
		}
		if ct == CertDV {
			sanFields = append(sanFields, addSanField(c))
			addSanBtn.Hide()
		} else {
			sanFields = append(sanFields, addSanField(c))
			sanFields = append(sanFields, addSanField("www."+c))
			addSanBtn.Show()
		}
	}

	updateOVFields := func() {
		isOV := certType == CertOV
		for _, w := range ovFieldsWidgets {
			if isOV {
				w.Show()
			} else {
				w.Hide()
			}
		}
	}

	certTypeRadio := widget.NewRadioGroup([]string{"OV", "DV"}, func(s string) {
		if s == "DV" {
			certType = CertDV
		} else {
			certType = CertOV
		}
		updateOVFields()
		setSANDefaults(certType)
	})
	certTypeRadio.Horizontal = true
	certTypeRadio.SetSelected("OV")

	setSANDefaults(CertOV)

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
		ct := certType

		var errs []string
		if cn == "" {
			errs = append(errs, "CN (домен) обязателен для заполнения")
		}
		if ct == CertOV {
			if org == "" {
				errs = append(errs, "Для OV сертификата нужно указать организацию (O)")
			}
			if province == "" {
				errs = append(errs, "Для OV сертификата нужно указать регион (ST)")
			}
			if locality == "" {
				errs = append(errs, "Для OV сертификата нужно указать город (L)")
			}
			if street == "" {
				errs = append(errs, "Для OV сертификата нужно указать улицу (Street)")
			}
			if inn == "" {
				errs = append(errs, "Для OV сертификата нужно указать ИНН (10 цифр)")
			} else if len(inn) != 10 || !numericRegex.MatchString(inn) {
				errs = append(errs, "ИНН должен содержать ровно 10 цифр")
			}
			if ogrn == "" {
				errs = append(errs, "Для OV сертификата нужно указать ОГРН (13 цифр)")
			} else if len(ogrn) != 13 || !numericRegex.MatchString(ogrn) {
				errs = append(errs, "ОГРН должен содержать ровно 13 цифр")
			}
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
				if ct == CertDV && (strings.HasPrefix(v, "*.") || strings.HasPrefix(v, "*")) {
					errs = append(errs, "WildCard (*) запрещён для DV сертификата: "+v)
				}
				dnsNames = append(dnsNames, v)
			}
		}
		if len(dnsNames) == 0 {
			errs = append(errs, "Добавьте хотя бы одно DNS-имя в SAN")
		}
		if ct == CertDV && len(dnsNames) > 1 {
			errs = append(errs, "Для DV сертификата допустимо только одно DNS-имя")
		}
		if ct == CertDV && len(dnsNames) == 1 && dnsNames[0] != cn {
			errs = append(errs, "Для DV сертификата DNS-имя должно совпадать с CN")
		}
		if len(errs) > 0 {
			dialog.ShowError(fmt.Errorf("Ошибки:\n%s", strings.Join(errs, "\n")), w)
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

			var subject pkix.Name
			if ct == CertDV {
				subject = pkix.Name{
					CommonName: cn,
					Country:    []string{country},
				}
			} else {
				subject = pkix.Name{
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
				cnfContent := generateCNF(ct, cn, org, country, province, locality, street, inn, ogrn, dnsNames)
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
		widget.NewFormItem("Тип сертификата", certTypeRadio),
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

	aboutItem := fyne.NewMenuItem("О программе", func() {
		showAboutDialog(w)
	})
	helpMenu := fyne.NewMenu("Справка", aboutItem)
	mainMenu := fyne.NewMainMenu(helpMenu)
	w.SetMainMenu(mainMenu)

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

func generateCNF(ct CertType, cn, org, country, province, locality, street, inn, ogrn string, dnsNames []string) string {
	var b strings.Builder

	if ct == CertDV {
		b.WriteString("[req]\n")
		b.WriteString("distinguished_name = req_distinguished_name\n")
		b.WriteString("req_extensions = v3_req\n")
		b.WriteString("x509_extensions = v3_req\n")
		b.WriteString("prompt = no\n")
		b.WriteString("string_mask = utf8only\n")
		b.WriteString("utf8 = yes\n\n")
		b.WriteString("[req_distinguished_name]\n")
		fmt.Fprintf(&b, "CN = %s\n", cn)
		fmt.Fprintf(&b, "C = %s\n", country)
	} else {
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

type githubRelease struct {
	TagName string `json:"tag_name"`
}

func showAboutDialog(w fyne.Window) {
	versionLabel := widget.NewLabelWithStyle(
		fmt.Sprintf("Версия: %s", appVersion),
		fyne.TextAlignCenter, fyne.TextStyle{Bold: true},
	)
	platform := fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
	platformLabel := widget.NewLabel(fmt.Sprintf("Платформа: %s", platform))
	linkLabel := widget.NewLabel(repoURL)
	updateBtn := widget.NewButton("Проверить обновления", func() {
		checkForUpdates(w)
	})

	content := container.NewVBox(
		widget.NewLabelWithStyle("ssl-generator", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		versionLabel,
		platformLabel,
		linkLabel,
		widget.NewSeparator(),
		updateBtn,
	)

	dialog.ShowCustom("О программе", "Закрыть", content, w)
}

func checkForUpdates(w fyne.Window) {
	dlg := dialog.NewInformation("Проверка обновлений", "Проверка...", w)
	dlg.Show()

	go func() {
		apiURL := "https://api.github.com/repos/igor-blag/ssl-generator/releases/latest"
		client := &http.Client{}
		req, err := http.NewRequest("GET", apiURL, nil)
		if err != nil {
			dlg.Hide()
			dialog.ShowError(fmt.Errorf("Ошибка запроса: %v", err), w)
			return
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "ssl-generator/"+appVersion)

		resp, err := client.Do(req)
		if err != nil {
			dlg.Hide()
			dialog.ShowError(fmt.Errorf("Не удалось проверить обновления: %v\nПроверьте подключение к интернету", err), w)
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			dlg.Hide()
			dialog.ShowError(fmt.Errorf("Ошибка чтения ответа: %v", err), w)
			return
		}

		if resp.StatusCode == 404 {
			dlg.Hide()
			dialog.ShowInformation("Проверка обновлений",
				"Релизы не найдены. Это первая версия проекта.", w)
			return
		}
		if resp.StatusCode != 200 {
			dlg.Hide()
			dialog.ShowError(fmt.Errorf("Ошибка сервера: HTTP %d", resp.StatusCode), w)
			return
		}

		var release githubRelease
		if err := json.Unmarshal(body, &release); err != nil {
			dlg.Hide()
			dialog.ShowError(fmt.Errorf("Ошибка парсинга ответа: %v", err), w)
			return
		}

		dlg.Hide()
		latest := strings.TrimPrefix(release.TagName, "v")
		if latest != "" && compareVersions(latest, appVersion) > 0 {
			url := repoURL + "/releases/latest"
			dialog.ShowConfirm("Обновление доступно",
				fmt.Sprintf("Версия %s уже вышла!\n\nТекущая: %s\nНовая: %s\n\nПерейти на страницу релиза?",
					release.TagName, appVersion, latest),
				func(ok bool) {
					if ok {
						openURL(url)
					}
				}, w)
		} else {
			dialog.ShowInformation("Проверка обновлений",
				fmt.Sprintf("У вас актуальная версия (%s).", appVersion), w)
		}
	}()
}

func compareVersions(a, b string) int {
	are := strings.Split(a, ".")
	bre := strings.Split(b, ".")
	maxLen := len(are)
	if len(bre) > maxLen {
		maxLen = len(bre)
	}
	for i := 0; i < maxLen; i++ {
		var ai, bi int
		if i < len(are) {
			fmt.Sscanf(are[i], "%d", &ai)
		}
		if i < len(bre) {
			fmt.Sscanf(bre[i], "%d", &bi)
		}
		if ai > bi {
			return 1
		}
		if ai < bi {
			return -1
		}
	}
	return 0
}

func openURL(url string) {
	switch runtime.GOOS {
	case "darwin":
		exec.Command("open", url).Start()
	case "windows":
		exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		exec.Command("xdg-open", url).Start()
	}
}
