package app

import (
    "encoding/base64"
    "fmt"
    "html/template"
    "net/http"
    "os"
    "path/filepath"
    "strings"

)

func SignInPageHandler(w http.ResponseWriter, r *http.Request) {
    tmplPath := "pkg/app/sign_in.html"
    tmpl, err := template.ParseFiles(tmplPath)
    if err != nil {
        http.Error(w, "Unable to load template", http.StatusInternalServerError)
        return
    }

    logoPath := os.Getenv("LOGO_PATH")
    logoData, err := loadCustomLogo(logoPath)
    if err != nil {
        logoData = ""
    }

    brandName := os.Getenv("BRAND_NAME")

    data := struct {
        BrandName   string
        Logo        template.HTML
        ErrorMessage string
    }{
        BrandName:   brandName,
        Logo:        template.HTML(logoData),
        ErrorMessage: "",
    }

    if r.Method == http.MethodPost {
        username := r.FormValue("username")
        password := r.FormValue("password")

        if username == "admin" && password == "password" {
            http.Redirect(w, r, "/welcome", http.StatusSeeOther)
            return
        } else {
            data.ErrorMessage = "Invalid credentials"
        }
    }

    err = tmpl.Execute(w, data)
    if err != nil {
        http.Error(w, "Unable to execute template", http.StatusInternalServerError)
    }
}

func loadCustomLogo(logoPath string) (string, error) {
    if logoPath == "" {
        return "", nil
    }

    if logoPath == "-" {
        return "", nil
    }

    if strings.HasPrefix(logoPath, "https://") {
        return fmt.Sprintf("<img src=\"%s\" alt=\"Logo\" />", logoPath), nil
    }

    logoData, err := os.ReadFile(logoPath)
    if err != nil {
        return "", fmt.Errorf("could not read logo file: %v", err)
    }

    extension := strings.ToLower(filepath.Ext(logoPath))
    switch extension {
    case ".svg":
        return string(logoData), nil
    case ".jpg", ".jpeg":
        return encodeImg(logoData, "jpeg"), nil
    case ".png":
        return encodeImg(logoData, "png"), nil
    case ".ico":
        return encodeImg(logoData, "x-icon"), nil
    default:
        return "", fmt.Errorf("unknown extension: %q, supported extensions are .svg, .jpg, .jpeg, .png, and .ico", extension)
    }
}

func encodeImg(data []byte, format string) string {
    b64Data := base64.StdEncoding.EncodeToString(data)
    return fmt.Sprintf("<img src=\"data:image/%s;base64,%s\" alt=\"Logo\" />", format, b64Data)
}