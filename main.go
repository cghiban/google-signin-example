package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"text/template"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/mendsley/gojwk"
)

const (
	clientID     = "....."
	clientSecret = "..."
)

type Claims struct {
	jwt.StandardClaims
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	FamilyName    string `json:"family_name"`
	GivenName     string `json:"given_name"`
	Picture       string `json:"picture"`
}

var T *template.Template

func index(rw http.ResponseWriter, r *http.Request) {
	uri := r.URL.Path
	log.Println("path:", uri)
	data := struct{ ClientID string }{
		ClientID: clientID,
	}
	rw.Header().Add("Cache-Control", "no-cache")
	if err := T.ExecuteTemplate(rw, "index.gohtml", data); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}
}

func login(rw http.ResponseWriter, r *http.Request) {
	uri := r.URL.Path
	log.Println("path:", uri)

	r.ParseForm()

	credential := r.Form.Get("credential")
	csrf_token_cookie := ""
	csrf_token_post := ""
	csrf_cookie, err := r.Cookie("g_csrf_token")
	if err == nil {
		fmt.Printf("cookie: %+v", csrf_cookie)
		csrf_token_cookie = csrf_cookie.Value
		fmt.Println("got POST csrf token:", csrf_token_cookie)
	}

	//if csrf_token == "" {
	csrf_token_post = r.Form.Get("g_csrf_token")
	fmt.Println("got POST csrf token:", csrf_token_post)
	//}

	fmt.Println(r.Header)
	for k, v := range r.Header {
		fmt.Printf(" ** %s\t%v\n", k, v)
	}

	fmt.Println("csrf_token_cookie: ", csrf_token_cookie)
	fmt.Println("csrf_token_post: ", csrf_token_post)
	fmt.Println("credential: ", credential)

	//ctx := r.Context()

	//myToken := strings.Replace(r.Header.Get("Authorization"), "Bearer ", "", 1)

	var claims Claims

	token, err := jwt.ParseWithClaims(credential, &claims, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		fmt.Printf("token: %+v\n", token)
		return myLookupKey(token.Header["kid"].(string))
	})
	if err != nil {
		fmt.Printf("%v\n", err)
		fmt.Fprintf(rw, "not ok: %s", err.Error())
		return
	}

	fmt.Println("--------------------")
	fmt.Printf("claims: %+v\n", claims)
	fmt.Printf("claims.Audience: %+v\n", claims.Audience)
	fmt.Printf("tocken.Valid: %+v\n", token.Valid)

	//fmt.Fprintf(rw, "Hello %s", claims.Name)
	data := struct {
		Name string
		OK   bool
	}{
		Name: claims.Name,
		OK:   token.Valid,
	}
	if err := T.ExecuteTemplate(rw, "login.gohtml", data); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}

}

func myLookupKey(kid string) (interface{}, error) {
	fmt.Printf("Kid : %v\n", kid)
	var keys struct{ Keys []gojwk.Key }
	parseJSONFromURL("https://www.googleapis.com/oauth2/v3/certs", &keys)
	for _, key := range keys.Keys {
		if key.Kid == kid {
			fmt.Printf("Key : %v\n", key)
			return key.DecodePublicKey()
		}
	}
	return nil, fmt.Errorf("Key not found")
}

func parseJSONFromURL(url string, v interface{}) {
	//resp, err := urlfetch.Client(ctx).Get(url)
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("error fetching JSON: ", err)
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	json.Unmarshal(body, v)
}

func main() {
	l := log.New(os.Stdout, "testing google sign in", log.LstdFlags)

	l.Println("about to start server")

	funcMap := template.FuncMap{
		"dateISOish": func(t time.Time) string { return t.Format("2006-01-02 3:04p") },
	}
	T = template.Must(template.New("tmpls").Funcs(funcMap).ParseGlob("var/templates/*.gohtml"))

	sm := mux.NewRouter()

	sm.HandleFunc("/", index)
	sm.HandleFunc("/login", login).Methods("POST")
	sm.Handle("/favicon.ico", http.NotFoundHandler())
	//sm.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("var/static/"))))

	s := &http.Server{
		Addr:         ":8080",
		Handler:      sm,
		IdleTimeout:  60 * time.Second,
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
	}

	// https://rafallorenz.com/go/handle-signals-to-graceful-shutdown-http-server/
	go func() {
		err := s.ListenAndServe()
		if err != nil {
			l.Fatalln(err)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		syscall.SIGHUP)

	sig := <-sigChan
	l.Println("Received terminate, graceful shutdown", sig)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s.Shutdown(ctx)
}
