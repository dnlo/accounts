package main

import (
	"html/template"
	"net/http"
	"os"
	"log"
	"fmt"

	"github.com/asdine/storm"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

var store = sessions.NewCookieStore([]byte("0oqkfnv983nglfdiouerwjnv9x0ds532jf3s"))

type User struct {
	ID       int    `storm:"id,increment"`
	Email    string `storm:"unique"` 
	Password string
}

func main() {
	db, err := storm.Open("users.db")
	if err != nil {
		log.Fatal(err)
		os.Exit(2)
	}
	defer db.Close()
	
	if len(os.Args) < 2 {
		fmt.Println("I need a port number as argument")
		return
	}
	 
	http.HandleFunc("/", login(db))
	http.HandleFunc("/signup", signUp(db))
	http.HandleFunc("/private", private)
	http.HandleFunc("/logout", logout)
	
	fmt.Println("Listening on port " + os.Args[1])

	log.Fatal(http.ListenAndServe(":"+os.Args[1], nil))
}

func private(w http.ResponseWriter, r *http.Request) {
	sess, _ := store.Get(r, "cookie")
	if auth, ok := sess.Values["authenticated"].(bool); !ok || !auth {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	tmpl, err := template.ParseFiles("private.html")
	if err != nil {
		log.Print("error parsing private.html", err)
		return
	}
	tmpl.Execute(w, nil)
}

func signUp(db *storm.DB) func(http.ResponseWriter, *http.Request) {
	var user User
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			r.ParseForm()
			pHash, err := bcrypt.GenerateFromPassword([]byte(r.PostForm["password"][0]), bcrypt.MinCost)
			if err != nil {
				log.Print("error hashing password", err)
				return
			}
			user = User{
				Email:    r.PostForm["email"][0],
				Password: string(pHash),
			}
			err = db.Save(&user)
			if err != nil {
				fmt.Fprint(w, err)
				return
			}
			http.Redirect(w, r, "/login", 302)
		case "GET":
			tmpl, err := template.ParseFiles("signup.html")
			if err != nil {
				log.Print("error parsing signup.html", err)
				return
			}
			tmpl.Execute(w, nil)
		default:
			return
		}
	}
}

func login(db *storm.DB) func(http.ResponseWriter, *http.Request) {
	var user User
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			r.ParseForm()
			err := db.One("Email", r.PostForm["email"][0], &user)
			if err != nil {
				fmt.Fprint(w, err)
				return
			}
			err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(r.Form["password"][0]))
			if err != nil {
				fmt.Fprint(w, "Wrong email or password")
				return
			}
			sess, _ := store.Get(r, "cookie")
			sess.Values["authenticated"] = true
			sess.Save(r, w)
			http.Redirect(w, r, "/private", 302)
		case "GET":
			tmpl, err := template.ParseFiles("login.html")
			if err != nil {
				log.Print("error parsing login.html", err)
				return
			}
			tmpl.Execute(w, nil)
		default:
			return
		}
	}
}

func logout(w http.ResponseWriter, r *http.Request) {
	sess , _ := store.Get(r, "cookie")
	sess.Values["authenticated"] = false
	sess.Save(r, w)
	http.Redirect(w, r, "/", 302)
}