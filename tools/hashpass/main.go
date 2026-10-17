// hashpass — печатает bcrypt-хеш пароля, совместимый с users.pass_hash.
//
// Штатного «сброса пароля» в сервисе нет (нет ни CLI-команды, ни эндпоинта),
// поэтому пароль меняется так:
//
//	go run ./tools/hashpass 'новый-пароль'          # получить хеш
//	# затем на сервере: UPDATE users SET pass_hash=? WHERE username=?
//
// (см. DESIGN.md / auth: таблица users в /var/lib/rival/auth.db)
package main

import (
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: hashpass <password>")
		os.Exit(2)
	}
	h, err := bcrypt.GenerateFromPassword([]byte(os.Args[1]), bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bcrypt:", err)
		os.Exit(1)
	}
	fmt.Println(string(h))
}
