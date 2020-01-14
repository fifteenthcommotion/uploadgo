package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/fcgi"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

var dir string

func check_err(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func write_page(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html")
	/* multiple file upload added in html5, so html5 */
	fmt.Fprintln(w, `<!DOCTYPE html>
<html>
<head>
	<title>Upload</title>
</head>
<body>
	<form method="POST" enctype="multipart/form-data">
	<input type="file" name="file" multiple>
	<input type="submit" value="Submit">
	</form>
</body>
</html>`)
}

func handler_upload(w http.ResponseWriter, r *http.Request) {
	const numrandb = 12 /* 96 bits to guess */
	var t time.Time
	var ts string
	var randb []byte
	var nonce string
	var stub string
	var fn string
	var in multipart.File
	var out *os.File
	var err error
	if r.Method == "GET" {
		write_page(w)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "405 Method Not Allowed", 405)
		return
	}
	/* parsing large forms might write to disk which will violate pledge */
	if r.ParseMultipartForm(1<<31) != nil {
		http.Error(w, "400 Bad Request", 400)
		return
	}
	/* it's gonna be plaintext, baby! */
	w.Header().Set("Content-Type", "text/plain")
	for name, headers := range r.MultipartForm.File {
		if name == "file" && len(headers) > 0 {
			randb = make([]byte, numrandb)
			_, err = rand.Read(randb)
			check_err(err)
			nonce = hex.EncodeToString(randb)

			t = time.Now()
			ts = t.Format(time.RFC3339)
			for i := 0; i < len(headers); i++ {
				stub = fmt.Sprintf(fmt.Sprintf("%s-%s-%04d", ts, nonce, i))
				fn = filepath.Join(dir, stub)
				out, err = os.OpenFile(fn, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0666) /* umask important here */
				if err != nil {
					if os.IsExist(err) {
						log.Print(err)
						http.Error(w, "503 Service Unavailable", 503)
						return
					} else {
						check_err(err)
					}
				}
				defer out.Close()
				in, err = headers[i].Open()
				check_err(err)
				defer in.Close()
				_, err = io.Copy(out, in)
				check_err(err)
				fmt.Fprintln(w, stub)
			}
			return
		}
	}
	http.Error(w, "400 Bad Request", 400)
}

/* make sure you don't coredump into your uploads dir */
func main() {
	var l net.Listener
	var err error
	var sock string
	var gid int
	var sockumask int
	var umask int
	flag.StringVar(&sock, "sock", "/var/www/run/uploadgo/upload-go.sock", "unix socket for fcgi")
	flag.StringVar(&dir, "dir", "./uploads", "directory to store uploads") /* dir is a global */
	flag.IntVar(&gid, "gid", -1, "gid to set on socket (-1 to not set gid)")
	flag.IntVar(&sockumask, "sockumask", 0117, "umask with which to open socket")
	flag.IntVar(&umask, "umask", 0122, "umask with which to write files")
	flag.Parse()
	http.HandleFunc("/", handler_upload)

	/* remove existing sock, pray it is unused */
	err = os.Remove(sock)
	check_err(err)

	/* set permissions on socket and listen */
	syscall.Umask(sockumask)
	l, err = net.Listen("unix", sock)
	check_err(err)
	err = os.Chown(sock, -1, gid)
	check_err(err)
	defer l.Close()

	err = unix.Unveil(dir, "rwc")
	check_err(err)

	err = unix.Pledge("stdio rpath wpath cpath unix", "")
	check_err(err)

	syscall.Umask(umask) /* umask for file writes */
	log.Fatal(fcgi.Serve(l, http.DefaultServeMux))
}
