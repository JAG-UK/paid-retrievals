package retrievalclient_test

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fidlabs/paid-retrievals/internal/mpp"
)

// Valid IPFS CID for MPP challenge parsing (see internal/mpp).
const testPieceCID = "bafkreidcbkgxoddug6vawnjrzb4aaublfn46sd2rvxnykbxkkarke7y76e"

func freePieceServer(cid string, body []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/piece/"+cid {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodHead, http.MethodGet:
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusOK)
			if r.Method == http.MethodGet {
				_, _ = w.Write(body)
			}
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

func paidPieceServer(cid, dealUUID, price, payee string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/piece/"+cid {
			http.NotFound(w, r)
			return
		}
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Payment ") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("paid-car"))
			return
		}
		ch := mpp.Challenge{
			ID:     dealUUID,
			Realm:  mpp.RealmPrefix + r.Host,
			Method: mpp.MethodID,
			Intent: mpp.IntentID,
			Request: mpp.PaymentRequest{
				DealUUID: dealUUID, CID: cid, PriceUSDFC: price, Payee0x: payee,
				Method: http.MethodGet, Path: "/piece/" + cid, Host: r.Host,
			},
			Expires: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		}
		v, err := ch.WWWAuthenticateValue()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("WWW-Authenticate", v)
		w.WriteHeader(http.StatusPaymentRequired)
	})
}
