package pkg

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/liquanhui01/wechatpay-go/core/consts"
)

var pool *x509.CertPool // 声明证书池

// HTTPSClient发送返回可以发送https请求的客户端
func HTTPSClient(ctx context.Context, CacertPath, CaPath, CaKeyPath string) (*http.Client, error) {
	clicrt, err := getTLS(CacertPath, CaPath, CaKeyPath)
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      pool,
				Certificates: []tls.Certificate{*clicrt},
			},
		},
	}

	return client, nil
}

// getTLS通过指定的路径读取并加载public、private key信息
func getTLS(cacertpath, certfile, keyfile string) (*tls.Certificate, error) {
	cacrt, err := ioutil.ReadFile(cacertpath)
	if err != nil {
		return nil, err
	}
	pool = x509.NewCertPool()
	pool.AppendCertsFromPEM(cacrt)

	clicrt, err := tls.LoadX509KeyPair(certfile, keyfile)
	if err != nil {
		return nil, err
	}
	return &clicrt, nil
}

// NewRequest创建一个新的请求
func NewRequest(ctx context.Context, method, url, auth string, body io.Reader) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to new a request, err is: %s", err.Error())
	}

	request.Header.Add("Content-Type", consts.ContentType)
	request.Header.Add("Accept", consts.Accept)
	request.Header.Add("User-Agent", consts.UserAgent)
	request.Header.Add("Authorization", auth)

	return request, nil
}
