/*
   Copyright 2015 Cesanta Software Ltd.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       https://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package authn

import (
	"github.com/go-ldap/ldap"
	"crypto/tls"
	"fmt"
	"github.com/syndtr/goleveldb/leveldb/errors"
	"sync"
	"github.com/golang/glog"
)

type LdapAuthConfig struct {
	Host     string `yaml:"host,omitempty"`
	Port     int `yaml:"port,omitempty"`
	Suffix   string `yaml:"suffix,omitempty"`
	Tls      bool `yaml:"tls,omitempty"`
	Insecure bool `yaml:"insecure,omitempty"`
}

type ldapAuth struct {
	conn *ldap.Conn
	config *LdapAuthConfig
	lock *sync.Mutex
}

func NewLdapAuth(config *LdapAuthConfig) (*ldapAuth, error) {
	conn, err := config.connect()
	sua := &ldapAuth{conn: conn, config: config, lock: &sync.Mutex{}}
	if err != nil {
		return nil, err
	}
	return sua, nil
}

func (sua *LdapAuthConfig) connect() (*ldap.Conn, error) {
	if sua.Tls {
		tlsConfig := &tls.Config{
			ServerName: sua.Host,
		}
		if sua.Insecure {
			tlsConfig = &tls.Config{
				InsecureSkipVerify: true,
			}
		}
		l, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", sua.Host, sua.Port), tlsConfig)
		return l, err
	} else {
		l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", sua.Host, sua.Port))
		return l, err
	}
}


func (sua *ldapAuth) Authenticate(user string, password PasswordString) error {

	for retries := 0; retries < 3; retries++ {
		err := sua.conn.Bind(user + sua.config.Suffix, string([]byte(password)))
		if err != nil {
			ldapErr := err.(*ldap.Error)
			if ldapErr.ResultCode == 200 {
				conn, conErr := sua.config.connect()
				if conErr != nil {
					glog.Warningln(conErr)
				} else {
					sua.lock.Lock()
					sua.conn = conn
					sua.lock.Unlock()
				}
			} else {
				return err
			}
		} else {
			return nil
		}
	}

	return errors.New("Failed to reconnect after 3 retries")

}

func (sua *ldapAuth) Stop() {
	sua.conn.Close()
}
