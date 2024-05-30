package gormext

import (
	"fmt"
	"regexp"
)

const dsnRegex = `^(?P<scheme>[^:]*):host=(?P<host>[^;]*);port=(?P<port>[^;]*);dbname=(?P<database>[^;]*)\?sslmode=(?P<ssl>[^:]*)?$`

type Configs struct {
	DbType      Type   `env:"TYPE" mapstructure:"type"`
	Port        uint16 `env:"PORT" mapstructure:"port"`
	Host        string `env:"HOST" mapstructure:"host"`
	Username    string `env:"UESRNAME" mapstructure:"username"`
	Password    string `env:"PASSWORD" mapstructure:"password"`
	Name        string `env:"NAME" mapstructure:"name"`
	IsSSLEnable bool   `env:"IS_SSL_ENABLE" mapstructure:"is_ssl_enable"`
	DSN         string `env:"DSN,file"`
}

func (c *Configs) generateDSN() string {
	if c.DSN != "" {
		return c.DSN
	}
	switch c.DbType {
	case PostgreSQL:
		c.DSN = fmt.Sprintf("postgresql://%v:%v@%v:%v/%v?sslmode=%v", c.Username, c.Password, c.Host, "%v", c.Name, "%v")
		if c.Port != 0 {
			c.DSN = fmt.Sprintf(c.DSN, c.Port)
		}
		if c.IsSSLEnable {
			c.DSN = fmt.Sprintf(c.DSN, "Enable")
		} else {
			c.DSN = fmt.Sprintf(c.DSN, "disable")
		}
	}
	return c.DSN
}

func (c *Configs) rootDSN() string {
	dsn := ""
	if c.DSN != "" {
		r, err := regexp.Compile(dsnRegex)
		r.FindAll()
		dsn = c.DSN
	}
	//^(?P<scheme>[^:]*):host=(?P<host>[^;]*);port=(?P<port>[^;]*);dbname=(?P<database>[^;]*)(\?sslmode=[^:]*){0,1}$
	switch c.DbType {
	case PostgreSQL:
		dsn = fmt.Sprintf("postgresql://%v:%v@%v:%v?sslmode=%v", c.Username, c.Password, c.Host, "%v", "%v")
		if c.Port != 0 {
			dsn = fmt.Sprintf(dsn, c.Port)
		}
		if c.IsSSLEnable {
			dsn = fmt.Sprintf(dsn, "Enable")
		} else {
			dsn = fmt.Sprintf(dsn, "disable")
		}
	}
	return dsn
}
