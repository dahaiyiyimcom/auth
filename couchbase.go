package auth

import (
	"github.com/couchbase/gocb/v2"
	"time"
)

type CouchbaseConfig struct {
	ConnStr    string
	Username   string
	Password   string
	BucketName string
	Scope      string
	Collection string
	Timeout    time.Duration
}

type CouchbaseStore struct {
	Cluster    *gocb.Cluster
	Bucket     *gocb.Bucket
	Collection *gocb.Collection
}
