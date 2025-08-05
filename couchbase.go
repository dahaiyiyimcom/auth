package auth

import (
	"fmt"
	"github.com/couchbase/gocb/v2"
	"sync"
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

var (
	storeInstance *CouchbaseStore
	once          sync.Once
)

func GetCouchbaseStore(config CouchbaseConfig) (*CouchbaseStore, error) {
	var err error
	once.Do(func() {
		cluster, e := gocb.Connect(config.ConnStr, gocb.ClusterOptions{
			Username: config.Username,
			Password: config.Password,
		})
		if e != nil {
			err = e
			return
		}
		err = cluster.WaitUntilReady(config.Timeout, nil)
		if err != nil {
			panic(fmt.Sprintf("Cluster is not ready or credentials invalid: %v", err))
		}

		bucket := cluster.Bucket(config.BucketName)
		if e = bucket.WaitUntilReady(config.Timeout, nil); e != nil {
			err = e
			return
		}

		scope := bucket.Scope(config.Scope)
		collection := scope.Collection(config.Collection)

		storeInstance = &CouchbaseStore{
			Cluster:    cluster,
			Bucket:     bucket,
			Collection: collection,
		}
	})

	return storeInstance, err
}
