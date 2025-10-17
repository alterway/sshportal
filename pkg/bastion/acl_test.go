package bastion // import "moul.io/sshportal/pkg/bastion"

import (
	"os"
	"fmt"
	"path/filepath"
	"testing"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"moul.io/sshportal/pkg/dbmodels"
)

func SetupBase(aesKey string) (*gorm.DB, string, error) {
	tmpDir, err := os.MkdirTemp("", "sshportal")

	if err != nil {
		return nil, "", fmt.Errorf("Can't setup test: %v", err)
	}
	//

	db, err := gorm.Open(sqlite.Open(filepath.Join(tmpDir, "sshportal.db")), &gorm.Config{})
	if err != nil {
		return nil, "", fmt.Errorf("Can't setup test DB: %v", err)
	}

	DBInit(db, aesKey)

	return db, tmpDir, nil
}

func TestCheckACLs(t *testing.T) {
	db, tmpDir, err := SetupBase("")
	defer os.RemoveAll(tmpDir)

	if err != nil {
		t.Errorf("%v", err)
	}
	// create dummy objects
	var hostGroup dbmodels.HostGroup
	if err := dbmodels.HostGroupsByIdentifiers(db, []string{"default"}).First(&hostGroup).Error; err != nil {
		t.Errorf("Can't create host")
	}

	if err := db.Create(&dbmodels.Host{Groups: []*dbmodels.HostGroup{&hostGroup}}).Error; err != nil {
		t.Errorf("%v", err)
	}

	var (
		hosts []dbmodels.Host
		users []dbmodels.User
	)
	db.Preload("Groups").Preload("Groups.ACLs").Find(&hosts)
	db.Preload("Groups").Preload("Groups.ACLs").Find(&users)

	// test
	action := checkACLs(users[0], hosts[0], "")
	if action != string(dbmodels.ACLActionAllow) {
		t.Errorf("ACL test fail")
	}
}
