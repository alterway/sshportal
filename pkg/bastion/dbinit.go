package bastion // import "github.com/alterway/sshportal/pkg/bastion"

import (
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"os/user"
	"strings"

	"github.com/alterway/sshportal/pkg/crypto"
	"github.com/alterway/sshportal/pkg/dbmodels"

	gormigrate "github.com/go-gormigrate/gormigrate/v2"
	ssh "golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

const (
	UserAdmin      = "admin"
	UserDefault    = "default"
	CommentDefault = "created by sshportal"
)

// Old migrations have been removed in v1.31.0
// Upgrading from a very old release is not supported
func checkUpgradePath(db *gorm.DB) error {
	var total int64
	if err := db.Table("migrations").Count(&total).Error; err != nil || total == 0 {
		return nil
	}

	var found int64
	if err := db.Table("migrations").Where("id = 32").Count(&found).Error; err != nil {
		return nil
	}

	if found == 0 {
		return fmt.Errorf("this upgrade path is not possible. Please upgrade first to 1.29.0")
	}
	return nil
}

func DBInit(db *gorm.DB, aesKey string) error {
	log.SetOutput(io.Discard)
	log.SetOutput(os.Stderr)

	m := gormigrate.New(db, gormigrate.DefaultOptions, []*gormigrate.Migration{
		{
			ID: "33",
			Migrate: func(tx *gorm.DB) error {

				if err := checkUpgradePath(tx); err != nil {
					log.Printf("error: %v", err)
					os.Exit(1)
				}

				var count int64
				if err := db.Table("ssh_keys").Where("name = ?", UserDefault).Count(&count).Error; err != nil {
					return err
				}

				// Starting with v1.29, When --aes-key is provided, SSHportal will re-encrypt all secret fields in DB
				// that have either been encrypted with deprecated cipher (CFB) or was left in plaintext
				if aesKey != "" && count != 0 {
					if err := MigrateToGCMCipher(tx, aesKey); err != nil {
						return err
					}
				}

				if err := migrateToGormV2(tx); err != nil {
					return err
				}

				// Use AutoMigrate to recreate them with CASCADE enabled
				return tx.AutoMigrate(
					&dbmodels.SSHKey{},
					&dbmodels.Host{},
					&dbmodels.UserKey{},
					&dbmodels.User{},
					&dbmodels.UserGroup{},
					&dbmodels.HostGroup{},
					&dbmodels.ACL{},
					&dbmodels.Session{},
					&dbmodels.Event{},
				)
			},
			Rollback: func(tx *gorm.DB) error { return fmt.Errorf("not implemented") },
		},
	})

	// Only runs if the `migrations` table is empty (fresh install):
	// creates the final schema directly and marks "33" as already applied.
	m.InitSchema(func(tx *gorm.DB) error {
		return tx.AutoMigrate(
			&dbmodels.Setting{},
			&dbmodels.SSHKey{},
			&dbmodels.Host{},
			&dbmodels.UserKey{},
			&dbmodels.UserRole{},
			&dbmodels.User{},
			&dbmodels.UserGroup{},
			&dbmodels.HostGroup{},
			&dbmodels.ACL{},
			&dbmodels.Session{},
			&dbmodels.Event{},
		)
	})

	if err := m.Migrate(); err != nil {
		return err
	}

	dbmodels.NewEvent("system", "migrated").Log(db)

	if err := ensureRoles(db, UserAdmin, "listhosts"); err != nil {
		return err
	}

	if err := ensureSSHKey(db, UserDefault, aesKey); err != nil {
		return err
	}

	defaultHostGroup, err := ensureDefaultHostGroup(db)
	if err != nil {
		return err
	}

	defaultUserGroup, err := ensureDefaultUserGroup(db)
	if err != nil {
		return err
	}

	if err := ensureDefaultACL(db, defaultUserGroup, defaultHostGroup); err != nil {
		return err
	}

	if err := ensureAdminUser(db, defaultUserGroup); err != nil {
		return err
	}

	if err := ensureSSHKey(db, "host", aesKey); err != nil {
		return err
	}

	// close unclosed connections
	return db.Table("sessions").Where("status = ?", "active").Updates(&dbmodels.Session{
		Status: string(dbmodels.SessionStatusClosed),
		ErrMsg: "sshportal was halted while the connection was still active",
	}).Error
}

func ensureRoles(db *gorm.DB, names ...string) error {
	for _, name := range names {
		role := dbmodels.UserRole{Name: name}
		if err := db.Where(&role).FirstOrCreate(&role).Error; err != nil {
			return err
		}
	}
	return nil
}

func ensureSSHKey(db *gorm.DB, name, aesKey string) error {
	var count int64
	if err := db.Table("ssh_keys").Where("name = ?", name).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	key, err := crypto.NewSSHKey("ed25519", 1)
	if err != nil {
		return err
	}
	key.Name = name
	key.Comment = CommentDefault

	if aesKey != "" {
		if err := crypto.EncryptField(aesKey, &key.PrivKey); err != nil {
			return fmt.Errorf("failed to encrypt PrivKey %d: %v", key.ID, err)
		}
	}
	return db.Create(&key).Error
}

func ensureDefaultHostGroup(db *gorm.DB) (dbmodels.HostGroup, error) {
	group := dbmodels.HostGroup{Name: UserDefault}
	err := db.Where(&group).Attrs(dbmodels.HostGroup{Comment: CommentDefault}).FirstOrCreate(&group).Error
	return group, err
}

func ensureDefaultUserGroup(db *gorm.DB) (dbmodels.UserGroup, error) {
	group := dbmodels.UserGroup{Name: UserDefault}
	err := db.Where(&group).Attrs(dbmodels.UserGroup{Comment: CommentDefault}).FirstOrCreate(&group).Error
	return group, err
}

func ensureDefaultACL(db *gorm.DB, userGroup dbmodels.UserGroup, hostGroup dbmodels.HostGroup) error {
	var count int64
	if err := db.Table("acls").Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	acl := dbmodels.ACL{
		UserGroups: []*dbmodels.UserGroup{&userGroup},
		HostGroups: []*dbmodels.HostGroup{&hostGroup},
		Action:     "allow",
		Comment:    CommentDefault,
	}
	return db.Create(&acl).Error
}

// ensureAdminUser creates the first admin account if the users table is empty.
func ensureAdminUser(db *gorm.DB, defaultUserGroup dbmodels.UserGroup) error {
	var count int64
	if err := db.Table("users").Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	inviteToken, err := randStringBytes(16)
	if err != nil {
		return err
	}
	if t := os.Getenv("SSHPORTAL_DEFAULT_ADMIN_INVITE_TOKEN"); t != "" {
		inviteToken = t
	}

	var adminRole dbmodels.UserRole
	if err := db.Where("name = ?", UserAdmin).First(&adminRole).Error; err != nil {
		return err
	}

	username := os.Getenv("USER")
	if currentUser, err := user.Current(); err == nil {
		username = currentUser.Username
	}
	username = strings.ToLower(username)
	if username == "" {
		username = "root" // fallback username
	}

	admin := dbmodels.User{
		Name:        username,
		Email:       fmt.Sprintf("%s@localhost", username),
		Comment:     CommentDefault,
		Roles:       []*dbmodels.UserRole{&adminRole},
		InviteToken: inviteToken,
		Groups:      []*dbmodels.UserGroup{&defaultUserGroup},
	}
	if err := db.Create(&admin).Error; err != nil {
		return err
	}
	log.Printf("info: '%s' user created. Run 'ssh localhost -p 2222 -l invite:%s' to associate your public key with this account", admin.Name, admin.InviteToken)
	return nil
}

func randStringBytes(n int) (string, error) {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	b := make([]byte, n)
	for i := range b {
		r, err := rand.Int(rand.Reader, big.NewInt(int64(len(letterBytes))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random string: %s", err)
		}
		b[i] = letterBytes[r.Int64()]
	}
	return string(b), nil
}

func MigrateToGCMCipher(db *gorm.DB, aesKey string) error {
	var sshKeys []*dbmodels.SSHKey
	var hosts []*dbmodels.Host

	if aesKey == "" {
		return nil
	}

	if err := db.Where("password <> ''").Find(&hosts).Error; err != nil {
		return err
	}

	if err := db.Find(&sshKeys).Error; err != nil {
		return err
	}

	for _, k := range sshKeys {
		keyDecryptedWithGcm := k.PrivKey
		keyDecryptedWithCfb := ""

		if err := crypto.DecryptField(aesKey, &keyDecryptedWithGcm); err != nil {
			keyDecryptedWithCfb, err = crypto.DecryptCFBField(aesKey, k.PrivKey)

			// Impossible to decrypt with GCM or CFB but we ignore the error
			// because we don't want SSHportal to crash now
			// It will be catched by PrivateKeyFromDB() later
			if err != nil {
				log.Printf("warn(MigrateToGCMCipher): %s key can't be decrypted", k.Name)
				return nil
			}

			// Wrong AES key has been provided but we ignore the error here because
			// we don't want SSHportal to crash now.
			// It will be catched by PrivateKeyFromDB() later
			if _, err := ssh.ParsePrivateKey([]byte(keyDecryptedWithCfb)); err != nil {
				log.Printf("warn(MigrateToGCMCipher): %s key can't be decrypted with provided --aes-key ", k.Name)
				log.Printf("warn(MigrateToGCMCipher): re-encryption aborted")
				return nil
			}
		}

		// No error when decrypting with GCM and content field changed means the field
		// was already encrypted with GCM
		if keyDecryptedWithGcm != k.PrivKey {
			return nil
		}

		// Field was encrypted with CFB or is unencrypted
		// DecryptCFBField() return the field unchanged if found unencrypted
		if keyDecryptedWithCfb != "" {
			k.PrivKey = keyDecryptedWithCfb
		}

		if err := crypto.EncryptField(aesKey, &k.PrivKey); err != nil {
			return fmt.Errorf("failed to encrypt PrivKey %s: %v", k.Name, err)
		}
	}

	// If we are here this means there is no GCM encrypted fields (we abort above if we
	// find a AES-GCM encrypted field)
	//
	// We can't really test if we are decrypting the CFB-encrypted Password field with
	// the right AES key so if you only have CFB-encrypted Passwords in your SSHportal
	// DB and you run v1.29.0 AND provide a bad --aes-key then your passwords will be lost!
	// If you have at least one encrypted SSH key the problem will be detected above
	for _, h := range hosts {

		pwdDecryptedWithCfb, err := crypto.DecryptCFBField(aesKey, h.Password)
		if err != nil {
			log.Printf("warn(MigrateToGCMCipher): failed to decrypt Password of Host %s | %v", h.Name, err)
			return nil
		}

		if pwdDecryptedWithCfb != h.Password {
			h.Password = pwdDecryptedWithCfb
		}

		if err := crypto.EncryptField(aesKey, &h.Password); err != nil {
			return fmt.Errorf("failed to reencrypt Password of Host %s: %v", h.Name, err)
		}
	}

	// We only update the DB now to prevent encryption of plaintext field with a bad
	// AES key (which could be detected too late if done in the first loop)
	err := db.Transaction(func(tx *gorm.DB) error {
		for _, h := range hosts {
			err := tx.Model(hosts).Where("id = ?", h.ID).Update("password", h.Password).Error
			if err != nil {
				return fmt.Errorf("failed to update password of Host '%s' in DB | %v", h.Name, err)
			}
		}
		for _, k := range sshKeys {
			err := tx.Model(sshKeys).Where("id = ?", k.ID).Update("priv_key", k.PrivKey).Error
			if err != nil {
				return fmt.Errorf("failed to update SSHKey '%s' in DB | %v", k.Name, err)
			}
		}
		return nil
	})

	if err != nil {
		log.Printf("error(MigrateToGCMCipher): %v", err)
	} else {
		log.Printf("info: CFB encrypted fields have been re-encrypted with AES-GCM")
	}

	return nil
}

func migrateToGormV2(db *gorm.DB) error {
	migrator := db.Migrator()

	type HostHostGroup struct {
		HostID      uint `gorm:"primaryKey"`
		HostGroupID uint `gorm:"primaryKey"`
	}
	type UserUserRole struct {
		UserID     uint `gorm:"primaryKey"`
		UserRoleID uint `gorm:"primaryKey"`
	}
	type UserUserGroup struct {
		UserID      uint `gorm:"primaryKey"`
		UserGroupID uint `gorm:"primaryKey"`
	}
	type UserGroupACL struct {
		UserGroupID uint `gorm:"primaryKey"`
		ACLID       uint `gorm:"primaryKey"`
	}
	type HostGroupACL struct {
		HostGroupID uint `gorm:"primaryKey"`
		ACLID       uint `gorm:"primaryKey"`
	}

	joinTables := []struct {
		model     interface{}
		fieldName string
		joinModel interface{}
	}{
		{&dbmodels.Host{}, "Groups", &HostHostGroup{}},
		{&dbmodels.UserRole{}, "Users", &UserUserRole{}},
		{&dbmodels.UserGroup{}, "Users", &UserUserGroup{}},
		{&dbmodels.UserGroup{}, "ACLs", &UserGroupACL{}},
		{&dbmodels.HostGroup{}, "ACLs", &HostGroupACL{}},
	}

	for _, jt := range joinTables {
		if err := db.SetupJoinTable(jt.model, jt.fieldName, jt.joinModel); err != nil {
			return fmt.Errorf("prepareMySQLForV2: setup join table for %T.%s: %w", jt.model, jt.fieldName, err)
		}
	}

	alterations := []struct {
		model  interface{}
		fields []string
	}{
		{&dbmodels.Setting{}, []string{"ID"}},
		{&dbmodels.SSHKey{}, []string{"ID"}},
		{&dbmodels.Host{}, []string{"ID", "SSHKeyID", "HopID"}},
		{&dbmodels.UserKey{}, []string{"ID", "UserID"}},
		{&dbmodels.UserRole{}, []string{"ID"}},
		{&dbmodels.User{}, []string{"ID"}},
		{&dbmodels.UserGroup{}, []string{"ID"}},
		{&dbmodels.HostGroup{}, []string{"ID"}},
		{&dbmodels.ACL{}, []string{"ID"}},
		{&dbmodels.Session{}, []string{"ID", "UserID", "HostID"}},
		{&dbmodels.Event{}, []string{"ID", "AuthorID"}},
		{&HostHostGroup{}, []string{"HostID", "HostGroupID"}},
		{&UserUserRole{}, []string{"UserID", "UserRoleID"}},
		{&UserUserGroup{}, []string{"UserID", "UserGroupID"}},
		{&UserGroupACL{}, []string{"UserGroupID", "ACLID"}},
		{&HostGroupACL{}, []string{"HostGroupID", "ACLID"}},
	}

	for _, a := range alterations {
		for _, field := range a.fields {
			if err := migrator.AlterColumn(a.model, field); err != nil {
				return fmt.Errorf("alter %T.%s failed: %w", a.model, field, err)
			}
		}
	}

	// Clean up orphaned records before creating foreign keys
	cleanupStatements := []string{
		"UPDATE hosts SET hop_id = NULL WHERE hop_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM hosts h2 WHERE h2.id = hosts.hop_id)",
		"UPDATE hosts SET ssh_key_id = NULL WHERE ssh_key_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM ssh_keys WHERE ssh_keys.id = hosts.ssh_key_id)",
		"UPDATE sessions SET user_id = NULL WHERE user_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM users WHERE users.id = sessions.user_id)",
		"UPDATE sessions SET host_id = NULL WHERE host_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM hosts WHERE hosts.id = sessions.host_id)",
		"UPDATE events SET author_id = NULL WHERE author_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM users WHERE users.id = events.author_id)",

		"DELETE FROM user_keys WHERE NOT EXISTS (SELECT 1 FROM users WHERE users.id = user_keys.user_id)",

		"DELETE FROM host_host_groups WHERE NOT EXISTS (SELECT 1 FROM hosts WHERE hosts.id = host_host_groups.host_id)",
		"DELETE FROM host_host_groups WHERE NOT EXISTS (SELECT 1 FROM host_groups WHERE host_groups.id = host_host_groups.host_group_id)",

		"DELETE FROM user_user_roles WHERE NOT EXISTS (SELECT 1 FROM users WHERE users.id = user_user_roles.user_id)",
		"DELETE FROM user_user_roles WHERE NOT EXISTS (SELECT 1 FROM user_roles WHERE user_roles.id = user_user_roles.user_role_id)",

		"DELETE FROM user_user_groups WHERE NOT EXISTS (SELECT 1 FROM users WHERE users.id = user_user_groups.user_id)",
		"DELETE FROM user_user_groups WHERE NOT EXISTS (SELECT 1 FROM user_groups WHERE user_groups.id = user_user_groups.user_group_id)",

		"DELETE FROM user_group_acls WHERE NOT EXISTS (SELECT 1 FROM user_groups WHERE user_groups.id = user_group_acls.user_group_id)",
		"DELETE FROM user_group_acls WHERE NOT EXISTS (SELECT 1 FROM acls WHERE acls.id = user_group_acls.acl_id)",

		"DELETE FROM host_group_acls WHERE NOT EXISTS (SELECT 1 FROM host_groups WHERE host_groups.id = host_group_acls.host_group_id)",
		"DELETE FROM host_group_acls WHERE NOT EXISTS (SELECT 1 FROM acls WHERE acls.id = host_group_acls.acl_id)",
	}

	for _, stmt := range cleanupStatements {
		if err := db.Exec(stmt).Error; err != nil {
			log.Printf("warn: failed to clean orphaned records for mysql: %v", err)
		}
	}

	return nil
}
